#!/usr/bin/env python3
"""Resolve libphp symbols by name -- never hardcode zif/dtor offsets.

The official php:*-apache images are built by the Docker PHP maintainers, so
every point release can move both the symbol values and the ELF load bias.
This module copies libphp.so out of the target container and walks its ELF
symbol tables (SHT_SYMTAB + SHT_DYNSYM), returning chunk-relative offsets:

    offset(name) = st_value(name) - min(PT_LOAD p_vaddr)

Usage (library):
    from symbols import resolve
    info = resolve("php2shell-exp-8426", ["zif_system", "zval_ptr_dtor"])
    info["symbols"]["zif_system"]      # -> 0x465370

Usage (CLI):
    python3 symbols.py php2shell-exp-8426 [--libphp PATH] [--json OUT]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1
SHN_UNDEF = 0


def docker_cp(container: str, libpath: str, dest: str) -> None:
    """Copy libphp.so out of a running container (no binutils inside needed)."""
    try:
        proc = subprocess.run(
            ["docker", "cp", f"{container}:{libpath}", dest],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    except FileNotFoundError:
        raise SystemExit("docker not found in PATH")
    if proc.returncode != 0:
        raise SystemExit(
            f"cannot copy {libpath} from {container!r}: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )


def parse_elf(path: str, wanted: set[str]) -> tuple[int, dict[str, int], dict[str, int]]:
    """Return (load_bias, {name: st_value}, {name: st_shndx}) for wanted names."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit(f"{path} is not a little-endian ELF64 file")

    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise SystemExit("libphp.so has no PT_LOAD segment")
    bias = min(loads)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({
            "name_off": sh_name, "type": sh_type, "offset": sh_offset,
            "size": sh_size, "link": sh_link, "entsize": sh_entsize,
        })

    found: dict[str, int] = {}
    shndx: dict[str, int] = {}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sec["link"] >= len(sections):
            continue
        strtab = sections[sec["link"]]
        entsize = sec["entsize"] or 24
        for i in range(sec["size"] // entsize):
            off = sec["offset"] + i * entsize
            st_name, st_info, st_other, st_shndx, st_value = struct.unpack_from(
                "<IBBHQ", data, off
            )
            if st_name == 0 or st_shndx == SHN_UNDEF:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and name not in found:
                found[name] = st_value
                shndx[name] = st_shndx

    return bias, found, shndx


def resolve(container: str, names: list[str], libpath: str = "/usr/lib/apache2/modules/libphp.so",
            keep: str | None = None) -> dict:
    """Copy libphp.so from `container` and resolve `names` to load-bias offsets."""
    tmp = keep or os.path.join(tempfile.mkdtemp(prefix="php2shell-sym-"), "libphp.so")
    os.makedirs(os.path.dirname(tmp) or ".", exist_ok=True)
    docker_cp(container, libpath, tmp)
    try:
        bias, syms, _ = parse_elf(tmp, set(names))
        sha = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
        size = os.path.getsize(tmp)
    finally:
        if keep is None:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    missing = [n for n in names if n not in syms]
    if missing:
        raise SystemExit(f"symbols not found in {libpath}: {', '.join(missing)}")

    return {
        "libphp": libpath,
        "sha256": sha,
        "size": size,
        "load_bias": bias,
        "symbols": {name: syms[name] - bias for name in names},
        "symbol_values": syms,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("container")
    ap.add_argument("--libphp", default="/usr/lib/apache2/modules/libphp.so")
    ap.add_argument("--symbols", default="zif_system,zval_ptr_dtor")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    names = [s.strip() for s in args.symbols.split(",") if s.strip()]
    info = resolve(args.container, names, args.libphp)
    for name, off in info["symbols"].items():
        print(f"{name:24s} libphp+0x{off:x}")
    print(f"libphp sha256 {info['sha256']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
