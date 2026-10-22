# php2shell-exp

Profile-driven php2shell chain (CVE-2026-109619 class) for stock
`php:*-apache` images, with an MSF-style interface. Everything that differs
between PHP builds comes from `profiles/<target>.json`; libphp addresses are
resolved from the ELF symbol table by name (`symbols.py`). No zif/dtor offset,
carrier offset, spray count or pad list is compiled into the chain.

## Quick start

```sh
python3 chain.py --target 8.4.26            # full chain -> PROOF
python3 chain.py calibrate --target 8.4.26  # oracle-measure the profile
python3 chain.py doctor --target 8.4.26     # image / symbols / profile facts
```

Lab: `docker/compose.yml` starts one single-worker prefork Apache per version,
bound to `127.0.0.1` only, with `no-new-privileges`, `pids_limit` and
`mem_limit`. The default services do not need `CAP_SYS_PTRACE`; the calibration
override (`docker/compose.calibrate.yml`) adds it so `calibrate` can read its
own worker's Zend chunk.

## MSF-style entrypoint (p2s.py)

```text
msf6 > use exploit/php2shell/109619
msf6 exploit(php2shell/109619) > show options
msf6 exploit(php2shell/109619) > show targets
msf6 exploit(php2shell/109619) > set RHOSTS 127.0.0.1
msf6 exploit(php2shell/109619) > set RPORT 19126
msf6 exploit(php2shell/109619) > set TARGET 8.4.26
msf6 exploit(php2shell/109619) > set CMD id
msf6 exploit(php2shell/109619) > check
msf6 exploit(php2shell/109619) > exploit
```

Modules:

| module | purpose |
|---|---|
| `exploit/php2shell/109619` | full chain, executes the proof command |
| `auxiliary/php2shell/109618` | leak/check only, never executes a command |

Options: `RHOSTS`, `RPORT`, `TARGET`, `CMD`, `PAYLOAD`, `PROFILE`, `URL`,
`TIMEOUT`, `RETRIES`, `VERBOSE`, `PROOF_FILE`. `TARGET` only selects a
profile; offsets and heap geometry come from that profile.

`check` runs the profile's leak probe without executing anything:

| target | check result | exit |
|---|---|---|
| 8.4.26 | vulnerable (stage-1 heap leak) | 0 |
| 8.4.27 | not vulnerable (stage-1 leak fails) | 1 |
| 8.5.11 | unknown (combined-leak profile not checkable) | 3 |
| 8.5.12 | not vulnerable (stage-1 leak fails) | 1 |
| 8.2.34 | check negative (stage-1 blocked; build is *affected*) | 1 |
| 8.3.35 | vulnerable (stage-1 heap leak) | 0 |
| 8.2.35 | not vulnerable (stage-1 leak fails; fixed control) | 1 |
| 8.3.36 | not vulnerable (stage-1 leak fails; fixed control) | 1 |

Measured on this lab (p2s.py, 2026-10-22):

```text
[+] http://127.0.0.1:19126/index.php (8.4.26): vulnerable - stage1 heap leak chunk=0x7fe963200000
[-] http://127.0.0.1:19127/index.php (8.4.27): not vulnerable - stage1 leak failed
[?] http://127.0.0.1:19111/index.php (8.5.11): unknown - combined leak profile is not checkable without executing the chain
[+] http://127.0.0.1:19129/index.php (8.3.35): vulnerable - stage1 heap leak chunk=0x7fc7b5600000
[-] http://127.0.0.1:19128/index.php (8.2.34): not vulnerable - stage1 leak failed
[-] http://127.0.0.1:19130/index.php (8.2.35): not vulnerable - stage1 leak failed
[-] http://127.0.0.1:19131/index.php (8.3.36): not vulnerable - stage1 leak failed
```

`exploit` for 8.4.26 and 8.3.35 printed `PROOF: uid=33(www-data)
gid=33(www-data) groups=33(www-data)`.

Exit codes: 0 success / vulnerable, 1 failure / not vulnerable,
2 option error, 3 check undecidable.

Non-interactive:

```sh
python3 p2s.py -x exploit/php2shell/109619 \
  -o RHOSTS=127.0.0.1 -o RPORT=19126 -o TARGET=8.4.26 -o CMD=id
python3 p2s.py --rhost 127.0.0.1 --rport 19126 --target 8.4.26 --cmd id
python3 p2s.py --resource p2s.rc
```

`CMD` is limited to 14 bytes by the 167-byte carrier. Longer commands need a
script on a writable mount, e.g. `sh</out/c`.

## Calibration

```sh
# calibration needs the SYS_PTRACE override
docker compose -f docker/compose.yml -f docker/compose.calibrate.yml up -d apache8426
python3 chain.py calibrate --target 8.4.26
```

`chain.py calibrate` measures a profile with three oracles and writes the
result back to `profiles/<target>.json`:

1. `stage1.fillers` — rotate, send the leak arm and forged-field request;
   success oracle is a 2 MiB-aligned heap pointer in `Set-Cookie`.
2. `stage2.target` — same, but the oracle is `cookie[8:16]` matching the
   symbol-resolved `zval_ptr_dtor`.
3. `htdata_offset` — replay the full rotate -> stage1 -> stage2 -> arm -> B
   sequence against a calibration-only `/_hold.php` endpoint (same path
   length as `index.php`, sleeps after startup), then scan the live Zend
   chunk through `/proc/<pid>/mem` for the marked 167-byte string. The
   zend_string header is at `data-0x18`; accepted header is
   `rc==1 && (type_info & 0x0f)==6 && len==0xA7`.
4. `stage3.pads` — the real stage-3 request must write the proof file; seed
   verified first, then pad count is swept with the same oracle.

Measured 8.4.26 (`libphp sha256 51663cf8...`):

```text
stage1 fillers = 841            (verified twice)
stage2 target  = 406 / 16       (verified twice)
htdata         = chunk+0x690d8  header 0x690c0, rc=1, type_info=0x16,
                                 len=0xa7, 20 copies at +0xC0
pads           = 6x(31,31)      verified by PROOF
symbols        = zif_system +0x465370, zval_ptr_dtor +0x65eb60
```

The `_hold.php` endpoint is installed from `docker/probe/hold.php` only for
the duration of a calibration and removed afterwards.

## 8.3.35 calibration (PROOF)

`chain.py calibrate --target 8.3.35` measured, on `php:8.3.35-apache`
(Apache 2.4.69, libphp sha256 `ea069762...`, `zif_system +0x3ac080`,
`zval_ptr_dtor +0x49ec50`):

```text
stage1 fillers = 841   (confirm=0x7fc7b5600000)
stage2 target  = 406/16 (confirm=0x7fc7b7375000)
htdata         = +0x6a0d8  header=0x6a0c0 type_info=0x16 len=0xa7
                 20 copies @0xc0
pads           = 6x[31,31] -> PROOF uid=33(www-data)
symbols        = zif_system +0x3ac080, zval_ptr_dtor +0x49ec50
```

`chain.py run --target 8.3.35` and
`p2s.py -x exploit/php2shell/109619 ... -o TARGET=8.3.35 -o CMD=id` both
printed `PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

Note: PHP 8.2's session startup rejects the historical 19-byte id
(`Too short session ID`) before a dangling `PS(id)` exists; 8.3.35 still
leaks with the same 19-byte id despite the warning. `chain.py` therefore
allows a profile to override the B-request id via `heap.stage1.sid_len`,
`heap.stage2.sid_len` and `stage3.b_sid_len`; 8.4.26 omits them and keeps
its verified 19-byte id.

## 8.2.34 bounded attempt (still NO PROOF, affected version)

`php:8.2.34-apache`, libphp sha256 `42ae9f69...`, `zif_system +0x39b8a0`,
`zval_ptr_dtor +0x487650`. Two calibration attempts and two carrier rounds
were spent, then stopped:

- Endpoint `/index.php` (same 10-byte path as 8.4.26); `session.save_path=/tmp`
  writable; exactly one `www-data` prefork worker.
- With the historical 19-byte id, the stage-1 B request fails at session
  startup: `PHP Request Startup: Failed to create session data file path.
  Too short session ID, invalid save_path or path length exceeds 4096
  characters`; no `Set-Cookie`.
- With a full-length 32-byte id the request returns `OK` but no leak cookie:
  the forge never lands on `PS(id)`.
- Calibration attempts (19-byte and 32-byte id) both end in
  `CALIBRATE_FAILED stage1`; a `patch_low7` run and a `live_reference` run
  (one round each) both end in `HEAP_LEAK_FAILED` at stage 1.

This version is in the affected range, but this chain does **not** exploit
it. The p2s `check` result `not vulnerable` for 8.2.34 means only "our leak
oracle is negative"; it is not evidence that the build is patched.

## 8.5.11 bounded attempt (still NO PROOF)

The 8.5.11 port was exercised against dinosn's pinned image
`php@sha256:974e3a920309...` (Apache 2.4.68, libphp sha256 `fd8062d8...`,
`zif_system +0x5996e0`, `zval_ptr_dtor +0x7b47a0`) with the lab runtime
replicated: `mem_limit 256m`, `pids_limit 128`, tmpfs `/tmp` 64m, hostname
`php-rfc1867-rce-lab`, and a `t.php?mode=warm` 12 MiB prewarm.

Observed failure point (two bounded rounds, then stop):

- leak-A is byte-identical to dinosn's (25,281,929-byte request) and behaves
  identically: max_input_vars warning, "session cookie cannot be sent after
  headers have already been sent", OOM `tried to allocate 6296371 bytes`.
- After leak-A the stale session id is visible at `chunk+0xb75a0` (ASCII
  `17981b3ea7563d0ed4df6f7a`); dinosn's report places it at
  `chunk+0xb75c0`, a 0x20 difference.
- leak-B (68,456 bytes, exactly 1000 vars) returns no `Set-Cookie`; body is
  `Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to
  allocate 12884901923 bytes)` — `ZSTR_LEN` read as -5, i.e. the
  `a0447[0..256]` array did not land at `PS(id)-0x10`.
- A bounded target sweep 440..455 (m=257) found only target 446 producing a
  normal 32-hex session cookie (233-byte response); every other target
  returned the 346-byte OOM page. No 512-byte disclosure. The sweep was
  stopped there.
- dinosn's own `e2e/nb_pure.py` also reports `LEAK_FAILED` against
  this container (with and without `--rotate`, and after the warm request),
  so the failure is environmental, not a difference in our request bytes:
  the arm and `barr` bodies are byte-identical to `nb_leak.py`.

Consequence: no 8.5.11 profile has been calibrated and the 31-byte live
carrier stage-3 has not been reached. `www/t.php?mode=warm` and
`www/_warm.php` are lab-only calibration helpers.

## What this proves / does not prove

Proves, on the pinned official images in this lab:

- The 8.4.26 session/upload-progress chain works with all libphp addresses
  resolved by symbol name and all heap geometry read from a calibrate-produced
  profile.
- 8.4.27 and 8.5.12 do not produce a proof with these profiles (the stage-1
  leak no longer lands); this is a negative control, not a patch analysis.
- The calibrator can measure filler count, target index, HT data offset and
  pads from live memory and proof oracles on 8.4.26 and 8.3.35.
- 8.3.35 (affected) reaches a full RCE proof with the same chain; its
  measured HTDATA is +0x6a0d8 (not the 8.4.26 +0x690d8).

Does not prove:

- That 8.4.27/8.5.12 are free of the underlying bug — only that this chain
  and profile do not reach a proof.
- That 8.5.11 works end to end: the combined leak (`742/447/257`) is still
  LEAK_FAILED under the replicated dinosn runtime; no 8.5.11 profile has
  been calibrated and the 31-byte live-carrier stage-3 was not reached.
- That 8.2.34 is patched, or that this chain can exploit it: the stage-1
  oracle is negative at both 19-byte and 32-byte session ids.
- Any remote/Internet target, any non-prefork SAPI, or any build whose
  libphp symbols differ without recalibration.

## Layout

```text
chain.py        stage1/2/3 orchestration, combined leak, docker glue, CLI
symbols.py      ELF64 symbol lookup by name (zif_system, zval_ptr_dtor)
profile.py      profile schema / load / save / validate
calibrate.py    oracle-driven measurement + profile provenance
p2s.py          MSF-style shell and non-interactive driver
docker/         compose (official images, one worker), ini, probe endpoint
profiles/       per-version measured/seed profiles
```

## Safety

Lab only. Every compose service binds `127.0.0.1`; containers use
`no-new-privileges`, `pids_limit` and `mem_limit`. `CAP_SYS_PTRACE` is only
needed by `calibrate`; keep it in the calibration override, never in the
default exploit path.

Do not point this at hosts you do not own or have written permission to test.
The proof command is intentionally limited (14-byte carrier, benign
`id`-class marker).

## Credits

- `9bie/php2shell-bypass-aslr-exp` — PHP 8.4.26 chain.
- `dinosn/php-cve-2026-10961x-lab-poc` — 8.5.11 mechanics (31-byte carrier).
- `RemiPelloux/php-session-upload-progress-uaf` — minimal crash reproduction.
- MADBugs PHP writeup — dynamic ELF/symbol resolution methodology.

No third-party source code is vendored; techniques are reimplemented and
credited.

## License

**No license is granted. All rights reserved.** The code is published for
defensive research and reproducibility. Do not redistribute or reuse without
written permission. Provided as-is, without warranty.
