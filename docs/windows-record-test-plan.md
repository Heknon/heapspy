# Windows recorder: test plan

`heapspy record` on Windows (M7b, `crates/heapspy-record/src/windows*`) is
compiled and clippy-checked for `x86_64-pc-windows-gnu`, and its logic is
unit-tested on Linux:
- ETW and QPC clock conversion (`windows::clock`)
- nearest-stack matching (`windows::matcher`)
- the debugger's breakpoint state machine (`windows::debug`)
- the guardian's protocol, cleanup plan, "still our patch" check and ETW
  session names (`windows::guardian`)

The Win32 glue runs on `windows-latest` in `.github/workflows/record.yml`
(PR label `ci:record`), through `crates/heapspy/tests/record_live_windows.rs`.
The steps below marked **automated** are covered there; do the others by
hand on a real machine, and record the results at the end of this file.

## What the workflow automates

| step | test in `record_live_windows.rs` | checks |
|---|---|---|
| 2 (ETW) | `python31{2,3,4}_etw` | `mechanisms` is `["etw"]`, samples > 0, events `["arena"]`, `heapspy.skipped_events` names `large_object`, every sample and frame approximate, at least half the samples matched a stack, a top-5 stack is `build_payload` (line 5 or 6) under `handler:8`, more samples under `handler` than under `noise`, objects linked, no recorder session (`heapspy-<pid>` or `NT Kernel Logger`) left |
| 3 (debugger) | `python31{2,3,4}_debugger` | `mechanisms` is `["debugger"]`, `total_pause_ns > 0`, no approximate frame, top stack `build_payload:5 <- handler:8`, a native return address on every sample, `leaked` linked to `build_payload:5`; afterwards the target runs, no debugger is attached, and `KERNELBASE!VirtualAlloc` has the same bytes as in the test process |
| 4 (auto) | `python313_auto` | `mechanisms` is `["etw"]` (auto is ETW alone on Windows), then the ETW checks above |
| 5.1 (kill) | `kill_mid_run_etw`, `kill_mid_run_debugger` | `TerminateProcess` on the recorder after 2.5 s; the target runs, no debugger attached, `VirtualAlloc` unchanged, no recorder session left, no profile written. The guardian's log is printed (`GUARDIAN`) |
| 5.1 (guardian idle) | `guardian_idle_after_clean_finish_{etw,debugger}` | after a clean finish the guardian prints nothing, writes no log, and has exited when the recorder's stderr closes |
| 5.5 (sessions) | `stale_session_is_cleaned_up` | a `heapspy-<dead pid>` session is stopped by the next recording, which says so |
| 5.5 (sessions) | `foreign_sessions_are_untouched` | `heapspy-foreign`, `heapspyx-<pid>` and `other-<pid>` survive a recording |
| 5.2 (Ctrl-C) | `ctrl_break_etw`, `ctrl_break_debugger` | `CTRL_BREAK_EVENT` to the recorder's process group (Ctrl-C cannot be sent to one group): exit 0 within 5 s, a valid profile flagged truncated, the target clean as above |
| 5.2 (Ctrl-C) | `stop_flag_etw`, `stop_flag_debugger` | the same through `heapspy_record::record` and its stop flag |
| 7 (versions) | the `_etw` and `_debugger` tests | run on python-build-standalone 3.12, 3.13 and 3.14 |
| setup | every test | the process is elevated (`TokenElevation`); the workflow also prints `logman query -ets` before and after |

ETW frames are matched by time, so the ETW checks are statistical: see the
module docs of `record_live_windows.rs` for why the top stack itself is not
required to be `build_payload:5`.

Not automated: step 1 (watching thread states in Process Explorer), 5.3
(target exits mid-run), 5.4 (not elevated: the runner always is), 5.5
(kernel logger busy), 6 (EDR), and Windows 10. Step 2.4 is measured: on
`windows-latest` every ETW sample matched a stack within 20 ms.

## Setup

- Windows 10 22H2 and Windows 11 (x64). On one of them, also a machine
  with Windows Defender real-time protection on (the default). Use an EDR
  product if one is available.
- An elevated prompt (Run as administrator), so heapspy can enable
  `SeDebugPrivilege` and start the kernel ETW session.
- python.org CPython 3.12, 3.13 and 3.14 (x64, not free-threaded).
- `cargo build --release`, and `heapspy.exe` on `PATH`.
- No other kernel-logger user running: close xperf, WPR, Process Monitor
  and Process Explorer's ETW views. The recorder uses the "NT Kernel
  Logger" session and reports `unsupported` if it is taken.

Victim `victim.py`, the same chain as the Linux live tests (lines matter:
arenas are carved at line 5, payloads at line 6):

```python
import os, sys, time
keep = []
leaked = []
def build_payload(i):
    leaked.append([i] * 16)
    return bytes(64 * 1024)
def handler(i):
    keep.append(build_payload(i))
    if len(keep) > 200:
        del keep[0]
def noise():
    return bytes(16 * 1024)
def main():
    i = 0
    while True:
        handler(i)
        noise()
        i += 1
main()
```

Start it with `py -3.13 victim.py` and take its PID from Task Manager or
`Get-Process python`.

## 1. live::open does not suspend the target

1. `heapspy record --pid PID --duration 10s --mechanism etw -o a.hpya`.
2. While it runs, watch the victim in Process Explorer (threads tab).
   - Expect: its threads never show as suspended, and its CPU use stays
     near one core.

## 2. ETW only (approximate frames)

1. `heapspy record --json --pid PID --duration 5s --mechanism etw -o etw.hpya --then-dump etw.hpy`.
   - Expect exit 0, `"mechanisms": ["etw"]`, and `samples > 0`. The victim
     maps about one arena per 5,000 iterations.
2. `heapspy analyze etw.hpy --allocations etw.hpya --json`.
   - Expect: `allocations.approximate` is true, and the top stacks
     contain `build_payload` and `handler`, each with `"approximate": true`.
     The line is where the thread was at the nearest stack sample, usually
     6 (the 64 KiB `bytes`), not the arena call at line 5; the top stack is
     sometimes `handler:8` or `main:20` alone.
   - Expect: `allocations.sampling.events` is `["arena"]`, and the profile
     meta `heapspy.skipped_events` mentions `large_object`.
3. Note `overhead.samples_dropped`, which is ETW `EventsLost` plus
   `RealTimeBuffersLost`; it should be 0.
4. Measure how far ETW events land from the stack samples (spike item):
   rerun with the matcher distance logged, or compare the share of samples
   with no frames. Fewer than 5% without frames is good. If many have
   none, raise `MAX_DISTANCE_NS` in `windows.rs` (20 ms today) or the
   sampling rate (5 ms).

## 3. Debugger only (exact frames)

1. `heapspy record --json --pid PID --duration 5s --mechanism debugger -o dbg.hpya --then-dump dbg.hpy`.
   - Expect `"mechanisms": ["debugger"]`, `samples > 0`, and
     `overhead.total_pause_ns > 0`.
2. `heapspy analyze dbg.hpy --allocations dbg.hpya --json`.
   - Expect: `approximate` is false, and the top stack is `build_payload`
     (line 5) ← `handler` ← `main`, with `native_return_address` inside
     `python3XY.dll`.
3. After heapspy exits:
   - Expect the victim is still running. Process Explorer shows no
     debugger, and the victim's handle list no longer has heapspy.
   - Code bytes: in WinDbg (non-invasive attach, `windbg -pv -p PID`),
     `u KERNELBASE!VirtualAlloc L2` shows the original instructions, not
     `int 3`.

## 4. Both (auto)

1. `heapspy record --pid PID --duration 5s -o both.hpya --then-dump both.hpy`.
   - Expect `"mechanisms": ["etw", "debugger"]`.
   - Expect: arenas seen by both are written once. Samples whose address
     the debugger recorded have exact frames, and there are no duplicate
     addresses at the same time.

## 5. Safety

1. **Kill mid-run.** Start a 60 s recording with `--mechanism debugger`.
   After 2 s, `taskkill /F /IM heapspy.exe`.
   - Expect: the victim keeps running, and within half a second the
     guardian has restored `VirtualAlloc`, detached and stopped the ETW
     session; stderr has one `heapspy guardian:` line and the profile's
     directory a `.guardian.log`.
   - Then `taskkill /T /F` the recorder's tree instead: the guardian dies
     too (a documented limit). Expect the victim to crash at its next arena
     with `STATUS_BREAKPOINT`, and the next recording to stop the leftover
     `heapspy-<pid>` session.
2. **Ctrl-C.** Start a 60 s recording in each mode and press Ctrl-C after
   2 s.
   - Expect: exit 0 within 2 s, a valid profile with `truncated: true`,
     and the victim running with no debugger attached.
3. **Target exits mid-run.** Kill the victim during a recording.
   - Expect: the recording ends early with `truncated: true`, or with
     `no_such_process` before any sample.
4. **Not elevated.** Run from a normal prompt.
   - Expect: `permission_denied` (ETW and the debugger both refuse), and
     no profile written.
5. **Kernel logger busy.** Start `xperf -on PROC_THREAD` first, then
   record with `--mechanism etw`.
   - Expect: the recording runs anyway in its own `heapspy-<pid>`
     session (system logger mode does not need the NT Kernel Logger).
   - Only where the system logger mode is refused (pre-Windows 8) is the
     NT Kernel Logger used; then expect `unsupported` naming it.

## 6. EDR (spike item)

With Defender real-time protection on, repeat step 3. Then repeat it with
any EDR available.
- Expect: either it works, or `DebugActiveProcess` fails with access
  denied. In that case `auto` must still record with ETW alone and say so
  in `heapspy.windows.mechanism_failed`. Record any alert the security
  product raises.

## 7. Versions

Repeat steps 2 and 3 on 3.12, 3.13 and 3.14.
- 3.12 on Windows has a 4-byte `native_thread_id`. A wrong size there
  shows up as no frames at all in step 3.

## Results

Results on `windows-latest` from the record workflow runs 42351820140,
42352771607 and 42353444868 (November 2026; the job log prints the OS
version).

| step | Windows 10 | Windows 11 | windows-latest (CI) | notes |
|---|---|---|---|---|
| 1 | | | not automated | |
| 2 | | | pass, 3.12 to 3.14 | 84 to 119 samples in 3 s, all matched a stack, 0 dropped. Top stack `build_payload:6 <- handler:8` in 7 of 9 runs, `handler:8` or `main:20` in the other two |
| 3 | | | pass, 3.12 to 3.14 | 163 to 179 samples, top stack `build_payload:5 <- handler:8` (139 to 154 samples), threads stopped about 2.9 s in a 3 s window. Needed the fix for single steps queued at detach (see 5.2) |
| 4 | | | pass, 3.13 | 184 samples, 0 approximate: every arena ETW saw was also seen by the debugger |
| 5.1 | | | pass (guardian) | see "Kill safety" below. Before the guardian: **fail** | debugger: the target dies with `STATUS_BREAKPOINT` (0x80000003), the `int3` left in `VirtualAlloc`, the known risk above. ETW: the `NT Kernel Logger` session stays running after the recorder is killed, and the next recording fails with `unsupported` until `logman stop "NT Kernel Logger" -ets` |
| 5.2 | | | pass | Ctrl-Break stops in 0.1 to 0.2 s with a truncated profile; the stop flag in 2.6 s. Before the fix, the debugger left a queued `EXCEPTION_SINGLE_STEP` to the target, which died with 0x80000004 |
| 5.3-5.5 | | | not automated | |
| 6 | | | not checked | Defender's ETW sessions run on the runner (`logman`); whether real-time protection is on was not checked. Nothing blocked `DebugActiveProcess` |
| 7 | | | pass | python-build-standalone 3.12, 3.13, 3.14 |

### Kill safety (the guardian)

Record workflow runs 42358155568 and 42359502629 on PR #37 (November 2026).
Run 42359502629 passed all 17 `record_live_windows` tests on 3.12, 3.13 and
3.14; the Linux job stayed green in both.

| test | result |
|---|---|
| `kill_mid_run_debugger` | target running, no debugger attached, `VirtualAlloc` unchanged. Guardian log, run 1: restored `0xcc -> 0x48`, detached. Run 2: the same, plus thread 5372 with its trap flag set and a pending `EXCEPTION_SINGLE_STEP` (cleared, continued) |
| `kill_mid_run_etw` | target running; the guardian stopped `heapspy-<recorder pid>`; no session left |
| `guardian_idle_after_clean_finish_{etw,debugger}` | no guardian output, no log |
| `stale_session_is_cleaned_up` | `heapspy-<dead pid>` stopped by the next recording, reported on stderr |
| `foreign_sessions_are_untouched` | `heapspy-foreign`, `heapspyx-<pid>`, `other-<pid>` all still running |
| `python313_auto` | `mechanisms: ["etw"]`, 117 samples, paused 0 ms |
| ETW session | `heapspy-<pid>` in system logger mode starts and delivers events on windows-latest; `NT Kernel Logger` is not used |

Run 1 failed every ETW test that stops a session: `ControlTraceW` with the
start properties block (system trace GUID, kernel flags) returns
`ERROR_INVALID_PARAMETER` (87) for a system logger session. Control calls now
pass a bare block. In run 1 `python314_etw` also missed the statistical top-5
check once; it passed in run 2.
