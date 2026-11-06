# Windows recorder: manual test plan

`heapspy record` on Windows (M7b, `crates/heapspy-record/src/windows*`) is
compiled and clippy-checked for `x86_64-pc-windows-gnu`, and its logic is
unit-tested on Linux:
- ETW and QPC clock conversion (`windows::clock`)
- nearest-stack matching (`windows::matcher`)
- the debugger's breakpoint state machine (`windows::debug`)

The Win32 glue has never run. Do every step below on a real machine before
calling M7b done, and record the results at the end of this file.

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
   - Expect: `allocations.approximate` is true, and `top_stacks[0].frames`
     contains `build_payload` (line 5) and `handler`, each with
     `"approximate": true`.
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
   - Expect: the victim keeps running (`DebugSetProcessKillOnExit(FALSE)`).
   - Known risk: an `int3` written by the dead debugger stays in
     `VirtualAlloc`, and the next arena allocation then raises an
     unhandled breakpoint and kills the victim. If that happens, it is a
     real gap. A fix would be a watchdog process, or ETW only for the
     unattended case. Record what happens.
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
   - Expect: `unsupported` naming the NT Kernel Logger.
   - With `auto`: the debugger alone runs, and meta
     `heapspy.windows.mechanism_failed` says why ETW did not.

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

| step | Windows 10 | Windows 11 | notes |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5.1 | | | |
| 5.2-5.5 | | | |
| 6 | | | |
| 7 | | | |
