#!/usr/bin/env bash
# Report what this Linux kernel offers `heapspy record`, and decide whether
# the eBPF live tests can run here. Used by .github/workflows/record.yml.
#
#   sudo -E scripts/record-kernel-check.sh HEAPSPY_BIN PYTHON
#
# HEAPSPY_BIN is a built heapspy, PYTHON any supported CPython. The last
# check is a real one-second `heapspy record --mechanism ebpf` against a
# sleeping PYTHON: the kernel version alone does not say whether the BPF
# program loads.
#
# Prints one line per feature. With GITHUB_OUTPUT set, writes `ebpf=true`
# or `ebpf=false` and `ebpf_reason=...` to it. Exits non-zero only when
# the script itself cannot run (not root, missing arguments).
set -u

bin="${1:?usage: record-kernel-check.sh HEAPSPY_BIN PYTHON}"
py="${2:?usage: record-kernel-check.sh HEAPSPY_BIN PYTHON}"
if [ "$(id -u)" != 0 ]; then
    echo "run as root (sudo -E)" >&2
    exit 2
fi

rel="$(uname -r)"
major="${rel%%.*}"
rest="${rel#*.}"
minor="${rest%%[!0-9]*}"
ver=$((major * 1000 + minor))
at_least() { [ "$ver" -ge $(($1 * 1000 + $2)) ]; }
yesno() { if "$@"; then echo yes; else echo no; fi; }

ebpf=true
reason=""
fail() {
    if [ "$ebpf" = true ]; then
        ebpf=false
        reason="$1"
    fi
}

printf '%-34s %s\n' "kernel" "$rel"
printf '%-34s %s\n' "BTF (/sys/kernel/btf/vmlinux)" \
    "$(yesno test -e /sys/kernel/btf/vmlinux) (not needed: the program uses no CO-RE)"
if [ -r /sys/bus/event_source/devices/uprobe/type ]; then
    printf '%-34s %s\n' "uprobe PMU" "yes (type $(cat /sys/bus/event_source/devices/uprobe/type))"
else
    printf '%-34s %s\n' "uprobe PMU" "no (required)"
    fail "the kernel has no uprobe PMU (/sys/bus/event_source/devices/uprobe)"
fi
if at_least 5 8; then
    printf '%-34s %s\n' "BPF ring buffer (5.8+)" "yes (required)"
else
    printf '%-34s %s\n' "BPF ring buffer (5.8+)" "no (required)"
    fail "kernel $rel is older than 5.8 (BPF ring buffer)"
fi
printf '%-34s %s\n' "bpf_loop (5.17+)" \
    "$(yesno at_least 5 17) (not used: the program has bounded loops)"
if at_least 6 13; then
    printf '%-34s %s\n' "uprobe sessions (6.13+)" "yes (one program per allocator function)"
else
    printf '%-34s %s\n' "uprobe sessions (6.13+)" "no (falls back to uprobe + uretprobe pairs)"
fi
for k in kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid kernel.yama.ptrace_scope; do
    printf '%-34s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo n/a)"
done
if grep -qw lockdown /sys/kernel/security/lsm 2>/dev/null; then
    printf '%-34s %s\n' "lockdown" "$(cat /sys/kernel/security/lockdown 2>/dev/null || echo n/a)"
fi

# The real check: load and attach the recorder for one second.
if [ "$ebpf" = true ]; then
    tmp="$(mktemp -d)"
    "$py" -c 'import time; time.sleep(60)' &
    victim=$!
    sleep 1
    out="$("$bin" record --pid "$victim" --duration 1s --mechanism ebpf \
        -o "$tmp/probe.hpya" --json 2>"$tmp/err")"
    rc=$?
    kill "$victim" 2>/dev/null
    wait "$victim" 2>/dev/null
    if [ "$rc" = 0 ]; then
        mode="$(strings "$tmp/probe.hpya" | grep -Eo 'large_object_attach(session|uprobe\+uretprobe|none)' |
            sed 's/large_object_attach//' | head -n1)"
        printf '%-34s %s\n' "heapspy record --mechanism ebpf" \
            "ok (large objects attached as: ${mode:-unknown})"
    else
        err="$(tr '\n' ' ' <"$tmp/err")"
        printf '%-34s %s\n' "heapspy record --mechanism ebpf" "failed (exit $rc): $err"
        # Only a refusal by this machine is a reason to skip. Any other
        # failure is a bug the eBPF tests should show, so they still run.
        # The JSON error report is on stdout.
        if grep -Eq '"code": *"(unsupported|permission_denied)"' <<<"$out"; then
            fail "heapspy record --mechanism ebpf refused on this runner: $err"
        fi
    fi
    rm -rf "$tmp"
fi

echo "eBPF tests: $ebpf${reason:+ ($reason)}"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "ebpf=$ebpf"
        echo "ebpf_reason=$reason"
    } >>"$GITHUB_OUTPUT"
fi
