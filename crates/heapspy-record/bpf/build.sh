#!/bin/sh
# Rebuild heapspy.bpf.o from heapspy.bpf.c. `--check` rebuilds into a
# temporary file and fails if it differs from the committed object.
# Needs clang with the BPF target (tested with clang 18).
set -eu
cd "$(dirname "$0")"
CLANG=${CLANG:-clang}
out=heapspy.bpf.o
[ "${1:-}" = "--check" ] && out=$(mktemp)
"$CLANG" -target bpf -O2 -g0 -fno-ident -fdebug-prefix-map="$PWD"=. \
    -Wall -Werror -c heapspy.bpf.c -o "$out"
llvm-strip-18 -g "$out" 2>/dev/null || llvm-strip -g "$out" 2>/dev/null || true
if [ "${1:-}" = "--check" ]; then
    if cmp -s "$out" heapspy.bpf.o; then echo "heapspy.bpf.o is up to date"; rm -f "$out"
    else echo "heapspy.bpf.o differs from heapspy.bpf.c; run crates/heapspy-record/bpf/build.sh" >&2; rm -f "$out"; exit 1; fi
fi
