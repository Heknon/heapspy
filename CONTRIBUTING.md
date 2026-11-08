# Contributing

## Run checks locally

CI on GitHub does not run on every push. Run these before you push:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace --target x86_64-pc-windows-gnu
cargo check --workspace --target x86_64-unknown-linux-musl
```

The last two commands type-check the code for the other release targets.
The Windows one checks the Windows `cfg` code from a Linux or macOS machine;
the musl one catches libc signatures that differ from glibc's. Add the
targets once with `rustup target add x86_64-pc-windows-gnu
x86_64-unknown-linux-musl`. Neither links anything, so no MinGW or musl
toolchain is needed.

## Running CI on GitHub

The workflow in `.github/workflows/ci.yml` runs only when asked:

| Trigger | What runs |
|---|---|
| PR label `ci` | fmt, clippy (glibc and musl) and `cargo test --workspace` on ubuntu-latest |
| PR label `ci:windows` | `cargo test --workspace` on windows-latest |
| every release (called by `release.yml`) | both jobs |
| manual dispatch (Actions tab) | both jobs |

Once a label is on a PR, later pushes to that PR run the labelled jobs again.
Remove the label to stop that. Pushes to `master` run CI only when they
release a new version. Changes that touch only Markdown files or `docs/` do
not trigger a PR run.

End-to-end tests (`.github/workflows/e2e.yml`) run heapspy against real
CPython processes on Linux and Windows, for Python 3.12, 3.13 and 3.14:

| Trigger | What runs |
|---|---|
| PR label `ci:e2e` | the Linux and Windows e2e matrices |
| every release (called by `release.yml`) | both |
| manual dispatch (Actions tab) | both; `mcp_ref` also smoke-tests heapspy-mcp from that ref |

Run them locally before adding the label (Linux, needs ptrace permission and
gdb for `gcore`):

```sh
cargo build --release
HEAPSPY_BIN=target/release/heapspy uv run --project tests/e2e pytest tests/e2e
uvx ruff check tests/e2e && uvx ruff format --check tests/e2e
```

See [tests/e2e/README.md](tests/e2e/README.md) for choosing interpreters and
adding a fixture.

The Linux e2e job also runs the glibc native heap walker against a real
CPython, live and through `gcore` (the ignored test
`crates/heapspy-reader/tests/native_heap_live.rs`). Locally, with gdb and
ptrace permission:

```sh
HEAPSPY_PY="$(uv python find 3.13)" \
    cargo test -p heapspy-reader --test native_heap_live -- --ignored --test-threads 1
```

The e2e job also checks the live counters (`watch --counters`, `top`'s
Graphs tab) against what a real CPython's `gc` and `sys` report, read
without stopping it (`crates/heapspy-reader/tests/counters_live.rs`):

```sh
cargo test -p heapspy-reader --test counters_live -- --ignored --test-threads 1
```

The same test runs against older and other glibc releases in
`.github/workflows/glibc.yml`: one distro image per malloc layout, from
Ubuntu 12.04 (glibc 2.15) to Ubuntu 24.04 (2.39). CPython does not run on
the oldest, so each image builds the C victim
(`crates/heapspy-reader/tests/victims/glibc_heap.c`) with its own gcc and
runs the test, built statically for musl, live and through `gcore` (live
only on 12.04, whose gdb 7.4 writes cores without file names):

| Trigger | What runs |
|---|---|
| PR label `ci:glibc` | every image in the matrix |
| manual dispatch (Actions tab) | the same |

Locally, the C victim stands in for CPython the same way:

```sh
gcc -O0 -o /tmp/victim crates/heapspy-reader/tests/victims/glibc_heap.c -lpthread
HEAPSPY_VICTIM=/tmp/victim \
    cargo test -p heapspy-reader --test native_heap_live -- --ignored --test-threads 1
```

Live `heapspy record` tests (`.github/workflows/record.yml`) record real
CPython 3.12, 3.13 and 3.14 processes through every mechanism:

| Trigger | What runs |
|---|---|
| PR label `ci:record` | Linux (eBPF, ptrace, as root) and Windows (ETW, debugger) |
| every release (called by `release.yml`) | both |
| manual dispatch (Actions tab) | both, or one with `side: linux` or `side: windows` |

On Linux the job prints what the runner's kernel supports
(`scripts/record-kernel-check.sh`). If the eBPF recorder cannot run there,
only the ptrace tests run, and the job summary lists the skipped eBPF tests
and the reason; the job fails if any selected test did not pass.

Run them locally. Linux, as root (or with `CAP_BPF`, `CAP_PERFMON` and
`CAP_SYS_PTRACE`), with gdb for the `gcore` tests:

```sh
uv python install 3.12 3.13 3.14
export HEAPSPY_PY312="$(uv python find --python-preference only-managed 3.12)"
export HEAPSPY_PY313="$(uv python find --python-preference only-managed 3.13)"
export HEAPSPY_PY314="$(uv python find --python-preference only-managed 3.14)"
cargo test -p heapspy --test record_live -- --ignored --test-threads 1
cargo test -p heapspy --test cpython_live -- --ignored --test-threads 1
cargo test -p heapspy-record --test live_stack -- --ignored --test-threads 1
```

Run as a normal user, build first (`cargo test --no-run`) and run the test
binaries with `sudo env HEAPSPY_PY312=... <binary> --ignored --test-threads 1`;
`sudo -E` is ignored by the sudo of recent Ubuntu releases.

Windows, from an elevated prompt, with the same `HEAPSPY_PY31X` variables
(or uv on `PATH`):

```sh
cargo test -p heapspy --test record_live_windows -- --ignored --test-threads 1 --nocapture
```

Close xperf, WPR and Process Monitor first: the ETW tests need the
`NT Kernel Logger` session. The two `kill_mid_run_*` tests fail today; see
[docs/windows-record-test-plan.md](docs/windows-record-test-plan.md).

### Release workflow

`.github/workflows/release.yml` builds the PyPI wheels and sdists and
publishes them. Releasing is a version bump merged to `master`:

| Trigger | What runs |
|---|---|
| push to `master`, version already tagged | only the `gate` job, which stops |
| push to `master`, version not tagged yet | CI, E2E, Record, version check, all builds, publish to PyPI, tag `vX.Y.Z`, GitHub release |
| tag push matching `v*` | the same, for the tagged commit |
| manual dispatch, `publish: none` | CI, E2E, Record, version check and all builds; artifacts on the run page |
| manual dispatch, `publish: testpypi` | the same, then upload to TestPyPI |

It has no PR triggers. See [docs/releasing.md](docs/releasing.md) for the
release steps.

## Commits

- Imperative subject line, under about 70 characters.
- A body that says what changed and why, when the subject does not.
- One logical change per commit.

## Contracts

These are shared between crates and with outside tooling. Change them
deliberately and update the docs in the same PR:

- Snapshot file format: `docs/snapshot-format.md`, `crates/heapspy-snapshot`.
- `MemorySource` trait: `crates/heapspy-reader/src/source/mod.rs`.
- JSON report schema: `docs/json-schema.md`, `crates/heapspy-analyzer/src/report.rs`,
  examples in `docs/examples/`.
- Allocation profile format: `docs/alloc-format.md`, `crates/heapspy-alloc`.
- Recorder interface (`Recorder`, `RecordOptions`, `SampleSink`):
  `crates/heapspy-record`; the frame offsets recorders use:
  `crates/heapspy-reader/src/cpython/frames.rs`.
