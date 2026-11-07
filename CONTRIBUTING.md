# Contributing

## Run checks locally

CI on GitHub does not run on every push. Run these before you push:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace --target x86_64-pc-windows-gnu
```

The last command type-checks the Windows `cfg` code from a Linux or macOS
machine. Add the target once with `rustup target add x86_64-pc-windows-gnu`.
It does not link or run anything, so no MinGW toolchain is needed.

## Running CI on GitHub

The workflow in `.github/workflows/ci.yml` runs only when asked:

| Trigger | What runs |
|---|---|
| PR label `ci` | fmt, clippy and `cargo test --workspace` on ubuntu-latest |
| PR label `ci:windows` | `cargo test --workspace` on windows-latest |
| tag push matching `v*` | both jobs |
| manual dispatch (Actions tab) | both jobs |

Once a label is on a PR, later pushes to that PR run the labelled jobs again.
Remove the label to stop that. Pushes to `master` do not run CI. Changes that
touch only Markdown files or `docs/` do not trigger a PR run.

End-to-end tests (`.github/workflows/e2e.yml`) run heapspy against real
CPython processes on Linux and Windows, for Python 3.12, 3.13 and 3.14:

| Trigger | What runs |
|---|---|
| PR label `ci:e2e` | the Linux and Windows e2e matrices |
| tag push matching `v*` | both |
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

Live `heapspy record` tests (`.github/workflows/record.yml`) record real
CPython 3.12, 3.13 and 3.14 processes through every mechanism:

| Trigger | What runs |
|---|---|
| PR label `ci:record` | Linux (eBPF, ptrace, as root) and Windows (ETW, debugger) |
| tag push matching `v*` | both |
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
publishes them. It also runs only when asked:

| Trigger | What runs |
|---|---|
| tag push matching `v*` | version check, all builds, publish to PyPI, GitHub release |
| manual dispatch, `publish: none` | version check and all builds; artifacts on the run page |
| manual dispatch, `publish: testpypi` | the same, then upload to TestPyPI |

It has no PR or branch push triggers. A tag push runs both this workflow and
`ci.yml`. See [docs/releasing.md](docs/releasing.md) for the release steps.

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
