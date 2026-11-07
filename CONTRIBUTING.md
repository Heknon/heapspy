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

### Release workflow

`.github/workflows/release.yml` builds the PyPI wheels and sdists and
publishes them. Releasing is a version bump merged to `master`:

| Trigger | What runs |
|---|---|
| push to `master`, version already tagged | only the `gate` job, which stops |
| push to `master`, version not tagged yet | CI, E2E, version check, all builds, publish to PyPI, tag `vX.Y.Z`, GitHub release |
| tag push matching `v*` | the same, for the tagged commit |
| manual dispatch, `publish: none` | CI, E2E, version check and all builds; artifacts on the run page |
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
