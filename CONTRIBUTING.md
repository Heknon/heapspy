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
