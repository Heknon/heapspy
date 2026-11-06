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

End-to-end jobs (fixture Python processes, core dumps, minidumps) will be added
later. They will run on a `ci:e2e` label and on tag pushes.

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
