# End-to-end tests

These tests run the built `heapspy` binary against real CPython processes
that hold known leaks, and check that `analyze`, `query` and `diff` name the
right holder, with the right size and the right retaining path.

## Running locally

Linux, with permission to ptrace other processes of your user
(`kernel.yama.ptrace_scope` 0, or root) and `gdb` installed for `gcore`:

```sh
cargo build --release
HEAPSPY_BIN=target/release/heapspy uv run --project tests/e2e pytest tests/e2e
```

Without `HEAPSPY_BIN`, the session fixture runs `cargo build --release` itself.
Each victim interpreter is tested with every acquisition method. To run one
case, select it by id, for example
`-k "unbounded_cache and pid"` or `-k test_diff`.

The pytest summary ends with a "heapspy timings" section: per test, how long
each victim took to get ready, each `gcore` / `procdump`, each `heapspy`
call, and for the performance test the total.

## Interpreters

Set `HEAPSPY_E2E_PYTHONS` to a list of interpreters separated by `:` (`;` on
Windows). An entry is a path or `label=path`; the label is used in test ids.

```sh
export HEAPSPY_E2E_PYTHONS="debian-3.12=/usr/bin/python3.12:pbs-3.13=$(uv python find --python-preference only-managed 3.13)"
```

Without it, the suite uses whatever `uv python find` returns for 3.12, 3.13
and 3.14. Free-threaded and debug builds are rejected at start-up, because
heapspy does not support them.

The suite has been run on `/usr/bin/python3.12` (3.12.3, distribution
package), `/usr/local/bin/python3.13` (3.13.18), and python-build-standalone
3.12.13, 3.13.14 and 3.14.6 from `uv python install`. CI uses
python-build-standalone builds.

## Acquisition methods

| platform | `method` | how the snapshot is taken |
|---|---|---|
| Linux | `pid` | `heapspy dump --pid` (ptrace) |
| Linux | `core` | `gcore`, then `heapspy dump --core` |
| Windows | `pid` | `heapspy dump --pid` (heapspy writes a temporary minidump) |
| Windows | `minidump` | `procdump -accepteula -ma`, then `heapspy dump --minidump` |

The Windows path has not been run yet; see "Status" below.

## Environment variables

| variable | default | meaning |
|---|---|---|
| `HEAPSPY_BIN` | build with cargo | heapspy executable to test |
| `HEAPSPY_E2E_PYTHONS` | `uv python find` 3.12 to 3.14 | victim interpreters |
| `HEAPSPY_E2E_TIMEOUT` | 300 | seconds one heapspy, gcore or procdump call may take |
| `HEAPSPY_E2E_READY_TIMEOUT` | 180 | seconds a victim may take to build its heap |
| `HEAPSPY_E2E_PERF_BUDGET` | 120 | seconds for dump plus analyze of the 2M-object heap |
| `HEAPSPY_E2E_REPORT` | unset | write the timings as JSON to this file |
| `HEAPSPY_PROCDUMP` | `procdump64.exe` on PATH | Sysinternals procdump (Windows) |
| `HEAPSPY_MCP_DIR` | unset | a checkout of `python/heapspy-mcp`; enables `test_mcp.py` |

## What is tested

| file | what |
|---|---|
| `test_fixtures.py` | each leak fixture: top retainer type and root path, retained bytes in band, retaining-path hops, type queries |
| `test_diff.py` | dump the growing list, grow it, dump again: `diff` puts the growth at `EVENTS` |
| `test_robustness.py` | cut cores and minidumps, non-Python processes, exited and nonexistent PIDs, junk images, ptrace refused (as root, Linux), a non-snapshot file, a busy multi-threaded target; failures are checked for their `dump --json` error code |
| `test_perf.py` | about 2.1M objects dumped and analyzed within the budget |
| `test_mcp.py` | heapspy-mcp's tools against the real binary (only with `HEAPSPY_MCP_DIR`) |

To run the MCP smoke test, check out the branch that has `python/heapspy-mcp`
somewhere else (for example `git worktree add ../mcp origin/feature/mcp-server`)
and set `HEAPSPY_MCP_DIR=../mcp/python/heapspy-mcp`. The test runs the tools
in that project's own environment with `uv run --project`. When that
heapspy-mcp's `map_to_source` takes a `snapshot`, the test also checks that
`__main__.CachedResponse` resolves exactly to its `class` line from the
location the snapshot recorded.

## Fixtures

Each victim in `victims/` is a script run as `python VICTIM.py WORKDIR`. It
builds its heap at import time, computes the facts the test needs about
itself (sizes with `sys.getsizeof`, counts, indices), and in its
`if __name__ == "__main__":` block calls `_victim.ready(**facts)`, which writes
`WORKDIR/ready.json`, then `_victim.serve()`, which sleeps until the process
is killed. A victim that changes on request passes a callback to `serve`; the
test creates `WORKDIR/trigger-<n>` and waits for `WORKDIR/done-<n>.json`.

The expectations are in `expectations.py`, one `Fixture` per victim:

- `top_type` and `top_root_path`: what `analyze --json` must rank first;
- `expected_retained` from the victim: retained bytes must be within
  `RETAINED_LO` to `RETAINED_HI` (0.98 to 1.10) of it;
- `top_path_edges`: labelled hops that `query --retaining-path` on the top
  retainer must contain, in order;
- `noise_root_paths`: other retainers that must be listed below the leak;
- optional `type_query` (instance count, holders) and `path_type_query`
  (hops that `--retaining-path-type` paths must contain);
- optional `extra` for fixture-specific checks.

Sizes are never hardcoded: the victim measures them on the interpreter under
test. heapspy's shallow size of an instance includes its attribute values
array, which `sys.getsizeof` leaves out, so heapspy reads about 2% high for
classes with instance dicts; the band allows that.

### Adding a fixture

1. Write `victims/<name>.py`: import `ready` and `serve` from `_victim`,
   build the leak and some noise of similar types that is smaller in bytes
   but larger by some naive measure (more items, more objects), and report
   `expected_retained` computed with `sys.getsizeof` over the objects the
   leak's holder owns alone. Put `ready` and `serve` under a main guard.
2. Add a `Fixture` to `FIXTURES` in `expectations.py`.
3. Run `uv run --project tests/e2e pytest tests/e2e -k <name>` on every
   interpreter you have, and `ruff check tests/e2e` and
   `ruff format --check tests/e2e`.

## Status

Linux: all tests pass on the five interpreters above with both methods.
Windows: the harness and the CI job exist but have not been run; expect to
debug the first run.
