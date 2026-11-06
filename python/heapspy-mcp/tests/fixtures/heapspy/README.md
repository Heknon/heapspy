# heapspy CLI fixtures

Example documents copied unchanged from heapspy branches that are not merged
into this one yet. `tests/fake_heapspy.py` prints them.

| file | copied from |
|---|---|
| `dump.json` | `docs/examples/dump.json` on `feature/dump-json-errors` (PR #20), commit 40c85ed |
| `analyze_allocations.json` | `docs/examples/analyze_allocations.json` on `feature/alloc-join` (PR #19), commit b04cc2f |

When those branches are merged, these copies can be replaced by the files in
`docs/examples/`.

## `contract.snapshot` and `contract.hpya`

A synthetic snapshot (`contract.snapshot`, a `.hpy` file renamed because
`*.hpy` is git-ignored in this repository) and allocation profile for
`tests/test_contract_real.py`, which runs the allocation tools against a real
heapspy binary. The test copies them to a temporary directory as
`contract.hpy` and `contract.hpya`. Both were
written with heapspy's test builders (`SnapshotBuilder`, `ProfileBuilder`) at
`feature/alloc-join` commit b04cc2f, and are deterministic.

- Snapshot: pid 4242, CPython 3.12.0, captured at Unix second 2000.
  `sys.modules['app.cache']` holds `CACHE`, a dict of three 64 KiB `bytes`
  objects; `sys.modules['app.session']` holds `SESSIONS`, a list of 200
  `app.session.Session` objects of 1 KiB, all inside one 1 MiB range.
- Profile: pid 4242, CPython 3.12.0, recorded from second 1000 to 1060, five
  samples. One arena sample over the Session objects
  (`Session.__init__` < `SessionStore.create` < `handle_login`, approximate
  links), three large-object samples on the `CACHE` values (`fill_cache` <
  `main`, exact links), and one 2 MiB large-object sample that links to
  nothing (`build_report` < `main`).

To regenerate them, put the program below in a heapspy checkout of
`feature/alloc-join` (or later) as `crates/heapspy/examples/contract_fixtures.rs`
(it is not part of heapspy) and run:

```sh
cargo run --release -p heapspy --example contract_fixtures -- OUT_DIR
cp OUT_DIR/contract.hpy python/heapspy-mcp/tests/fixtures/heapspy/contract.snapshot
cp OUT_DIR/contract.hpya python/heapspy-mcp/tests/fixtures/heapspy/
```

```rust
//! Writes the synthetic snapshot and allocation profile used by the
//! heapspy-mcp real-binary contract tests.
//!
//! cargo run --release -p heapspy --example contract_fixtures -- OUT_DIR

use heapspy_alloc::{EventKind, ProfileBuilder, PythonVersion};
use heapspy_snapshot::{RootKind, SnapshotBuilder};

fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("OUT_DIR"));
    std::fs::create_dir_all(&out).unwrap();

    // Snapshot of pid 4242, CPython 3.12.0, captured at Unix second 2000.
    let mut b = SnapshotBuilder::new();
    b.info_mut().source.reference = "4242".into();
    b.info_mut().captured_at = 2000;
    let module = b.ty("builtins", "module");
    let dict = b.ty("builtins", "dict");
    let list = b.ty("builtins", "list");
    let bytes = b.ty("builtins", "bytes");
    let session = b.ty("app.session", "Session");

    // app.cache.CACHE: a dict of three 64 KiB bytes objects (large objects).
    b.object(0x1000, module, 72).attr(0x1100, "__dict__");
    b.object(0x1100, dict, 1000).dict_value(0x2000, "'CACHE'");
    {
        let o = b.object(0x2000, dict, 600);
        for i in 0..3u64 {
            o.dict_value(0x40_0000 + i * 0x1_0000, &format!("'k{i}'"));
        }
    }
    for i in 0..3u64 {
        b.object(0x40_0000 + i * 0x1_0000, bytes, 65536).untracked();
    }
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app.cache']");

    // app.session.SESSIONS: a list of 200 Session objects in one arena.
    b.object(0x3000, module, 72).attr(0x3100, "__dict__");
    b.object(0x3100, dict, 1000).dict_value(0x3200, "'SESSIONS'");
    {
        let o = b.object(0x3200, list, 1656);
        for i in 0..200u32 {
            o.list_item(0x100_0000 + u64::from(i) * 0x400, i);
        }
    }
    for i in 0..200u64 {
        b.object(0x100_0000 + i * 0x400, session, 1024);
    }
    b.root(0x3000, RootKind::ModuleDict, "sys.modules['app.session']");
    b.write_to(out.join("contract.hpy")).unwrap();

    // Profile of pid 4242, CPython 3.12.0, recorded from second 1000 to 1060.
    let mut p = ProfileBuilder::new();
    p.info_mut().pid = 4242;
    p.info_mut().python = PythonVersion::new(3, 12, 0);
    p.info_mut().start_ns = 1000 * 1_000_000_000;
    p.info_mut().end_ns = 1060 * 1_000_000_000;
    let fill = p.code_with_lines(0x7f00_1000, "fill_cache", "app/cache.py", 10, &[(8, 11), (8, 12)]);
    let main = p.code_with_lines(0x7f00_2000, "main", "app/main.py", 1, &[(16, 5)]);
    let init = p.code_with_lines(0x7f00_3000, "Session.__init__", "app/session.py", 40, &[(8, 41)]);
    let create =
        p.code_with_lines(0x7f00_4000, "SessionStore.create", "app/session.py", 85, &[(8, 88)]);
    let login = p.code_with_lines(0x7f00_5000, "handle_login", "app/views.py", 118, &[(8, 120)]);
    let report = p.code_with_lines(0x7f00_6000, "build_report", "app/reports.py", 50, &[(8, 57)]);
    let t0 = 1000 * 1_000_000_000u64;
    // One arena that the Session objects were carved from (approximate links).
    p.sample(EventKind::Arena, 0x100_0000, 1 << 20)
        .at(t0 + 1_000)
        .frame(init, 2)
        .frame(create, 2)
        .frame(login, 2);
    // Three large objects (exact links).
    for i in 0..3u64 {
        p.sample(EventKind::LargeObject, 0x40_0000 + i * 0x1_0000, 65536)
            .at(t0 + 2_000 + i)
            .frame(fill, 10)
            .frame(main, 4);
    }
    // A large object that is gone by the time of the snapshot (links nothing).
    p.sample(EventKind::LargeObject, 0x900_0000, 2 << 20)
        .at(t0 + 3_000)
        .frame(report, 2)
        .frame(main, 4);
    p.write_to(out.join("contract.hpya")).unwrap();
    println!("wrote {}", out.display());
}
```
