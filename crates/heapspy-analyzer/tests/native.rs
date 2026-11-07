//! Native heap blocks in the graph: retaining paths for native memory, and
//! blocks nothing points to reported as leaked.

use heapspy_analyzer::report::AnalyzeReport;
use heapspy_analyzer::{analyze, root_path_string, AnalyzeOptions};
use heapspy_snapshot::{ObjectFlags, RootKind, SnapshotBuilder};

const MIB: u64 = 1 << 20;

fn run(b: &SnapshotBuilder) -> AnalyzeReport {
    let r = analyze(&b.build().unwrap(), "t.hpy", &AnalyzeOptions::default()).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: AnalyzeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    r
}

fn shop() -> SnapshotBuilder {
    let mut b = SnapshotBuilder::new();
    let module = b.ty("builtins", "module");
    let dict = b.ty("builtins", "dict");
    let list = b.ty("builtins", "list");
    let int = b.ty("builtins", "int");
    let block = b.ty("native", "heap_block");
    let obj = b.ty("app", "Callback");
    // sys.modules['shop.native']._HANDLES = [<int that is an address>]
    b.object(0x100, module, 72)
        .attr(0x110, "__dict__")
        .refcount(1);
    b.object(0x110, dict, 64)
        .dict_value(0x120, "'_HANDLES'")
        .refcount(1);
    b.object(0x120, list, 56).list_item(0x130, 0).refcount(1);
    b.object(0x130, int, 32)
        .other(0x1000, Some("address"))
        .refcount(1);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['shop.native']");
    // The 1 MiB buffer the int points at.
    b.object(0x1000, block, MIB).flags(ObjectFlags::NATIVE);
    // A block nothing points to: leaked.
    b.object(0x2000, block, 4 * MIB).flags(ObjectFlags::NATIVE);
    // A block a C global holds, which holds a Python callback.
    b.object(0x3000, block, 128)
        .flags(ObjectFlags::NATIVE)
        .scanned(0x400, 16);
    b.object(0x400, obj, 2_000).refcount(1);
    b.root(0x3000, RootKind::Native, "ext.dll globals");
    b
}

#[test]
fn native_blocks_are_counted_and_lost_ones_reported() {
    let r = run(&shop());
    let t = &r.totals;
    assert_eq!(t.native_blocks, 3);
    assert_eq!(t.native_bytes, MIB + 4 * MIB + 128);
    assert_eq!(t.native_lost_blocks, 1);
    assert_eq!(t.native_lost_bytes, 4 * MIB);
    // A lost native block is not Python garbage.
    assert_eq!(t.unreachable_objects, 0);
    assert!(r.notes.iter().any(|n| n.code == "native_lost"));
}

#[test]
fn a_native_block_held_through_an_address_int_has_a_path() {
    let r = run(&shop());
    let top = &r.top_retainers[0];
    assert_eq!(top.retained_bytes, MIB);
    assert_eq!(
        root_path_string(&top.path),
        "sys.modules['shop.native'].__dict__['_HANDLES'][0] <address>"
    );
    assert_eq!(top.type_name, "native.heap_block");
}

#[test]
fn a_python_object_held_by_native_memory_is_not_external() {
    let r = run(&shop());
    // The callback's one owner is the native block, which a C global holds.
    assert_eq!(r.totals.external_objects, 0);
    let cb = r
        .top_retainers
        .iter()
        .find(|t| t.type_name == "app.Callback" || t.address.0 == 0x3000)
        .expect("the callback or its block is a top retainer");
    assert_eq!(cb.path[0].root_label.as_deref(), Some("ext.dll globals"));
    assert_eq!(cb.path[0].root_kind.as_deref(), Some("native"));
}
