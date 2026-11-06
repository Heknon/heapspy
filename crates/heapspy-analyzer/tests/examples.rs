//! The example documents in docs/examples/ must match the report structs
//! exactly: every field in the example is known to the struct, and every
//! struct field appears in the example.

use std::path::PathBuf;

use heapspy_analyzer::report::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

fn example(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples")
        .join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn round_trip<T: DeserializeOwned + Serialize>(name: &str) -> T {
    let original = example(name);
    let parsed: T = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("{name} does not match the struct: {e}"));
    let again = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        again, original,
        "{name}: fields missing from or unknown to the struct"
    );
    parsed
}

#[test]
fn analyze_example() {
    let r: AnalyzeReport = round_trip("analyze.json");
    assert_eq!(r.top_retainers[0].path[0].edge, None);
    assert!(r.top_retainers[0].path[0].root_label.is_some());
    assert_eq!(r.top_retainers[0].address, Address(0x7f3a2c41b0d0));
}

#[test]
fn analyze_allocations_example() {
    let r: AnalyzeReport = round_trip("analyze_allocations.json");
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.mechanisms, ["ebpf"]);
    assert_eq!(a.top_stacks[0].rank, 1);
    assert_eq!(a.top_stacks[0].frames[0].location, "app/session.py:41");
    let at = r.top_retainers[0].allocated_at.as_ref().unwrap();
    assert_eq!(at.stacks[0].top_stack_rank, Some(1));
    assert_eq!(at.stacks[0].frames, a.top_stacks[0].frames);
    // Without --allocations the fields are present and null.
    let plain: AnalyzeReport = round_trip("analyze.json");
    assert!(plain.allocations.is_none());
    assert!(plain.top_retainers.iter().all(|t| t.allocated_at.is_none()));
}

/// Documents written before the allocation fields existed still parse.
#[test]
fn documents_without_allocation_fields_parse() {
    let mut v = example("analyze_allocations.json");
    v.as_object_mut().unwrap().remove("allocations");
    for t in v["top_retainers"].as_array_mut().unwrap() {
        t.as_object_mut().unwrap().remove("allocated_at");
    }
    let r: AnalyzeReport = serde_json::from_value(v).unwrap();
    assert!(r.allocations.is_none());
    assert!(r.top_retainers.iter().all(|t| t.allocated_at.is_none()));

    let mut v = example("type_query.json");
    for t in v["top_instances"].as_array_mut().unwrap() {
        t.as_object_mut().unwrap().remove("allocated_at");
    }
    let r: TypeQueryReport = serde_json::from_value(v).unwrap();
    assert!(r.top_instances.iter().all(|t| t.allocated_at.is_none()));
}

#[test]
fn type_query_example() {
    let _: TypeQueryReport = round_trip("type_query.json");
}

#[test]
fn retaining_path_example() {
    let r: RetainingPathReport = round_trip("retaining_path.json");
    assert_eq!(r.query.by, PathQueryBy::Address);
}

#[test]
fn diff_example() {
    let r: DiffReport = round_trip("diff.json");
    assert!(r.identity_approximate);
}

#[test]
fn error_example() {
    let _: ErrorReport = round_trip("error.json");
}

#[test]
fn every_example_is_tested() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "analyze.json",
            "analyze_allocations.json",
            "diff.json",
            "error.json",
            "retaining_path.json",
            "type_query.json"
        ]
    );
}

#[test]
fn wrong_schema_version_or_kind_rejected() {
    let mut v = example("error.json");
    v["schema_version"] = 2.into();
    assert!(serde_json::from_value::<ErrorReport>(v).is_err());
    let mut v = example("error.json");
    v["kind"] = "analyze".into();
    assert!(serde_json::from_value::<ErrorReport>(v).is_err());
    // A report of one kind does not parse as another.
    assert!(serde_json::from_value::<DiffReport>(example("analyze.json")).is_err());
}

#[test]
fn address_format() {
    assert_eq!(Address(0x7f3a2c41b0d0).to_string(), "0x7f3a2c41b0d0");
    assert_eq!("0X1F".parse::<Address>().unwrap(), Address(0x1f));
    assert!("1234".parse::<Address>().is_err());
    assert!("0xzz".parse::<Address>().is_err());
    assert_eq!(serde_json::to_string(&Address(255)).unwrap(), "\"0xff\"");
}
