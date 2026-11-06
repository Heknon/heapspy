"""Each leak fixture, on each interpreter, with each acquisition method.

The victim builds a known leak plus noise; heapspy must name the leak's
holder as the top retainer, at the expected root path, with a retained size
in the band computed by the victim, and with the expected labelled hops on
the retaining path.
"""

from __future__ import annotations

from typing import Any

import pytest

from expectations import FIXTURES, RETAINED_HI, RETAINED_LO, Fixture
from harness import acquire, edges, is_subsequence, render_path


def check_snapshot_summary(doc: dict[str, Any], python, method: str) -> None:
    snap = doc["snapshot"]
    assert snap["python_version"].startswith(python.version), snap
    assert snap["truncated"] is False, snap
    assert snap["contents_captured"] is False, snap
    assert snap["pointer_size"] == 8, snap
    assert snap["source"]["kind"] == method, snap


def check_analyze(report: dict[str, Any], fx: Fixture, info: dict[str, Any]) -> dict[str, Any]:
    tops = report["top_retainers"]
    assert tops, report
    top = tops[0]
    listing = [(t["rank"], t["type"], t["retained_bytes"], render_path(t["path"])) for t in tops]
    assert top["rank"] == 1
    assert top["type"] == fx.top_type, listing
    assert render_path(top["path"]) == fx.top_root_path(info), listing
    assert top["path"][0]["root_kind"] == "module_dict", top["path"][0]

    expected = info["expected_retained"]
    assert expected * RETAINED_LO <= top["retained_bytes"] <= expected * RETAINED_HI, (
        f"retained {top['retained_bytes']} not within "
        f"[{RETAINED_LO}, {RETAINED_HI}] x {expected} (victim's getsizeof total)"
    )

    sites = [render_path(t["path"]) for t in tops]
    for noise in fx.noise_root_paths:
        assert noise in sites[1:], (noise, listing)
        assert tops[sites.index(noise)]["retained_bytes"] < top["retained_bytes"]
    if fx.extra:
        fx.extra(report, info)
    return top


def check_queries(heapspy, snap, fx: Fixture, info: dict[str, Any], top: dict[str, Any]) -> None:
    # The retaining path of the top retainer, by address.
    doc = heapspy.path_to(snap, top["address"])
    (target,) = doc["targets"]
    assert target["address"] == top["address"]
    assert target["reachable"] is True
    assert target["retained_bytes"] == top["retained_bytes"]
    first = target["paths"][0]
    assert is_subsequence(fx.top_path_edges(info), edges(first)), edges(first)
    assert render_path(first) == fx.top_root_path(info)

    if fx.type_query:
        q = fx.type_query
        doc = heapspy.query_type(snap, q.type)
        assert doc["matched_types"] == [q.type], doc["matched_types"]
        assert doc["instances"] == q.instances(info), doc["instances"]
        holders = {(h["type"], h["edge"]): h["count"] for h in doc["holders"]}
        for h in q.holders:
            assert holders.get((h.type, h.edge)) == h.count(info), (h, doc["holders"])

    if fx.path_type_query:
        q = fx.path_type_query
        doc = heapspy.path_to_type(snap, q.type, top=q.top)
        assert doc["query"] == {"by": "type", "value": q.type}
        assert len(doc["targets"]) == q.top, doc["targets"]
        want = q.edges(info)
        for t in doc["targets"]:
            assert t["type"] == q.type
            assert t["reachable"] and t["paths"], t
            assert any(is_subsequence(want, edges(p)) for p in t["paths"]), (
                want,
                [edges(p) for p in t["paths"]],
            )
            if q.root_path_prefix:
                assert render_path(t["paths"][0]).startswith(q.root_path_prefix), render_path(
                    t["paths"][0]
                )


@pytest.mark.parametrize("fx", FIXTURES, ids=[f.name for f in FIXTURES])
def test_fixture(heapspy, start_victim, tmp_path, python, method, fx: Fixture) -> None:
    victim = start_victim(python, fx.script)
    info = victim.info
    snap = acquire(heapspy, method, victim, tmp_path)
    victim.kill()  # analysis only reads the snapshot

    report = heapspy.analyze(snap)
    check_snapshot_summary(report, python, method)
    top = check_analyze(report, fx, info)
    check_queries(heapspy, snap, fx, info, top)
