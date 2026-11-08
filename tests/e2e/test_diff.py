"""``heapspy diff`` between two dumps of the growing-list victim.

The victim is dumped, asked to append ``GROW_BY`` events (file trigger), and
dumped again. The diff must put the growth at ``EVENTS``'s site, sized as the
victim measured it, and say that identity across dumps is approximate.
"""

from __future__ import annotations

from expectations import MAIN, RETAINED_HI, RETAINED_LO
from harness import acquire

EVENTS = f"{MAIN}['EVENTS']"


def test_growth_is_reported_at_the_list(heapspy, start_victim, tmp_path, python, method) -> None:
    victim = start_victim(python, "growing_list.py")
    before = acquire(heapspy, method, victim, tmp_path, "before")
    grown = victim.trigger(1)
    after = acquire(heapspy, method, victim, tmp_path, "after")
    victim.kill()

    doc = heapspy.diff(before, after)
    assert doc["identity_approximate"] is True
    assert "identity_approximate" in [n["code"] for n in doc["notes"]]
    assert doc["before"]["path"] == str(before) and doc["after"]["path"] == str(after)
    assert doc["before"]["python_version"] == doc["after"]["python_version"]

    added = grown["delta_retained"]
    sites = {s["site"]: s for s in doc["by_site"]}
    listing = [(s["site"], s["delta_retained_bytes"]) for s in doc["by_site"]]

    # Largest growth first, and it is the list.
    top = doc["by_site"][0]
    assert top["site"] == EVENTS, listing
    assert top["type"] == "builtins.list"
    assert added * RETAINED_LO <= top["delta_retained_bytes"] <= added * RETAINED_HI, (
        top,
        added,
    )
    # Each event is three new objects: the Event, its seq int, its detail bytes.
    assert top["delta_retained_objects"] == 3 * grown["added_events"], top
    assert top["after_retained_bytes"] > top["before_retained_bytes"] > 0

    # The items under it are summed into one generalised site.
    items = sites.get(f"{EVENTS}[<index>]")
    assert items is not None, listing
    assert items["type"] == "__main__.Event"

    # Nothing grew under the noise list, and the module dict that only
    # restates EVENTS is not listed.
    assert not any(s.startswith(f"{MAIN}['COUNTERS']") for s in sites), listing
    assert MAIN not in sites, listing

    types = {t["type"]: t for t in doc["by_type"]}
    assert types["__main__.Event"]["delta_count"] == grown["added_events"]
    # Every new event's detail bytes is found under the list. (The heap-wide
    # bytes count is not exact: the interpreter can free a bytes object of
    # its own between the two dumps.)
    detail = sites.get(f"{EVENTS}[<index>].detail")
    assert detail is not None, listing
    assert detail["type"] == "builtins.bytes"
    assert detail["delta_retained_objects"] == grown["added_events"], detail
    delta = doc["totals"]["delta_reachable_bytes"]
    assert added * RETAINED_LO <= delta <= added * RETAINED_HI * 1.05, (delta, added)
