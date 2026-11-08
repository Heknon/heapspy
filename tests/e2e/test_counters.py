"""``heapspy watch --counters`` against the growing-list victim.

Counters are read while the victim runs (nothing is stopped). The victim is
sampled, asked to append ``GROW_BY`` events, and sampled again: the bytes in
pymalloc's blocks must grow by about what the victim measured, since every
part of an event (the ``Event``, its ``int``, its 400-byte ``bytes``) is a
small object.
"""

from __future__ import annotations

import json

from harness import IS_LINUX, is_crash


def counters(heapspy, victim, rounds: int = 3) -> list[dict]:
    r = heapspy.run(
        "watch",
        "--pid",
        str(victim.pid),
        "--counters",
        "--every",
        "200ms",
        "--rounds",
        str(rounds),
        "--json",
        step="watch --counters",
    )
    assert not is_crash(r), r.describe()
    assert r.returncode == 0, r.describe()
    docs = [json.loads(line) for line in r.stdout.splitlines()]
    assert [d["kind"] for d in docs] == ["sample"] * rounds + ["watch_counters_summary"], docs
    return docs


def test_counters_follow_growth(heapspy, start_victim, python) -> None:
    victim = start_victim(python, "growing_list.py")
    before = counters(heapspy, victim)
    grown = victim.trigger(1)
    after = counters(heapspy, victim)
    victim.kill()

    for s in before[:-1] + after[:-1]:
        assert s["approximate"] is True
        assert s["os"]["rss_bytes"] > 0, s
        py = s["python"]
        assert py["interpreters"] == 1 and py["threads"] >= 1, py
        gens = py["gc"]["generations"]
        assert len(gens) == 3 and all(g["threshold"] >= 0 for g in gens), gens
        a = py["allocator"]
        assert a["skipped_pools"] == 0, a
        assert a["arena_bytes"] >= a["block_bytes"] > 0, a
        assert sum(c["blocks"] for c in a["size_classes"]) == a["blocks"], a
        if IS_LINUX:
            assert s["native"]["heap_bytes"] > 0, s

    def block_bytes(docs: list[dict]) -> int:
        return docs[-2]["python"]["allocator"]["block_bytes"]

    added = grown["delta_retained"]
    delta = block_bytes(after) - block_bytes(before)
    assert 0.5 * added <= delta <= 2.0 * added, (delta, added)

    summary = after[-1]
    assert summary["samples"] == 3
    assert summary["python_bytes"]["last"] == block_bytes(after)


def test_agent_writes_a_memory_profile(heapspy, start_victim, tmp_path, python) -> None:
    victim = start_victim(python, "growing_list.py")
    out = tmp_path / "profiles"
    r = heapspy.run(
        "agent",
        "--dry-run",
        str(out),
        "--pid",
        str(victim.pid),
        "--tag",
        "env=e2e",
        "--once",
        step="agent --once",
    )
    victim.kill()
    assert not is_crash(r), r.describe()
    assert r.returncode == 0, r.describe()
    assert "sent 1 profiles" in r.stderr, r.describe()
    labels = json.loads((out / f"000001-{victim.pid}-memory.json").read_text())
    assert labels["__name__"] == "heapspy_memory"
    assert labels["service_name"] == "growing_list"
    assert labels["pid"] == str(victim.pid) and labels["env"] == "e2e"
    pprof = (out / f"000001-{victim.pid}-memory.pprof").read_bytes()
    for text in (b"resident", b"python objects (pymalloc)", b"pymalloc free"):
        assert text in pprof, text
