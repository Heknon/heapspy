"""Performance budget: dump and analyze a heap of about two million objects.

The budget is generous (it is meant to catch accidental quadratic behaviour,
not to benchmark) and can be changed with ``HEAPSPY_E2E_PERF_BUDGET``
(seconds, default 120) for slow machines. Timings are printed in the
"heapspy timings" section of the pytest summary.
"""

from __future__ import annotations

import os
import time

from expectations import MAIN, RETAINED_HI, RETAINED_LO
from harness import acquire, record, render_path

BUDGET = float(os.environ.get("HEAPSPY_E2E_PERF_BUDGET", "120"))


def test_two_million_objects(heapspy, start_victim, tmp_path, python, method) -> None:
    victim = start_victim(python, "many_objects.py")
    info = victim.info

    start = time.monotonic()
    snap = acquire(heapspy, method, victim, tmp_path)
    victim.kill()
    report = heapspy.analyze(snap)
    total = time.monotonic() - start
    record("acquire+analyze", total)

    objects = report["totals"]["objects"]
    assert objects >= info["approx_objects"], objects
    assert objects >= 2_000_000, objects
    assert report["snapshot"]["truncated"] is False

    top = report["top_retainers"][0]
    assert render_path(top["path"]) == f"{MAIN}['RECORDS']"
    expected = info["expected_retained"]
    assert expected * RETAINED_LO <= top["retained_bytes"] <= expected * RETAINED_HI, (
        top["retained_bytes"],
        expected,
    )
    print(f"\n{objects} objects, snapshot {snap.stat().st_size} bytes, {total:.1f} s")
    assert total < BUDGET, f"dump + analyze took {total:.1f} s, budget {BUDGET:g} s"
