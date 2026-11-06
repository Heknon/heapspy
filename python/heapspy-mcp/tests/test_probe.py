"""cache_sensitivity_probe gating and output parsing (the live run is in
test_contention_live.py)."""

from __future__ import annotations

import pytest

from heapspy_mcp.system import probe


def test_probe_output_parsing() -> None:
    x = probe._parse("1000000 0.5 1.0 500000000 400000000 5000 1")
    v = probe._phase_view(x)
    assert v["ns_per_access"] == 500.0 and v["avg_timeslice_us"] == 100.0
    assert v["cpu_share_of_wall"] == 0.5 and v["timeslices_per_s"] == 5000.0
    with pytest.raises(probe.ProbeError):
        probe._parse("garbage")


def test_default_sizes_from_cache_topology() -> None:
    topo = [
        {"level": 1, "type": "Data", "size_bytes": 48 * 1024},
        {"level": 1, "type": "Instruction", "size_bytes": 64 * 1024},
        {"level": 2, "type": "Unified", "size_bytes": 2 * 1024 * 1024},
        {"level": 3, "type": "Unified", "size_bytes": 32 * 1024 * 1024},
    ]
    sizes, basis = probe.default_sizes(topo)
    assert sizes == [16384, 1048576, 1572864, 8388608, 64 * 1024 * 1024]
    assert "L2" in basis
    # An L3 too large to double within the cap is left out.
    topo[3]["size_bytes"] = 512 * 1024 * 1024
    assert probe.default_sizes(topo)[0] == [16384, 1048576, 1572864, 8388608]
    assert probe.default_sizes([])[0] == list(probe.FALLBACK_SIZES)
