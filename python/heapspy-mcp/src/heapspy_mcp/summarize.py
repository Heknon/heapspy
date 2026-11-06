"""Turn heapspy JSON reports into bounded, compact summaries for a model.

Every list is capped, every string that can carry memory contents (edge
labels, root labels) is clipped, and long retaining paths are elided in the
middle. Nothing here returns the raw graph.
"""

from __future__ import annotations

import re
from typing import Any

MAX_TOP = 50
MAX_PATHS = 10
MAX_TARGETS = 10
MAX_HOPS = 24
HEAD_HOPS = 4
MAX_LABEL = 160
MAX_NAME = 200
MAX_NOTES = 20
MAX_MATCHED_TYPES = 20
MAX_SOURCE_HINTS = 5

_DICT_KEY_RE = re.compile(r"^\['([A-Za-z_][A-Za-z0-9_]*)'\]$")
_ATTR_RE = re.compile(r"^\.([A-Za-z_][A-Za-z0-9_]*)$")
_MODULE_ROOT_RE = re.compile(r"^sys\.modules\['([A-Za-z_][A-Za-z0-9_.]*)'\]$")


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def clip(text: Any, limit: int = MAX_LABEL) -> Any:
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def human_bytes(n: int | None) -> str | None:
    if n is None:
        return None
    value = float(n)
    sign = "-" if value < 0 else ""
    value = abs(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{sign}{value:.0f} {unit}" if unit == "B" else f"{sign}{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _joins_with_space(edge: str) -> bool:
    return bool(edge) and (edge[0].isalpha() or edge[0] == "<")


def _hop_start(hop: dict[str, Any]) -> str:
    label = hop.get("root_label")
    if isinstance(label, str) and label:
        return clip(label)
    return f"<{clip(hop.get('type'), MAX_NAME)} at {hop.get('address')}>"


def render_path(hops: list[dict[str, Any]] | None) -> str | None:
    """Render a root-first path the way the schema describes the diff ``site`` key."""
    if not hops:
        return None
    parts = [_hop_start(hops[0])]
    rest = hops[1:]
    if len(hops) > MAX_HOPS:
        keep_tail = MAX_HOPS - HEAD_HOPS
        elided = len(hops) - HEAD_HOPS - keep_tail
        rest = [*hops[1:HEAD_HOPS], None, *hops[-keep_tail:]]
    for hop in rest:
        if hop is None:
            parts.append(f" ...{elided} hops... ")
            continue
        edge = clip(hop.get("edge") or "<?>")
        parts.append(f" {edge}" if _joins_with_space(edge) else edge)
    return "".join(parts)


def compact_hops(hops: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Hops with clipped labels; the middle of a long path becomes one marker."""
    if not hops:
        return []

    def one(i: int, hop: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {
            "address": hop.get("address"),
            "type": clip(hop.get("type"), MAX_NAME),
            "shallow_bytes": hop.get("shallow_bytes"),
            "edge": clip(hop.get("edge")),
        }
        if i == 0:
            out["root_label"] = clip(hop.get("root_label"))
            out["root_kind"] = hop.get("root_kind")
        loc = compact_location(hop.get("source_loc"))
        if loc is not None:
            out["source_loc"] = loc
        return out

    if len(hops) <= MAX_HOPS:
        return [one(i, h) for i, h in enumerate(hops)]
    keep_tail = MAX_HOPS - HEAD_HOPS
    elided = len(hops) - HEAD_HOPS - keep_tail
    head = [one(i, h) for i, h in enumerate(hops[:HEAD_HOPS])]
    tail = [one(len(hops) - keep_tail + i, h) for i, h in enumerate(hops[-keep_tail:])]
    return [*head, {"elided_hops": elided}, *tail]


def compact_location(loc: Any) -> dict[str, Any] | None:
    """A SourceLocation from a report, clipped, with a ``location`` string.

    ``location`` is ``file:line``, ``file:~line`` when the line is derived
    (a class located through its methods; the class statement is at or
    before it), or ``file`` alone for a module.
    """
    if not isinstance(loc, dict) or not isinstance(loc.get("file"), str):
        return None
    file = clip(loc["file"], 400)
    line = loc.get("line") if isinstance(loc.get("line"), int) else None
    exact = bool(loc.get("exact"))
    suffix = "" if line is None else f":{line}" if exact else f":~{line}"
    text = f"{file}{suffix}"
    return {
        "location": text,
        "file": file,
        "line": line,
        "exact": exact,
        "via": clip(loc.get("via"), 40),
    }


def with_location(item: dict[str, Any], src: dict[str, Any], key: str) -> dict[str, Any]:
    """Copy ``key`` (``type_location`` or ``source_loc``) and its reason from a
    report entry, compacted. Nothing is added when the report has no such
    field (a heapspy from before source locations)."""
    if key in src:
        item[key] = compact_location(src.get(key))
        item[f"{key}_reason"] = clip(src.get(f"{key}_reason"), 60)
    return item


def source_locations(
    hops: list[dict[str, Any]] | None,
    type_location: Any = None,
    type_name: Any = None,
) -> list[dict[str, Any]]:
    """Locations recorded in the snapshot for a path: the target's type first,
    then each located hop (functions, classes, code objects, modules), from
    the target back to the root. Each entry can be read directly, or its
    ``name`` passed to ``map_to_source`` with the snapshot for an excerpt."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(entry: dict[str, Any] | None, **extra: Any) -> None:
        if entry is None or entry["location"] in seen or len(out) >= MAX_SOURCE_HINTS:
            return
        seen.add(entry["location"])
        out.append({**extra, **entry})

    if isinstance(type_name, str):
        add(compact_location(type_location), of="type", name=clip(type_name, MAX_NAME))
    for hop in reversed(hops or []):
        add(
            compact_location(hop.get("source_loc")),
            of="hop",
            type=clip(hop.get("type"), MAX_NAME),
            address=hop.get("address"),
            edge=clip(hop.get("edge")),
        )
    return out


def source_hints(hops: list[dict[str, Any]] | None) -> list[str]:
    """``module.qualname`` names along a path that ``map_to_source`` can resolve.

    - A module root followed by ``.__dict__['NAME']`` gives ``module.NAME``
      (repeated for class attributes: ``module.Class.attr``).
    - A non-builtin type followed by ``.attr`` or ``.__dict__['attr']`` gives
      ``Type.attr``; the type name itself is also a hint.
    """
    if not hops:
        return []
    hints: list[str] = []

    def add(name: str) -> None:
        if name not in hints:
            hints.append(name)

    root = _MODULE_ROOT_RE.match(hops[0].get("root_label") or "")
    if root:
        qual = [root.group(1)]
        i = 1
        while i + 1 < len(hops) and hops[i].get("edge") == ".__dict__":
            key = _DICT_KEY_RE.match(hops[i + 1].get("edge") or "")
            if not key:
                break
            qual.append(key.group(1))
            i += 2
        if len(qual) > 1:
            add(".".join(qual))

    for i, hop in enumerate(hops):
        type_name = hop.get("type")
        if not isinstance(type_name, str) or "." not in type_name:
            continue
        if type_name.startswith("builtins."):
            continue
        nxt = hops[i + 1].get("edge") if i + 1 < len(hops) else None
        attr = _ATTR_RE.match(nxt or "")
        if attr and attr.group(1) != "__dict__":
            add(f"{type_name}.{attr.group(1)}")
        elif nxt == ".__dict__" and i + 2 < len(hops):
            key = _DICT_KEY_RE.match(hops[i + 2].get("edge") or "")
            if key:
                add(f"{type_name}.{key.group(1)}")
        add(type_name)
    return hints[:MAX_SOURCE_HINTS]


def path_summary(
    hops: list[dict[str, Any]] | None,
    *,
    with_hops: bool,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``target`` is the report entry the path belongs to; its ``type`` and
    ``type_location`` lead ``source_locations``."""
    out: dict[str, Any] = {
        "rendered": render_path(hops),
        "length": len(hops or []),
        "root_kind": (hops or [{}])[0].get("root_kind") if hops else None,
        "source_hints": source_hints(hops),
    }
    # Only from a heapspy whose reports have locations.
    if any("source_loc" in h for h in hops or []) or (target and "type_location" in target):
        t = target or {}
        out["source_locations"] = source_locations(hops, t.get("type_location"), t.get("type"))
    if hops and len(hops) >= 2:
        holder = hops[-2]
        out["direct_holder"] = {
            "type": clip(holder.get("type"), MAX_NAME),
            "address": holder.get("address"),
            "edge": clip(hops[-1].get("edge")),
        }
    if with_hops:
        out["hops"] = compact_hops(hops)
    return out


def snapshot_summary(snap: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(snap, dict):
        return None
    source = snap.get("source") if isinstance(snap.get("source"), dict) else {}
    return {
        "path": clip(snap.get("path"), 400),
        "python_version": snap.get("python_version"),
        "os": snap.get("os"),
        "arch": snap.get("arch"),
        "captured_at": snap.get("captured_at"),
        "source": {"kind": source.get("kind"), "ref": clip(source.get("ref"), 400)},
        "contents_captured": snap.get("contents_captured"),
        "truncated": snap.get("truncated"),
    }


def notes(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for note in (items or [])[:MAX_NOTES]:
        if isinstance(note, dict):
            out.append({"code": note.get("code"), "message": clip(note.get("message"), 500)})
    return out


def with_human(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    """Add ``<key>_human`` next to each byte count."""
    for key in keys:
        if key in d and isinstance(d[key], int):
            d[key.removesuffix("_bytes") + "_human"] = human_bytes(d[key])
    return d


# -- per-report summaries ---------------------------------------------------------


def summarize_analyze(doc: dict[str, Any], top: int) -> dict[str, Any]:
    retainers = []
    for r in (doc.get("top_retainers") or [])[:top]:
        item = {
            "rank": r.get("rank"),
            "address": r.get("address"),
            "type": clip(r.get("type"), MAX_NAME),
            "retained_bytes": r.get("retained_bytes"),
            "retained_pct": r.get("retained_pct"),
            "retained_objects": r.get("retained_objects"),
            "shallow_bytes": r.get("shallow_bytes"),
            "path": path_summary(r.get("path"), with_hops=False, target=r),
        }
        with_location(item, r, "type_location")
        retainers.append(with_human(item, "retained_bytes"))
    histogram = []
    for row in (doc.get("type_histogram") or [])[:top]:
        item = {
            "type": clip(row.get("type"), MAX_NAME),
            "count": row.get("count"),
            "shallow_bytes": row.get("shallow_bytes"),
            "retained_bytes": row.get("retained_bytes"),
        }
        with_location(item, row, "type_location")
        histogram.append(with_human(item, "retained_bytes"))
    memory = dict(doc.get("memory") or {})
    with_human(memory, "rss_bytes", "graph_bytes", "outside_graph_bytes")
    totals = dict(doc.get("totals") or {})
    with_human(totals, "reachable_bytes", "unreachable_bytes")
    return {
        "snapshot": snapshot_summary(doc.get("snapshot")),
        "totals": totals,
        "memory": memory,
        "top_retainers": retainers,
        "type_histogram": histogram,
        "notes": notes(doc.get("notes")),
    }


def summarize_type_query(doc: dict[str, Any], top: int) -> dict[str, Any]:
    matched = doc.get("matched_types") or []
    type_locs = [t for t in doc.get("matched_type_locations") or [] if isinstance(t, dict)]
    by_type = {t.get("type"): t for t in type_locs}
    instances = []
    for inst in (doc.get("top_instances") or [])[:top]:
        # The instance's type location, for its path's source_locations.
        target = {"type": inst.get("type"), **by_type.get(inst.get("type"), {})}
        item = {
            "address": inst.get("address"),
            "type": clip(inst.get("type"), MAX_NAME),
            "shallow_bytes": inst.get("shallow_bytes"),
            "retained_bytes": inst.get("retained_bytes"),
            "length": inst.get("length"),
            "path": path_summary(inst.get("path"), with_hops=False, target=target)
            if inst.get("path") is not None
            else None,
        }
        if inst.get("source_loc") is not None:
            item["source_loc"] = compact_location(inst.get("source_loc"))
        instances.append(with_human(item, "retained_bytes"))
    holders = [
        {
            "type": clip(h.get("type"), MAX_NAME),
            "edge": clip(h.get("edge")),
            "count": h.get("count"),
        }
        for h in (doc.get("holders") or [])[:top]
    ]
    out = {
        "snapshot": snapshot_summary(doc.get("snapshot")),
        "query": clip(doc.get("query"), MAX_NAME),
        "matched_types": [clip(t, MAX_NAME) for t in matched[:MAX_MATCHED_TYPES]],
        "matched_types_total": len(matched),
        "instances": doc.get("instances"),
        "shallow_bytes": doc.get("shallow_bytes"),
        "retained_bytes": doc.get("retained_bytes"),
        "top_instances": instances,
        "holders": holders,
        "notes": notes(doc.get("notes")),
    }
    if "matched_type_locations" in doc:
        out["type_locations"] = [
            with_location({"type": clip(t.get("type"), MAX_NAME)}, t, "type_location")
            for t in type_locs[:MAX_MATCHED_TYPES]
        ]
    return with_human(out, "shallow_bytes", "retained_bytes")


def summarize_target(target: dict[str, Any], max_paths: int) -> dict[str, Any]:
    paths = target.get("paths") or []
    item = {
        "address": target.get("address"),
        "type": clip(target.get("type"), MAX_NAME),
        "shallow_bytes": target.get("shallow_bytes"),
        "retained_bytes": target.get("retained_bytes"),
        "reachable": target.get("reachable"),
        "paths": [path_summary(p, with_hops=True, target=target) for p in paths[:max_paths]],
        "paths_total": len(paths),
    }
    with_location(item, target, "type_location")
    return with_human(item, "retained_bytes")


def summarize_diff(doc: dict[str, Any], top: int) -> dict[str, Any]:
    note_list = notes(doc.get("notes"))
    identity_note = next(
        (n["message"] for n in note_list if n.get("code") == "identity_approximate"),
        "Objects are matched by type and retaining site, not by address. "
        "Per-object growth is approximate.",
    )
    totals = dict(doc.get("totals") or {})
    with_human(totals, "delta_shallow_bytes", "delta_reachable_bytes")
    by_type = []
    for row in (doc.get("by_type") or [])[:top]:
        item = {k: row.get(k) for k in ("before_count", "after_count", "delta_count")}
        item = {"type": clip(row.get("type"), MAX_NAME), **item}
        item["delta_bytes"] = row.get("delta_bytes")
        item["after_bytes"] = row.get("after_bytes")
        by_type.append(with_human(item, "delta_bytes"))
    by_site = []
    for row in (doc.get("by_site") or [])[:top]:
        item = {
            "site": clip(row.get("site"), 400),
            "type": clip(row.get("type"), MAX_NAME),
            "before_retained_bytes": row.get("before_retained_bytes"),
            "after_retained_bytes": row.get("after_retained_bytes"),
            "delta_retained_bytes": row.get("delta_retained_bytes"),
            "delta_retained_objects": row.get("delta_retained_objects"),
        }
        by_site.append(with_human(item, "delta_retained_bytes"))
    return {
        # Not optional: a model must not read address-level identity into a diff.
        "identity_approximate": bool(doc.get("identity_approximate", True)),
        "identity_note": identity_note,
        "before": snapshot_summary(doc.get("before")),
        "after": snapshot_summary(doc.get("after")),
        "totals": totals,
        "by_type": by_type,
        "by_type_total": len(doc.get("by_type") or []),
        "by_site": by_site,
        "by_site_total": len(doc.get("by_site") or []),
        "notes": note_list,
    }
