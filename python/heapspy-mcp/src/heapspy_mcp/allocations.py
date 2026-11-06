"""Bounded summaries of heapspy allocation data (``.hpya`` profiles).

Two sources:

- ``analyze SNAP --allocations FILE --json``: the ``allocations`` block
  (recording header, coverage, ``top_stacks``) and ``allocated_at`` on each
  top retainer; ``query --type ... --allocations`` fills ``allocated_at`` on
  instances. See docs/json-schema.md, "Allocations".
- ``flamegraph --allocations FILE --folded``: the only output heapspy has for
  a profile without a snapshot. It gives estimated bytes per stack and
  nothing else (no sample counts, event kinds or recording header).

Frames are innermost first everywhere in the output, as in the JSON report.
"""

from __future__ import annotations

import re
from typing import Any

from .summarize import MAX_NAME, clip, notes, with_human

MAX_FRAMES = 6
MAX_STACK_HINTS = 3
MAX_ALLOCATED_AT_STACKS = 3
MAX_SUMMARY_STACKS = 5
MAX_FOLDED_LINES = 100_000
MAX_LOCATION = 160

CAVEATS = (
    "Sampled, not complete: only arena, pool and large-object events made while recording "
    "are sampled. Blocks reused from freed memory, and objects allocated before recording "
    "started, have no stack.",
    "Arena and pool links are approximate: they name the most recent growth event that "
    "created the memory, not necessarily the call that allocated the object. "
    "exact_linked_bytes counts links through large-object samples, which are exact.",
    "estimated_bytes is the sum of sample weights over the recording window: an estimate "
    "of bytes allocated through sampled events, not of bytes still alive. linked_bytes is "
    "what is still alive in the snapshot.",
)

_IDENT_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*\.py$")
_FOLDED_FRAME_RE = re.compile(r"^(?P<function>.*) \((?P<location>[^()]*)\)$")


# -- frames and hints ----------------------------------------------------------------


def _module_guess(file: str) -> str | None:
    """``app/session.py`` -> ``app.session`` for a relative path of identifiers."""
    path = file.replace("\\", "/").removeprefix("./")
    if not _IDENT_PATH_RE.match(path):
        return None
    module = path.removesuffix(".py").replace("/", ".")
    return module.removesuffix(".__init__") or None


def qualname_guess(function: str | None, file: str | None) -> str | None:
    """A ``module.qualname`` for ``map_to_source`` from a frame, when one can be guessed.

    Only for relative ``co_filename`` values made of identifiers; the module
    is then the path. For an absolute filename the repository root is not
    known, so there is no guess: read the file at the line instead.
    """
    if not isinstance(file, str) or not isinstance(function, str):
        return None
    module = _module_guess(file)
    if module is None:
        return None
    if function == "<module>":
        return module
    parts = function.split(".")
    if not all(p.isidentifier() or p == "<locals>" for p in parts) or parts[0] == "<locals>":
        return None
    return f"{module}.{function}"


def clip_left(text: Any, limit: int = MAX_LOCATION) -> Any:
    """Clip a path from the left: the file name and line are the useful end."""
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return "..." + text[-(limit - 3) :]


def _frame(frame: dict[str, Any]) -> dict[str, Any]:
    line = frame.get("line")
    approximate = frame.get("approximate")
    return {
        "function": clip(frame.get("function"), MAX_NAME),
        "file": clip_left(frame.get("file")),
        "line": line if isinstance(line, int) else None,
        "location": clip_left(frame.get("location")),
        # None in folded output, which does not carry the flag.
        "approximate": approximate if isinstance(approximate, bool) else None,
    }


def stack_source_hints(frames: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Where to look, innermost frame first: ``file:line`` and a qualname guess.

    The first hint is the allocating function itself; the next ones are its
    callers, which are often where the decision to keep the object is made.
    """
    hints: list[dict[str, Any]] = []
    for f in frames:
        if len(hints) >= MAX_STACK_HINTS:
            break
        file, line = f.get("file"), f.get("line")
        if not isinstance(file, str) or not file or file.startswith("<"):
            continue
        hints.append(
            {
                "location": f.get("location") or f"{file}:{line if line is not None else '?'}",
                "file": file,
                "line": line,
                "function": f.get("function"),
                "qualname_guess": qualname_guess(f.get("function"), file),
            }
        )
    return hints


def _frames(raw: Any) -> tuple[list[dict[str, Any]], int]:
    frames = [f for f in raw or [] if isinstance(f, dict)]
    return [_frame(f) for f in frames[:MAX_FRAMES]], len(frames)


def _stack_common(frames_raw: Any) -> dict[str, Any]:
    frames, total = _frames(frames_raw)
    out: dict[str, Any] = {
        "allocated_in": frames[0]["location"] if frames else None,
        "frames": frames,
        "frames_total": total,
        "source_hints": stack_source_hints(frames),
    }
    return out


# -- analyze / query reports ---------------------------------------------------------


def summarize_top_stack(stack: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "rank": stack.get("rank"),
        "estimated_bytes": stack.get("estimated_bytes"),
        "samples": stack.get("samples"),
        "events": list(stack.get("events") or [])[:8],
        "linked_bytes": stack.get("linked_bytes"),
        "exact_linked_bytes": stack.get("exact_linked_bytes"),
        "approximate": stack.get("approximate"),
        **_stack_common(stack.get("frames")),
    }
    return with_human(item, "estimated_bytes", "linked_bytes", "exact_linked_bytes")


def summarize_allocated_at(
    at: dict[str, Any] | None, max_stacks: int = MAX_ALLOCATED_AT_STACKS
) -> dict[str, Any] | None:
    """``allocated_at`` of a retainer or instance, with at most ``max_stacks`` stacks."""
    if not isinstance(at, dict):
        return None
    raw = [s for s in at.get("stacks") or [] if isinstance(s, dict)]
    stacks = []
    for s in raw[:max_stacks]:
        item = {
            "linked_objects": s.get("linked_objects"),
            "linked_bytes": s.get("linked_bytes"),
            "exact_linked_bytes": s.get("exact_linked_bytes"),
            "top_stack_rank": s.get("top_stack_rank"),
            **_stack_common(s.get("frames")),
        }
        stacks.append(with_human(item, "linked_bytes"))
    out = {
        "linked_objects": at.get("linked_objects"),
        "linked_bytes": at.get("linked_bytes"),
        "exact_linked_bytes": at.get("exact_linked_bytes"),
        "approximate": at.get("approximate"),
        "stacks": stacks,
        "stacks_total": len(raw),
    }
    return with_human(out, "linked_bytes", "exact_linked_bytes")


def allocation_notes(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """The notes about the profile (``allocations_*`` codes)."""
    return [
        n
        for n in notes(items)
        if isinstance(n.get("code"), str) and n["code"].startswith("allocations_")
    ]


def _not_linked_warning(note_list: list[dict[str, Any]]) -> str | None:
    if any(n.get("code") == "allocations_not_linked" for n in note_list):
        return (
            "No object was linked to a sample: the profile does not match the snapshot (see "
            "the allocations_* notes: another pid, another CPython version, or a snapshot "
            "taken before recording started). top_stacks still shows estimated bytes, but "
            "linked_bytes is 0 everywhere."
        )
    return None


def summarize_allocations(
    block: dict[str, Any] | None, doc_notes: list[dict[str, Any]] | None, top: int
) -> dict[str, Any] | None:
    """The ``allocations`` block of an analyze report, bounded to ``top`` stacks."""
    if not isinstance(block, dict):
        return None
    sampling = block.get("sampling") if isinstance(block.get("sampling"), dict) else {}
    overhead = block.get("overhead") if isinstance(block.get("overhead"), dict) else {}
    coverage = dict(block.get("coverage") or {})
    with_human(coverage, "linked_bytes", "exact_linked_bytes")
    recording = {
        "path": clip_left(block.get("path"), 400),
        "pid": block.get("pid"),
        "python_version": block.get("python_version"),
        "started_at": block.get("started_at"),
        "duration_ms": block.get("duration_ms"),
        "mechanisms": list(block.get("mechanisms") or [])[:8],
        "sampling": {
            "events": list(sampling.get("events") or [])[:8],
            "byte_interval": sampling.get("byte_interval"),
            "max_frames": sampling.get("max_frames"),
        },
        "overhead": {
            k: overhead.get(k)
            for k in ("samples_taken", "samples_dropped", "probe_hits", "total_pause_ns")
        },
        "truncated": block.get("truncated"),
        "approximate": block.get("approximate"),
        "samples": block.get("samples"),
        "estimated_bytes": block.get("estimated_bytes"),
    }
    with_human(recording, "estimated_bytes")
    stacks = [s for s in block.get("top_stacks") or [] if isinstance(s, dict)]
    note_list = allocation_notes(doc_notes)
    out: dict[str, Any] = {
        "recording": recording,
        "coverage": coverage,
        "top_stacks": [summarize_top_stack(s) for s in stacks[:top]],
        "top_stacks_listed": len(stacks),
        "notes": note_list,
        "caveats": list(CAVEATS),
    }
    warning = _not_linked_warning(note_list)
    if warning:
        out["warning"] = warning
    return out


def add_to_analyze(summary: dict[str, Any], doc: dict[str, Any], top: int) -> dict[str, Any]:
    """Add the allocation join of an analyze report to its summary (in place)."""
    block = doc.get("allocations")
    if not isinstance(block, dict):
        return summary
    raw = [r for r in doc.get("top_retainers") or [] if isinstance(r, dict)]
    for item, r in zip(summary.get("top_retainers") or [], raw, strict=False):
        item["allocated_at"] = summarize_allocated_at(r.get("allocated_at"))
    summary["allocations"] = summarize_allocations(
        block, doc.get("notes"), min(top, MAX_SUMMARY_STACKS)
    )
    return summary


def add_to_type_query(summary: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    """Add ``allocated_at`` of each instance of a ``query --type --allocations`` report."""
    raw = [i for i in doc.get("top_instances") or [] if isinstance(i, dict)]
    for item, inst in zip(summary.get("top_instances") or [], raw, strict=False):
        item["allocated_at"] = summarize_allocated_at(inst.get("allocated_at"))
    note_list = allocation_notes(doc.get("notes"))
    out: dict[str, Any] = {"notes": note_list, "caveats": list(CAVEATS)}
    warning = _not_linked_warning(note_list)
    if warning:
        out["warning"] = warning
    summary["allocations"] = out
    return summary


# -- profile only: folded stacks -----------------------------------------------------


def _parse_folded_frame(text: str) -> dict[str, Any]:
    m = _FOLDED_FRAME_RE.match(text)
    if not m:
        # "[no Python stack]" and anything unexpected.
        return {"function": text, "file": None, "line": None, "location": None}
    function, location = m.group("function"), m.group("location")
    file: str | None = None
    line: int | None = None
    if location != "<unknown>":
        head, sep, tail = location.rpartition(":")
        if sep and (tail.isdigit() or tail == "?"):
            file = head
            line = int(tail) if tail.isdigit() else None
        else:
            file = location
    return {"function": function, "file": file, "line": line, "location": location}


def parse_folded(text: str) -> list[tuple[list[dict[str, Any]], int]]:
    """``outer;...;inner bytes`` lines as (frames innermost first, bytes)."""
    out: list[tuple[list[dict[str, Any]], int]] = []
    for raw in text.splitlines()[:MAX_FOLDED_LINES]:
        line = raw.rstrip()
        stack, sep, weight = line.rpartition(" ")
        if not sep or not weight.isdigit() or not stack:
            continue
        frames = [_parse_folded_frame(f) for f in stack.split(";")]
        frames.reverse()
        out.append((frames, int(weight)))
    return out


def summarize_folded(text: str, top: int) -> dict[str, Any]:
    """Top stacks of a profile from its folded stacks, merged by identical frames."""
    merged: dict[tuple[tuple[Any, ...], ...], int] = {}
    order: dict[tuple[tuple[Any, ...], ...], list[dict[str, Any]]] = {}
    for frames, weight in parse_folded(text):
        key = tuple((f["function"], f["location"]) for f in frames)
        merged[key] = merged.get(key, 0) + weight
        order.setdefault(key, frames)
    ranked = sorted(merged.items(), key=lambda kv: -kv[1])
    total = sum(merged.values())
    stacks = []
    for rank, (key, weight) in enumerate(ranked[:top], start=1):
        frames = [{**f, "approximate": None} for f in order[key]]
        item: dict[str, Any] = {
            "rank": rank,
            "estimated_bytes": weight,
            "estimated_pct": round(weight / total * 100, 2) if total else None,
            # Not in folded output; available with a snapshot.
            "samples": None,
            "events": None,
            "linked_bytes": None,
            "exact_linked_bytes": None,
            **_stack_common(frames),
        }
        stacks.append(with_human(item, "estimated_bytes"))
    out = {
        "estimated_bytes": total,
        "stacks_total": len(merged),
        "top_stacks": stacks,
    }
    return with_human(out, "estimated_bytes")
