#!/usr/bin/env python3
"""Investigate a live process's memory in rounds, asking each round what is
still unclear and getting the information that would make it clearer.

    python3 scripts/investigate.py --pid 1234 [--heapspy target/release/heapspy]

Each round:

1. Take a snapshot (`heapspy dump`), analyze it, and diff it against the
   previous round's.
2. Diagnose every suspect: what holds it, how big it is, how fast it grows,
   what the growth is made of, and where the code involved is.
3. Ask, for each suspect, what is still unclear, and pick for each question
   the action that answers it: another snapshot to measure growth, a
   snapshot with contents captured (module files, key names), a source
   lookup (done at once).
4. Stop when no open question has an action left. What heapspy cannot
   answer is reported as such, so it can be fixed in heapspy.

The report is printed after every round and written to the output
directory as `report.md` and `report.json`. Needs Python 3.11 or later and
the same rights `heapspy dump` needs.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# A suspect is a top retainer holding at least this share of what the
# process holds, or this many bytes.
MIN_PCT = 1.0
MIN_BYTES = 1 << 20
# Growth below this many bytes per second is noise, not a trend.
RATE_FLOOR = 4 << 10
# Rounds of growth that make a leak, not a blip.
CONFIRM_ROUNDS = 2
# Types whose source is the interpreter's, not the program's.
BUILTIN_MODULES = {"builtins", "native"}
# A site a person would fix: a module global, or a running function's local.
HOLDER = re.compile(
    r"sys\.modules\['[^']+'\]\.__dict__\['[^']+'\]|frame \S+ local '[^']+'"
)


def mib(n: float) -> str:
    return f"{n / (1 << 20):.1f} MiB"


def rate(n: float) -> str:
    return (
        f"{n / (1 << 20):+.2f} MiB/s" if abs(n) >= 1 << 16 else f"{n / 1024:+.1f} KiB/s"
    )


@dataclass
class Question:
    """Something still unclear about a suspect, and how to clear it up."""

    key: str
    text: str
    # What answers it: "snapshot" (another dump, for growth), "contents" (a
    # dump with --capture-contents), or None when nothing heapspy offers
    # answers it.
    action: str | None
    why_not: str | None = None


@dataclass
class Suspect:
    site: str
    type: str
    retained: int
    path: list[dict[str, Any]]
    # Bytes per second between consecutive rounds.
    rates: list[float] = field(default_factory=list)
    # What grew under the holder, as a path suffix with the most growth.
    made_of: str | None = None
    made_of_rate: float | None = None
    # The type the growth itself is, at the bottom of `made_of`.
    grows_type: str | None = None
    # Source locations found, by name, and facts that answer a question.
    locations: dict[str, str] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """Judged on the latest rounds: what a holder did while the program
        warmed up (a bounded cache filling) is not what it does now."""
        if not self.rates:
            return "unknown: one snapshot so far"
        recent = self.rates[-CONFIRM_ROUNDS:]
        grew = [r for r in recent if r > RATE_FLOOR]
        if len(recent) == CONFIRM_ROUNDS and len(grew) == len(recent):
            return "leak: grows every round"
        if len(recent) == CONFIRM_ROUNDS and not grew:
            if any(r > RATE_FLOOR for r in self.rates):
                return "flat now (grew earlier: warm-up)"
            return "large but flat"
        return "unsettled: grew in some rounds"


def render_path(path: list[dict[str, Any]]) -> str:
    out = ""
    for i, hop in enumerate(path):
        if i == 0:
            out = hop.get("root_label") or "?"
            continue
        edge = hop.get("edge") or ""
        out += edge if edge.startswith((".", "[")) else f" {edge}"
    return out


def generalise(path: str) -> str:
    """A path as `diff` names sites: list positions are `[<index>]`."""
    return re.sub(r"\[\d+\]", "[<index>]", path)


class Heapspy:
    def __init__(self, exe: str, out: Path) -> None:
        # An existing relative path is resolved here: Windows' process
        # creation does not look one up relative to the working directory.
        self.exe = str(Path(exe).resolve()) if Path(exe).exists() else exe
        self.out = out

    def run(self, *args: str) -> str:
        r = subprocess.run(
            [self.exe, *args], capture_output=True, text=True, check=False
        )
        if r.returncode != 0:
            raise RuntimeError(f"heapspy {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout

    def json(self, *args: str) -> dict[str, Any]:
        return json.loads(self.run(*args, "--json"))

    def dump(self, pid: int, name: str, contents: bool) -> Path:
        path = self.out / f"{name}.hpy"
        args = ["dump", "--pid", str(pid), "-o", str(path)]
        if contents:
            # Long enough for file paths, which is what the contents are for.
            args += ["--capture-contents", "--max-str", "512"]
        self.run(*args)
        return path

    def locate(self, snap: Path, name: str) -> tuple[str | None, str | None]:
        """`(file:line, None)`, or `(None, why not)`."""
        try:
            doc = self.json("query", str(snap), "--locate", name)
        except RuntimeError as e:
            return None, str(e)
        for m in doc.get("matches", []):
            loc = m.get("source_loc")
            if isinstance(loc, dict) and loc.get("file"):
                line = loc.get("line")
                return (f"{loc['file']}:{line}" if line else loc["file"]), None
            if m.get("source_loc_reason"):
                return None, m["source_loc_reason"]
        return None, "not_found"


class Investigation:
    def __init__(self, hs: Heapspy, pid: int, interval: float, max_rounds: int) -> None:
        self.hs = hs
        self.pid = pid
        self.interval = interval
        self.max_rounds = max_rounds
        self.snaps: list[Path] = []
        self.captured_at: list[int] = []
        self.suspects: dict[str, Suspect] = {}
        self.native: list[dict[str, Any]] = []
        self.feedback: list[str] = []
        self.want_contents = False
        self.have_contents = False
        self.rounds = 0

    # ---- one round -----------------------------------------------------

    def round(self) -> list[Question]:
        self.rounds += 1
        contents = self.want_contents
        snap = self.hs.dump(self.pid, f"round{self.rounds}", contents)
        self.have_contents |= contents
        report = self.hs.json("analyze", str(snap), "--top", "25")
        diff = (
            self.hs.json("diff", str(self.snaps[-1]), str(snap), "--top", "3000")
            if self.snaps
            else None
        )
        self.snaps.append(snap)
        self.captured_at.append(report["snapshot"]["captured_at"])
        t = report["totals"]
        self.native.append(
            {
                "blocks": t.get("native_blocks", 0),
                "bytes": t.get("native_bytes", 0),
                "lost_bytes": t.get("native_lost_bytes", 0),
            }
        )

        for r in report["top_retainers"]:
            if r["retained_pct"] < MIN_PCT and r["retained_bytes"] < MIN_BYTES:
                continue
            site = generalise(render_path(r["path"]))
            # One holder, one suspect: a retainer whose site extends (or is
            # extended by) one already followed is the same leak seen from
            # its container or its contents.
            if site not in self.suspects and any(
                k.startswith(site) or site.startswith(k) for k in self.suspects
            ):
                continue
            s = self.suspects.setdefault(
                site, Suspect(site=site, type=r["type"], retained=0, path=r["path"])
            )
            s.retained, s.path = r["retained_bytes"], r["path"]

        if diff is not None:
            seconds = max(1, self.captured_at[-1] - self.captured_at[-2])
            sites = {d["site"]: d for d in diff["by_site"]}
            # Small holders that grow are suspects too, however small: a
            # leak is a rate, and in a short window it is far below what the
            # biggest retainers hold. Only holders a person would fix: a
            # module global, or a local of a running function.
            for d in diff["by_site"]:
                if (
                    HOLDER.fullmatch(d["site"])
                    and d["delta_retained_bytes"] > RATE_FLOOR * seconds
                    # Not one already followed under another name (a top
                    # retainer's path goes on past its holder).
                    and not any(
                        k.startswith(d["site"]) or d["site"].startswith(k)
                        for k in self.suspects
                    )
                ):
                    self.suspects[d["site"]] = Suspect(
                        site=d["site"],
                        type=d["type"],
                        retained=d["after_retained_bytes"],
                        path=[{"root_label": d["site"], "type": d["type"]}],
                        # Measured from now on; earlier rounds missed it.
                    )
            for s in self.suspects.values():
                d = sites.get(s.site)
                s.rates.append((d["delta_retained_bytes"] if d else 0) / seconds)
                self.composition(s, diff["by_site"], seconds)
        return self.questions()

    def composition(
        self, s: Suspect, by_site: list[dict[str, Any]], seconds: int
    ) -> None:
        """What grew under `s`: the deepest descendant site that still
        carries most of the holder's growth, which names what to look at
        (`[<index>] ValueError <+40> traceback .tb_frame frame local 'upload'
        bytes`, not just `RECENT_FAILURES`)."""
        own = next((d for d in by_site if d["site"] == s.site), None)
        if own is None or own["delta_retained_bytes"] <= 0:
            return
        best = own
        for d in by_site:
            if (
                d["site"].startswith(s.site)
                and d["site"] != s.site
                and d["delta_retained_bytes"] >= 0.5 * own["delta_retained_bytes"]
                and len(d["site"]) > len(best["site"])
            ):
                best = d
        below = [
            d
            for d in by_site
            if d["site"].startswith(s.site)
            and d["site"] != s.site
            and d["delta_retained_bytes"] > 0
        ]
        # The leaf type the growth mostly is. A site's delta includes its
        # descendants', so only the deepest sites are summed: those no other
        # site extends.
        leaves = [
            d
            for d in below
            if not any(o["site"].startswith(d["site"]) and o is not d for o in below)
        ]
        by_type: dict[str, int] = {}
        for d in leaves:
            by_type[d["type"]] = by_type.get(d["type"], 0) + d["delta_retained_bytes"]
        mostly = None
        if by_type:
            top, grew = max(by_type.items(), key=lambda kv: kv[1])
            if grew >= 0.5 * own["delta_retained_bytes"]:
                mostly = top
        if best is not own:
            s.made_of = best["site"][len(s.site) :].strip() + f"  ({best['type']})"
            s.made_of_rate = best["delta_retained_bytes"] / seconds
            # The chain that carries the growth is not always what it holds:
            # a deque's own blocks, holding the items that grow.
            if mostly and mostly != best["type"]:
                s.made_of += f", holding mostly {mostly}"
            s.grows_type = mostly or best["type"]
        elif mostly:
            # Spread over one site per dict key or chain link: group the
            # sites by their shape (any key `[*]`, a run of links one
            # `<+..>`) and name the shape that grew most, which says what
            # the entries are (`[*].scratch`), not just their type.
            shapes: dict[tuple[str, str], int] = {}
            for d in leaves:
                if d["type"] != mostly:
                    continue
                shape = re.sub(r"\[[^\]]*\]", "[*]", d["site"][len(s.site) :].strip())
                shape = re.sub(r"(\s*<\+\d+>)+", " <+..>", shape).strip()
                k = (shape, d["type"])
                shapes[k] = shapes.get(k, 0) + d["delta_retained_bytes"]
            (shape, typ), _ = max(shapes.items(), key=lambda kv: kv[1])
            s.made_of = f"{shape}  ({typ}), over {len(leaves)} entries"
            s.made_of_rate = by_type[mostly] / seconds
            s.grows_type = mostly
        # The program's own types carrying a real share of the growth, to
        # locate: a type that is only along for the ride (a local in a kept
        # frame) is not where to look.
        for d in below:
            if (
                d["type"].split(".")[0] not in BUILTIN_MODULES
                and d["delta_retained_bytes"] >= 0.1 * own["delta_retained_bytes"]
            ):
                s.locations.setdefault(d["type"], "")

    # ---- what is still unclear ----------------------------------------

    def questions(self) -> list[Question]:
        open_qs: list[Question] = []
        snap = self.snaps[-1]
        for s in self.suspects.values():
            qs: list[Question] = []
            if len(s.rates) < CONFIRM_ROUNDS:
                qs.append(
                    Question(
                        "growth",
                        f"Is {s.site} growing, or just big? "
                        f"({len(s.rates)} of {CONFIRM_ROUNDS} growth measurements)",
                        "snapshot",
                    )
                )
            elif s.verdict.startswith("unsettled"):
                qs.append(
                    Question(
                        "settle",
                        f"Has {s.site} stopped growing, or is it still growing? "
                        "(it grew in some rounds and not in others)",
                        "snapshot",
                    )
                )
            # Where the code is: the holder's module, and the program's own
            # types in what grew.
            names = list(s.locations)
            m = re.match(
                r"sys\.modules\['([^']+)'\]", s.path[0].get("root_label") or ""
            )
            if m:
                names.insert(0, m.group(1))
            for name in names:
                if s.locations.get(name):
                    continue
                loc, why = self.hs.locate(snap, name)
                if loc:
                    s.locations[name] = loc
                elif why == "contents_not_captured" and not self.have_contents:
                    qs.append(
                        Question(
                            f"where:{name}",
                            f"Which file is {name}? Its path is a string, redacted in "
                            "this snapshot.",
                            "contents",
                        )
                    )
                elif why == "no_python_methods":
                    fact = f"{name} is implemented in C (no Python source)"
                    if fact not in s.facts:
                        s.facts.append(fact)
                else:
                    qs.append(
                        Question(
                            f"where:{name}",
                            f"Where is {name} defined?",
                            None,
                            f"heapspy could not locate it ({why})",
                        )
                    )
            for i, h in enumerate(s.path[1:], 1):
                edge = h.get("edge") or ""
                if re.fullmatch(r"<\+\d+>", edge):
                    owner, held = s.path[i - 1]["type"], h["type"]
                    fact = f"{owner} field {edge} is its {held}"
                    if fact not in s.facts:
                        s.facts.append(fact)
                    qs.append(
                        Question(
                            f"field{edge}",
                            f"What is {owner}'s field {edge} called?",
                            None,
                            "the type exposes it only through a getter, so heapspy knows "
                            "its offset and what it holds, but not its name",
                        )
                    )
            # Native memory says who holds it, never who allocated it: the
            # snapshot has the block, not the call that made it.
            # Only when native memory is what grows, not when the growth merely
            # passes through native blocks (a deque's blocks holding objects).
            if (s.grows_type or "").startswith("native.") and s.verdict.startswith(
                "leak"
            ):
                qs.append(
                    Question(
                        "native_alloc",
                        f"Which code allocates the native memory growing under {s.site}?",
                        None,
                        "a snapshot holds blocks, not the calls that made them: run "
                        "`heapspy record --prepare python.exe` (admin), restart the "
                        "target, then `heapspy record --pid P --events native`",
                    )
                )
            s.questions = qs
            open_qs += qs

        if len(self.native) >= 2:
            seconds = max(1, self.captured_at[-1] - self.captured_at[-2])
            grew = (
                self.native[-1]["lost_bytes"] - self.native[-2]["lost_bytes"]
            ) / seconds
            if grew > RATE_FLOOR:
                open_qs.append(
                    Question(
                        "native_lost",
                        f"Native blocks nothing points to grow at {rate(grew)}: where are "
                        "they allocated?",
                        None,
                        "needs allocation stacks: `heapspy record --prepare python.exe`, "
                        "restart the target, then `heapspy record --events native`",
                    )
                )
        return open_qs

    # ---- the loop ------------------------------------------------------

    def run(self) -> None:
        while self.rounds < self.max_rounds:
            qs = self.round()
            self.print_round(qs)
            actions = {q.action for q in qs if q.action}
            if not actions:
                break
            if "contents" in actions:
                self.want_contents = True
            print(
                f"  -> can I get more information? yes: {', '.join(sorted(actions))}; "
                f"next snapshot in {self.interval:.0f} s\n"
            )
            time.sleep(self.interval)
        for s in self.suspects.values():
            for q in s.questions:
                if q.action is None and q.why_not:
                    self.feedback.append(f"{q.text} ({q.why_not})")

    def print_round(self, qs: list[Question]) -> None:
        print(f"== round {self.rounds}: {self.snaps[-1].name}")
        for s in sorted(self.suspects.values(), key=lambda s: -s.retained):
            r = ", ".join(rate(x) for x in s.rates) or "-"
            print(f"  {mib(s.retained):>11}  {s.verdict:<28} {s.site}  [{r}]")
            if s.made_of:
                print(f"  {'':>11}  made of: {s.made_of}")
        if len(self.native) >= 2:
            a, b = self.native[-2], self.native[-1]
            print(
                f"  native heap {mib(b['bytes'])} (+{mib(b['bytes'] - a['bytes'])}), "
                f"leaked {mib(b['lost_bytes'])}"
            )
        actionable = [q for q in qs if q.action]
        print(
            f"  still unclear: {len(qs)} ({len(actionable)} answerable with more information)"
        )
        for q in qs[:12]:
            print(
                f"    - {q.text}"
                + (f"  [get: {q.action}]" if q.action else "  [no action]")
            )

    def report(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "rounds": self.rounds,
            "snapshots": [str(p) for p in self.snaps],
            "suspects": [
                {
                    "site": s.site,
                    "type": s.type,
                    "verdict": s.verdict,
                    "retained_bytes": s.retained,
                    "bytes_per_second": s.rates,
                    "made_of": s.made_of,
                    "locations": {k: v for k, v in s.locations.items() if v},
                    "facts": s.facts,
                    "unanswered": [q.text for q in s.questions],
                }
                for s in sorted(self.suspects.values(), key=lambda s: -s.retained)
            ],
            "native": self.native,
            "heapspy_feedback": list(dict.fromkeys(self.feedback)),
        }

    def markdown(self) -> str:
        r = self.report()
        lines = [f"# Memory investigation of pid {self.pid}", ""]
        lines.append(f"{r['rounds']} snapshots, about {self.interval:.0f} s apart.")
        for s in r["suspects"]:
            last = s["bytes_per_second"][-1] if s["bytes_per_second"] else None
            lines += ["", f"## `{s['site']}`", ""]
            lines.append(
                f"- **{s['verdict']}**: {mib(s['retained_bytes'])} retained"
                + (f", growing {rate(last)}" if last and last > RATE_FLOOR else "")
            )
            if s["made_of"]:
                what = "what grows" if s["verdict"].startswith("leak") else "what grew"
                lines.append(f"- {what}: `{s['made_of']}`")
            for name, loc in s["locations"].items():
                lines.append(f"- `{name}`: {loc}")
            for f in s["facts"]:
                lines.append(f"- {f}")
        if r["heapspy_feedback"]:
            lines += ["", "## What heapspy could not make clear", ""]
            lines += [f"- {f}" for f in r["heapspy_feedback"]]
        return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--heapspy", default=shutil.which("heapspy") or "heapspy")
    p.add_argument(
        "--interval", type=float, default=10.0, help="seconds between rounds"
    )
    p.add_argument("--rounds", type=int, default=6, help="most rounds to run")
    p.add_argument("--out", type=Path, default=Path("investigation"))
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    inv = Investigation(Heapspy(a.heapspy, a.out), a.pid, a.interval, a.rounds)
    inv.run()
    (a.out / "report.json").write_text(json.dumps(inv.report(), indent=2))
    md = inv.markdown()
    (a.out / "report.md").write_text(md)
    print("\n" + md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
