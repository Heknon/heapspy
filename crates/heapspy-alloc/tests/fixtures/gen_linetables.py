"""Dump co_linetable fixtures for the heapspy-alloc line-table tests.

Compiles linetable_source.py (it is never executed), walks every code object
in it, and writes linetable-3.<minor>.json next to this script with, per code
object:

- qualname, firstlineno
- linetable: co_linetable as lowercase hex
- positions: co_positions(), one [line, end_line, col, end_col] per code
  unit (2 bytes of bytecode), null where CPython reports None
- lines: co_lines() as [start, end, line] byte ranges

Run it once per interpreter from the repository root:

    python3.12 crates/heapspy-alloc/tests/fixtures/gen_linetables.py
    python3.13 crates/heapspy-alloc/tests/fixtures/gen_linetables.py
    python3.14 crates/heapspy-alloc/tests/fixtures/gen_linetables.py

The output depends only on the compiler of the minor version, so regenerate
it when moving to a new minor version, not for micro releases.
"""

import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "linetable_source.py")


def codes(co):
    yield co
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            yield from codes(c)


def main():
    with open(SOURCE, encoding="utf-8") as f:
        text = f.read()
    top = compile(text, "linetable_source.py", "exec")
    out = []
    for co in codes(top):
        out.append(
            {
                "qualname": co.co_qualname,
                "firstlineno": co.co_firstlineno,
                "code_bytes": len(co.co_code),
                "linetable": co.co_linetable.hex(),
                "positions": [list(p) for p in co.co_positions()],
                "lines": [list(r) for r in co.co_lines()],
            }
        )
    v = sys.version_info
    doc = {
        "python": f"{v.major}.{v.minor}.{v.micro}",
        "codes": out,
    }
    path = os.path.join(HERE, f"linetable-{v.major}.{v.minor}.json")
    with open(path, "w", encoding="utf-8") as f:
        # One code object per line keeps diffs readable.
        f.write('{"python": %s, "codes": [\n' % json.dumps(doc["python"]))
        f.write(",\n".join(json.dumps(c, separators=(",", ":")) for c in out))
        f.write("\n]}\n")
    print(f"wrote {path}: {len(out)} code objects")


if __name__ == "__main__":
    main()
