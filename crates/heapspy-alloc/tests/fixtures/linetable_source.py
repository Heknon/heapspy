# Source compiled (never run) by gen_linetables.py. Each construct is here to
# produce a particular kind of co_linetable entry: short forms, one-line
# forms with columns past 127, long forms with multi-byte and negative line
# deltas, multi-line expressions, and instructions with no location.

import os


def simple(a, b):
    c = a + b
    return c * 2


def loop(items):
    total = 0
    for i, item in enumerate(items):
        if i % 2:
            total += item
        else:
            total -= item
    while total > 100:
        total //= 2
    return total


def multiline_call(x):
    return dict(
        alpha=x,
        beta=[
            x + 1,
            x + 2,
        ],
        gamma={"k": x
               for _ in range(3)},
    )


def wide_columns(value):
    result = value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value
    return result


def far_lines(v):
    first = v



















































    second = first + 1




































































































    third = second + 1
    return third


def exceptions(path):
    try:
        with open(path) as f:
            data = f.read()
    except FileNotFoundError:
        data = ""
    except (OSError, ValueError) as e:
        raise RuntimeError(str(e)) from e
    finally:
        os.sync() if hasattr(os, "sync") else None
    return data


def generator(n):
    for i in range(n):
        yield i * i
    yield from range(3)


async def coroutine(q):
    async with q as item:
        await item
    async for x in q:
        print(x)


class Widget:
    size = 3

    def __init__(self, name):
        self.name = name
        self.parts = [p for p in name if p != " "]

    @property
    def label(self):
        return f"{self.name}:{len(self.parts)}"

    def nested(self):
        def inner(k):
            return lambda j: (k, j, self.size)
        return inner


def match_case(cmd):
    match cmd:
        case ["go", direction]:
            return direction
        case {"x": x, "y": y}:
            return x + y
        case _:
            return None


big_table = [
    (1, 2), (3, 4), (5, 6), (7, 8), (9, 10), (11, 12), (13, 14), (15, 16),
    (17, 18), (19, 20), (21, 22), (23, 24), (25, 26), (27, 28), (29, 30),
]
