"""A function kept in a global whose closure captures a large object.

Leak: ``make_handler`` builds an 8 MiB ``bytearray`` and returns a function
that only needs its length. The function is stored in ``HANDLER``, so the
buffer lives as long as the module. Expected top retainer: the bytearray,
reached as ``sys.modules['__main__'].__dict__['HANDLER'].__closure__[i].cell_contents``,
where ``i`` is the index of ``buffer`` in ``co_freevars`` (reported by the
victim, not assumed).

Noise:
- ``SMALL_HANDLER``: another closure over a 1 MiB bytearray.
- ``FRAMES``: a global list of 12 bytearrays of 512 KiB (6 MiB in total but
  less than the leak, and spread over many objects).
- ``STATIC_BUFFER``: a 2 MiB bytearray held directly by a global.
"""

import sys

from _victim import ready, serve

BIG = 8 * 1024 * 1024


def make_handler(size, name):
    prefix = f"handler:{name}"
    buffer = bytearray(size)

    def handler():
        return prefix, len(buffer)

    return handler


HANDLER = make_handler(BIG, "upload")
SMALL_HANDLER = make_handler(1024 * 1024, "ping")
FRAMES = [bytearray(512 * 1024) for _ in range(12)]
STATIC_BUFFER = bytearray(2 * 1024 * 1024)

if __name__ == "__main__":
    freevars = HANDLER.__code__.co_freevars
    index = freevars.index("buffer")
    captured = HANDLER.__closure__[index].cell_contents
    ready(
        freevars=list(freevars),
        cell_index=index,
        expected_retained=sys.getsizeof(captured),
    )
    del captured
    serve()
