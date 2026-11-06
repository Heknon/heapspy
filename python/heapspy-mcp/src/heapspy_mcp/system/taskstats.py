"""Per-process delay accounting through the taskstats generic-netlink interface.

``TASKSTATS_CMD_GET`` with a TGID returns the summed ``struct taskstats`` of a
process's threads (Documentation/accounting/taskstats.rst). The delay totals
(time waiting for a CPU, block I/O, swap-in, page reclaim, thrashing,
compaction) are only filled while delay accounting is on
(``kernel.task_delayacct=1`` or the ``delayacct`` boot option, 5.14+; on by
default before). This module only reads; it never changes the sysctl.

The kernel needs ``CAP_NET_ADMIN`` for this command.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Any

NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
TASKSTATS_CMD_GET = 1
TASKSTATS_CMD_ATTR_TGID = 2
TASKSTATS_TYPE_STATS = 3
TASKSTATS_TYPE_AGGR_PID = 4
TASKSTATS_TYPE_AGGR_TGID = 5
NLM_F_REQUEST = 1
NLMSG_ERROR = 2

# Byte offsets of the u64 fields of struct taskstats (include/uapi/linux/taskstats.h),
# with the version that added each one.
FIELDS: dict[str, tuple[int, int]] = {
    "cpu_count": (16, 1),
    "cpu_delay_total_ns": (24, 1),
    "blkio_count": (32, 1),
    "blkio_delay_total_ns": (40, 1),
    "swapin_count": (48, 1),
    "swapin_delay_total_ns": (56, 1),
    "ac_minflt": (168, 1),
    "ac_majflt": (176, 1),
    "nvcsw": (272, 2),
    "nivcsw": (280, 2),
    "freepages_count": (312, 6),
    "freepages_delay_total_ns": (320, 6),
    "thrashing_count": (328, 9),
    "thrashing_delay_total_ns": (336, 9),
    "compact_count": (352, 11),
    "compact_delay_total_ns": (360, 11),
}
COMM_OFFSET = 80
COMM_LEN = 32
PID_OFFSET = 128  # ac_pid (u32)


class TaskstatsError(Exception):
    """The taskstats request failed; the message says why."""


def _attr(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("HH", length, kind) + payload + b"\0" * ((4 - length % 4) % 4)


def _message(family: int, cmd: int, attrs: bytes, seq: int) -> bytes:
    genl = struct.pack("BBH", cmd, 1, 0)
    body = genl + attrs
    return struct.pack("IHHII", 16 + len(body), family, NLM_F_REQUEST, seq, 0) + body


def parse_attrs(data: bytes) -> dict[int, bytes]:
    """Netlink attributes of ``data`` (type -> payload); the nested flag is masked."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(data):
        length, kind = struct.unpack_from("HH", data, i)
        if length < 4:
            break
        out[kind & 0x3FFF] = data[i + 4 : i + length]
        i += (length + 3) & ~3
    return out


def _payloads(reply: bytes) -> list[tuple[int, bytes]]:
    """(type, genl attribute bytes) of each netlink message in ``reply``."""
    out = []
    i = 0
    while i + 16 <= len(reply):
        length, kind, _flags, _seq, _pid = struct.unpack_from("IHHII", reply, i)
        if length < 16:
            break
        body = reply[i + 16 : i + length]
        if kind == NLMSG_ERROR:
            (err,) = struct.unpack_from("i", body, 0)
            if err:
                raise TaskstatsError(f"netlink error: {os.strerror(-err)} (errno {-err})")
        else:
            out.append((kind, body[4:]))
        i += (length + 3) & ~3
    return out


def parse_taskstats(raw: bytes) -> dict[str, Any]:
    """Fields of one ``struct taskstats``; those newer than its version are None."""
    (version,) = struct.unpack_from("H", raw, 0)
    out: dict[str, Any] = {"version": version}
    for name, (offset, since) in FIELDS.items():
        if version >= since and offset + 8 <= len(raw):
            (out[name],) = struct.unpack_from("Q", raw, offset)
        else:
            out[name] = None
    if len(raw) >= PID_OFFSET + 4:
        (out["ac_pid"],) = struct.unpack_from("I", raw, PID_OFFSET)
        out["ac_comm"] = (
            raw[COMM_OFFSET : COMM_OFFSET + COMM_LEN].split(b"\0", 1)[0].decode("utf-8", "replace")
        )
    return out


def stats_from_reply(reply: bytes) -> dict[str, Any]:
    for _kind, attrs in _payloads(reply):
        top = parse_attrs(attrs)
        nested = top.get(TASKSTATS_TYPE_AGGR_TGID) or top.get(TASKSTATS_TYPE_AGGR_PID)
        if nested is None:
            continue
        stats = parse_attrs(nested).get(TASKSTATS_TYPE_STATS)
        if stats:
            return parse_taskstats(stats)
    raise TaskstatsError("no TASKSTATS_TYPE_STATS in the reply")


def _family_id(sock: socket.socket) -> int:
    sock.send(
        _message(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, _attr(CTRL_ATTR_FAMILY_NAME, b"TASKSTATS\0"), 1)
    )
    for _kind, attrs in _payloads(sock.recv(65536)):
        fid = parse_attrs(attrs).get(CTRL_ATTR_FAMILY_ID)
        if fid:
            return struct.unpack("H", fid[:2])[0]
    raise TaskstatsError("the TASKSTATS genetlink family is not registered (CONFIG_TASKSTATS off)")


def read_tgid(tgid: int, timeout_s: float = 1.0) -> dict[str, Any]:
    """Summed taskstats of every thread of ``tgid``."""
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    except (OSError, AttributeError) as e:
        raise TaskstatsError(f"cannot open a generic netlink socket: {e}") from e
    try:
        sock.settimeout(timeout_s)
        sock.bind((0, 0))
        family = _family_id(sock)
        sock.send(
            _message(
                family, TASKSTATS_CMD_GET, _attr(TASKSTATS_CMD_ATTR_TGID, struct.pack("I", tgid)), 2
            )
        )
        return stats_from_reply(sock.recv(65536))
    except PermissionError as e:
        raise TaskstatsError("taskstats needs CAP_NET_ADMIN") from e
    except OSError as e:
        raise TaskstatsError(f"taskstats request failed: {e}") from e
    finally:
        sock.close()
