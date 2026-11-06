"""Kernel wait-site categories for ``/proc/<tid>/stack`` and ``/proc/<tid>/wchan``.

:data:`CATEGORIES` is the one table that maps kernel function names to a
category. It is checked in order and the first category with a matching frame
wins, so the more specific memory-management waits (OOM, ``memory.high``
throttling, compaction, reclaim) come before page-fault I/O, and those come
before the general sleeps (futex, poll, nanosleep, block I/O).

Names are matched without offsets and compiler suffixes (``.isra.0``), either
exactly or by prefix. A thread whose stack matches nothing is ``other`` and
its innermost frames are kept, so new kernel names can be added here.

Pseudo-categories that do not come from a stack:

- ``running``: state ``R`` with no stack, or only interrupt-return frames (the
  kernel cannot unwind a task while it runs on a CPU).
- ``unavailable``: neither the stack nor ``wchan`` could be read.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Category:
    name: str
    meaning: str
    exact: frozenset[str] = field(default_factory=frozenset)
    prefixes: tuple[str, ...] = ()
    # Frames that count only when a page-fault frame is also on the stack.
    under_fault: frozenset[str] = field(default_factory=frozenset)
    # Matches only as the innermost frame.
    top_only: frozenset[str] = field(default_factory=frozenset)
    voluntary_idle: bool = False
    memory_management: bool = False

    def matches(self, frame: str) -> bool:
        return frame in self.exact or bool(self.prefixes and frame.startswith(self.prefixes))


# Frames that show a page fault (or a get_user_pages fault-in) in progress.
FAULT_FRAMES = frozenset(
    {
        "handle_mm_fault",
        "__handle_mm_fault",
        "handle_pte_fault",
        "do_user_addr_fault",
        "exc_page_fault",
        "asm_exc_page_fault",
        "do_page_fault",
        "__do_page_fault",
        "filemap_fault",
        "__do_fault",
        "do_fault",
        "do_read_fault",
        "do_shared_fault",
        "do_cow_fault",
        "do_swap_page",
        "do_anonymous_page",
        "filemap_map_pages",
        "faultin_page",
        "fixup_user_fault",
        "do_mem_abort",
        "do_translation_fault",
        "el0_da",
        "el1_abort",
    }
)

# Sleeping on a page or folio lock or on I/O. Under a fault this is page-fault I/O;
# without one (read(2), writeback, fsync) it is block I/O.
PAGE_WAIT_FRAMES = frozenset(
    {
        "folio_wait_bit_common",
        "folio_wait_bit",
        "folio_wait_bit_killable",
        "folio_wait_locked",
        "folio_wait_locked_killable",
        "__folio_lock",
        "__folio_lock_killable",
        "__folio_lock_or_retry",
        "wait_on_page_bit",
        "wait_on_page_bit_common",
        "wait_on_page_bit_killable",
        "__lock_page",
        "__lock_page_killable",
        "__lock_page_or_retry",
        "io_schedule",
        "io_schedule_timeout",
        "bit_wait_io",
    }
)

INTERRUPT_RETURN_PREFIXES = (
    "irqentry_exit",
    "asm_sysvec_",
    "asm_common_interrupt",
    "sysvec_",
    "exit_to_user_mode",
    "preempt_schedule",
    "schedule",
    "__schedule",
    "ret_from_intr",
    "retint_",
    "el0_interrupt",
    "el1_interrupt",
)

CATEGORIES: tuple[Category, ...] = (
    Category(
        "stopped_or_frozen",
        "stopped by a signal or ptrace (state T/t), or frozen by the cgroup freezer: "
        "the thread is held on purpose",
        exact=frozenset(
            {"__refrigerator", "do_freezer_trap", "do_signal_stop", "ptrace_stop", "do_jobctl_trap"}
        ),
        top_only=frozenset({"get_signal"}),
    ),
    Category(
        "oom",
        "inside the OOM killer, or waiting for an OOM kill in its cgroup to finish",
        exact=frozenset(
            {
                "out_of_memory",
                "oom_kill_process",
                "__oom_kill_process",
                "mem_cgroup_out_of_memory",
                "mem_cgroup_oom",
                "mem_cgroup_oom_synchronize",
                "pagefault_out_of_memory",
            }
        ),
        memory_management=True,
    ),
    Category(
        "memcg_high_throttle",
        "throttled on return to user space because its cgroup is over memory.high: "
        "reclaiming and then sleeping in proportion to the overage",
        exact=frozenset({"mem_cgroup_handle_over_high", "__mem_cgroup_handle_over_high"}),
        memory_management=True,
    ),
    Category(
        "compaction",
        "compacting memory to make a high-order (contiguous) allocation, or kcompactd",
        exact=frozenset({"try_to_compact_pages", "__alloc_pages_direct_compact", "kcompactd"}),
        prefixes=("compact_zone", "compact_node", "kcompactd_"),
        memory_management=True,
    ),
    Category(
        "direct_reclaim",
        "an allocation (or a cgroup charge) is reclaiming memory itself before it can "
        "continue: scanning and evicting pages, or throttled while others reclaim",
        exact=frozenset(
            {
                "try_to_free_pages",
                "try_to_free_mem_cgroup_pages",
                "do_try_to_free_pages",
                "__perform_reclaim",
                "__alloc_pages_direct_reclaim",
                "__alloc_pages_slowpath",
                "mem_cgroup_reclaim",
                "try_charge_memcg",
                "try_charge",
                "reclaim_throttle",
                "throttle_direct_reclaim",
                "node_reclaim",
                "__node_reclaim",
                "reclaim_high",
            }
        ),
        prefixes=(
            "shrink_node",
            "shrink_lruvec",
            "shrink_list",
            "shrink_folio_list",
            "shrink_page_list",
            "shrink_inactive_list",
            "shrink_active_list",
            "shrink_slab",
            "shrink_zones",
            "shrink_many",
        ),
        memory_management=True,
    ),
    Category(
        "dirty_throttle",
        "a writer is paused because too much of memory (or of its cgroup) is dirty "
        "and waiting for writeback",
        exact=frozenset({"balance_dirty_pages"}),
        prefixes=("balance_dirty_pages_ratelimited",),
        memory_management=True,
    ),
    Category(
        "page_fault_io",
        "a page fault waits for the page to be read in: a file-backed page (often a refault "
        "of a page evicted earlier) or a swap-in",
        exact=frozenset(
            {
                "do_swap_page",
                "swap_readpage",
                "swap_read_folio",
                "swapin_readahead",
                "swap_cluster_readahead",
                "swap_vma_readahead",
                "read_swap_cache_async",
                "__read_swap_cache_async",
            }
        ),
        under_fault=PAGE_WAIT_FRAMES,
        memory_management=True,
    ),
    Category(
        "futex",
        "waiting on a futex: a mutex, condition variable, semaphore or the Python GIL",
        exact=frozenset({"do_futex"}),
        prefixes=("futex_", "__x64_sys_futex", "__arm64_sys_futex", "__se_sys_futex"),
        voluntary_idle=True,
    ),
    Category(
        "poll",
        "waiting in poll, select, epoll or io_uring for file descriptors to be ready",
        exact=frozenset({"ep_poll", "do_poll", "io_cqring_wait"}),
        prefixes=(
            "do_epoll_",
            "do_sys_poll",
            "poll_schedule",
            "do_select",
            "core_sys_select",
            "do_pselect",
            "__x64_sys_epoll",
            "__x64_sys_poll",
            "__x64_sys_ppoll",
            "__x64_sys_select",
            "__x64_sys_pselect",
        ),
        voluntary_idle=True,
    ),
    Category(
        "nanosleep",
        "sleeping for a set time (nanosleep, clock_nanosleep)",
        exact=frozenset({"hrtimer_nanosleep", "do_nanosleep"}),
        prefixes=(
            "common_nsleep",
            "__x64_sys_nanosleep",
            "__x64_sys_clock_nanosleep",
            "__arm64_sys_nanosleep",
            "__arm64_sys_clock_nanosleep",
        ),
        voluntary_idle=True,
    ),
    Category(
        "ipc_wait",
        "waiting for input from a socket, pipe or terminal, for a child to exit, or for a signal",
        exact=frozenset(
            {
                "unix_stream_read_generic",
                "unix_stream_data_wait",
                "unix_dgram_recvmsg",
                "__skb_wait_for_more_packets",
                "__skb_recv_datagram",
                "sk_wait_data",
                "inet_csk_accept",
                "inet_csk_wait_for_connect",
                "tcp_recvmsg",
                "tcp_recvmsg_locked",
                "wait_woken",
                "pipe_read",
                "pipe_write",
                "anon_pipe_read",
                "anon_pipe_write",
                "do_wait",
                "kernel_wait4",
                "sigsuspend",
                "do_sigtimedwait",
                "n_tty_read",
                "inotify_read",
                "eventfd_read",
                "signalfd_dequeue",
            }
        ),
        prefixes=("__x64_sys_pause", "__x64_sys_wait4", "__x64_sys_rt_sigsuspend"),
        voluntary_idle=True,
    ),
    Category(
        "block_io",
        "waiting for block I/O outside a page fault: read(2) of an uncached page, fsync, "
        "writeback, a journal commit or direct I/O",
        exact=PAGE_WAIT_FRAMES
        | frozenset(
            {
                "submit_bio_wait",
                "wait_on_buffer",
                "__wait_on_buffer",
                "folio_wait_writeback",
                "wait_on_page_writeback",
                "__filemap_fdatawait_range",
                "rq_qos_wait",
                "wbt_wait",
                "iomap_dio_rw",
                "__iomap_dio_rw",
                "blkdev_issue_flush",
            }
        ),
        prefixes=("blk_mq_", "blk_execute", "jbd2_", "filemap_fdatawait", "xfs_log_force"),
    ),
)

BY_NAME = {c.name: c for c in CATEGORIES}

PSEUDO_CATEGORIES = {
    "running": "on a CPU or runnable (state R); the kernel does not unwind a running task, "
    "so no wait site is known",
    "other": "a kernel wait site not in the table; the innermost frames are kept",
    "unavailable": "neither /proc/<tid>/stack nor wchan could be read",
}

VOLUNTARY_IDLE = frozenset(c.name for c in CATEGORIES if c.voluntary_idle)
MEMORY_MANAGEMENT = frozenset(c.name for c in CATEGORIES if c.memory_management)
# The memory waits that mean the thread is stalled on getting memory back.
MEMORY_STALL = frozenset({"page_fault_io", "direct_reclaim", "memcg_high_throttle", "compaction"})

MAX_UNKNOWN_FRAMES = 3


def meanings() -> dict[str, str]:
    """Every category name and what it means, in table order."""
    return {**{c.name: c.meaning for c in CATEGORIES}, **PSEUDO_CATEGORIES}


@dataclass
class Classified:
    category: str
    matched_frame: str | None
    frames: list[str]  # innermost first, as read (capped by the caller)


def _only_interrupt_return(frames: list[str]) -> bool:
    return all(f.startswith(INTERRUPT_RETURN_PREFIXES) for f in frames)


def classify_stack(frames: list[str], state: str | None = None) -> Classified:
    """Category of one ``/proc/<tid>/stack`` sample (innermost frame first)."""
    if state in ("T", "t"):
        return Classified("stopped_or_frozen", None, frames)
    if not frames or (state == "R" and _only_interrupt_return(frames)):
        return Classified("running" if state == "R" else "other", None, frames)
    under_fault = any(f in FAULT_FRAMES for f in frames)
    for cat in CATEGORIES:
        if cat.top_only and frames[0] in cat.top_only:
            return Classified(cat.name, frames[0], frames)
        for f in frames:
            if cat.matches(f) or (under_fault and f in cat.under_fault):
                return Classified(cat.name, f, frames)
    if state == "R":
        return Classified("running", None, frames)
    return Classified("other", None, frames)


def classify_wchan(wchan: str | None, state: str | None, faulted: bool) -> Classified:
    """Category from ``wchan`` alone (no stack: not root, or stacks disabled).

    ``wchan`` is the innermost function, so a page or folio lock wait cannot be told
    apart from a read(2) wait. It counts as ``page_fault_io`` when ``faulted`` (the
    thread's major-fault count rose since the previous sample), else ``block_io``.
    """
    if state in ("T", "t"):
        return Classified("stopped_or_frozen", None, [])
    if not wchan:
        return Classified("running" if state == "R" else "unavailable", None, [])
    frames = [wchan]
    if wchan in PAGE_WAIT_FRAMES:
        return Classified("page_fault_io" if faulted else "block_io", wchan, frames)
    return classify_stack(frames, state)
