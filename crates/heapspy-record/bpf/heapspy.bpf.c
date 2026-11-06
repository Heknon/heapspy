// SPDX-License-Identifier: MIT OR GPL-2.0
//
// heapspy allocation recorder, kernel side. See ../src/linux_ebpf.rs for the
// design and src/linux_ebpf/abi.rs for the user-space mirror of every struct
// here. Self-contained: no libbpf headers, no BTF, legacy "maps" section, so
// the loader in loader.rs can stay small. Rebuild with ./build.sh; the
// committed heapspy.bpf.o must match its output (./build.sh --check).
//
// Programs:
//   raw_tracepoint/sys_enter, sys_exit  arenas: anonymous mmap of arena_size
//   uprobe/{malloc,calloc,realloc}[_ctx] large objects: entry, size, sampler
//   uretprobe/alloc_ret                  large objects: returned pointer
// Events are assembled in a per-CPU scratch map and only the frames in
// use are copied into the ring buffer.
// Every event carries the allocating thread's Python stack, walked here
// at event time exactly like heapspy_reader::cpython::frames::read_stack.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

#define SEC(n) __attribute__((section(n), used))
#define INLINE static __attribute__((always_inline)) inline

// Helpers, by number (include/uapi/linux/bpf.h).
static void *(*map_lookup)(void *map, const void *key) = (void *)1;
static long (*map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*map_delete)(void *map, const void *key) = (void *)3;
static u64 (*ktime_get_ns)(void) = (void *)5;
static u32 (*prandom_u32)(void) = (void *)7;
static u64 (*get_current_pid_tgid)(void) = (void *)14;
static long (*probe_read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static long (*ringbuf_output)(void *ringbuf, void *data, u64 size, u64 flags) = (void *)130;

struct map_def {
    u32 type, key_size, value_size, max_entries, map_flags;
};
#define MAP_HASH 1
#define MAP_ARRAY 2
#define MAP_PERCPU_ARRAY 6
#define MAP_LRU_HASH 9
#define MAP_RINGBUF 27

// ---- shared with abi.rs ---------------------------------------------------

#define KMAX_FRAMES 128     // frames copied per event (power of two)
#define KMAX_STEPS 256      // frame-chain links followed (shims included)
#define KMAX_INTERPS 4
#define KMAX_THREADS 256
#define N_THRESHOLDS 256

struct config {
    u64 tgid;
    u64 arena_size;          // 0: arenas off
    u64 large_on;            // large objects on
    u64 min_large;           // sizes <= this are not large objects (512)
    u64 interval;            // byte interval, 0: every call
    u64 runtime_addr;
    u64 max_frames;          // <= KMAX_FRAMES
    // FrameOffsets subset
    u64 rt_interpreters_head, is_next, is_threads_head;
    u64 ts_next, ts_native_thread_id, ts_native_thread_id_size;
    u64 ts_current_frame, ts_frame_via_cframe;
    u64 if_previous, if_executable, if_instr_ptr, if_owner, owner_first_shim;
    u64 executable_is_stackref;
};

struct frame {
    u64 executable;   // code object (masked), maybe not a code object
    u64 instr_ptr;
    u64 ob_type;      // type of `executable`; user space keeps code objects
};

#define KIND_ARENA 1
#define KIND_LARGE 3

#define EF_NO_TSTATE 1
#define EF_TRUNCATED 2
#define EF_BROKEN 4
#define EF_HAS_RET 8

struct event {
    u64 ts;           // CLOCK_MONOTONIC ns
    u64 addr, size, ret_addr;
    u32 tid;
    u8 kind, flags;
    u16 nframes;
    struct frame frames[KMAX_FRAMES];
};

// counters (per CPU)
#define C_HITS 0           // probe firings for this tgid
#define C_SAMPLED 1        // events that passed filters and sampler
#define C_DROPPED 2        // ring buffer full
#define C_ORPHANS 3        // sampled entries whose return never came
#define C_REFIRES 5        // entry probe fired twice for one call
#define C_TSTATE_MISS 4    // no PyThreadState for the thread
#define N_COUNTERS 8

struct pending {
    u64 size, ret_addr, ts;
};

struct pkey {
    u64 tid;
    u64 sp;           // stack pointer at entry: pairs nested calls exactly
};

// ---- maps -----------------------------------------------------------------

SEC("maps") struct map_def cfg = {MAP_ARRAY, 4, sizeof(struct config), 1, 0};
SEC("maps") struct map_def thresholds = {MAP_ARRAY, 4, 8, N_THRESHOLDS, 0};
SEC("maps") struct map_def remaining = {MAP_PERCPU_ARRAY, 4, 8, 1, 0};
SEC("maps") struct map_def counters = {MAP_PERCPU_ARRAY, 4, 8, N_COUNTERS, 0};
SEC("maps") struct map_def pending = {MAP_LRU_HASH, sizeof(struct pkey), sizeof(struct pending), 65536, 0};
SEC("maps") struct map_def mmaps = {MAP_LRU_HASH, 8, 8, 16384, 0};
SEC("maps") struct map_def tstates = {MAP_LRU_HASH, 8, 8, 16384, 0};
SEC("maps") struct map_def events = {MAP_RINGBUF, 0, 0, 16 << 20, 0};
// Events are built here, then only the used part is copied to the ring.
SEC("maps") struct map_def scratch = {MAP_PERCPU_ARRAY, 4, sizeof(struct event), 1, 0};

char LICENSE[] SEC("license") = "GPL";

// ---- helpers --------------------------------------------------------------

INLINE void count(u32 which) {
    u64 *c = map_lookup(&counters, &which);
    if (c)
        *c += 1;
}

// bpf_probe_read_user zero-fills on failure: no branch, so the verifier
// has fewer paths to explore.
INLINE u64 rd(u64 addr) {
    u64 v = 0;
    probe_read_user(&v, 8, (void *)addr);
    return v;
}

INLINE int rd_ok(u64 addr, u64 *v) {
    return probe_read_user(v, 8, (void *)addr) == 0;
}

INLINE u64 read_tid(struct config *c, u64 ts) {
    if (c->ts_native_thread_id_size == 4) {
        u32 v = 0;
        probe_read_user(&v, 4, (void *)(ts + c->ts_native_thread_id));
        return v;
    }
    return rd(ts + c->ts_native_thread_id);
}

// The thread state whose native_thread_id is tid, or 0.
INLINE u64 find_tstate(struct config *c, u64 tid) {
    u64 *hit = map_lookup(&tstates, &tid);
    if (hit && *hit && read_tid(c, *hit) == tid)
        return *hit;
    u64 found = 0;
    u64 interp = rd(c->runtime_addr + c->rt_interpreters_head);
    for (int i = 0; i < KMAX_INTERPS && interp && !found; i++) {
        u64 ts = rd(interp + c->is_threads_head);
        for (int j = 0; j < KMAX_THREADS && ts; j++) {
            if (read_tid(c, ts) == tid) {
                found = ts;
                break;
            }
            ts = rd(ts + c->ts_next);
        }
        interp = rd(interp + c->is_next);
    }
    if (found)
        map_update(&tstates, &tid, &found, 0);
    return found;
}

INLINE void walk(struct config *c, struct event *e, u64 tid) {
    u64 ts = find_tstate(c, tid);
    if (!ts) {
        e->flags |= EF_NO_TSTATE;
        count(C_TSTATE_MISS);
        return;
    }
    u64 f = rd(ts + c->ts_current_frame);
    if (c->ts_frame_via_cframe && f)
        f = rd(f);
    // The frame count lives in the event (map memory), not in a
    // register: the verifier does not track its value, so loop states
    // with different counts are pruned as equivalent.
    e->nframes = 0;
    for (int i = 0; i < KMAX_STEPS; i++) {
        if (!f)
            break;
        u8 owner = 0;
        if (probe_read_user(&owner, 1, (void *)(f + c->if_owner)) != 0) {
            e->flags |= EF_BROKEN;
            f = 0;
            break;
        }
        if (owner < c->owner_first_shim) {
            u64 code = rd(f + c->if_executable);
            if (c->executable_is_stackref)
                code = (code & 3) == 3 ? 0 : code & ~3ULL;
            if (code) {
                u32 n = e->nframes;
                if (n >= c->max_frames || n >= KMAX_FRAMES)
                    break;
                struct frame *fr = &e->frames[n & (KMAX_FRAMES - 1)];
                fr->executable = code;
                fr->instr_ptr = rd(f + c->if_instr_ptr);
                fr->ob_type = rd(code + 8);
                e->nframes = n + 1;
            }
        }
        u64 prev = 0;
        if (!rd_ok(f + c->if_previous, &prev)) {
            e->flags |= EF_BROKEN;
            f = 0;
            break;
        }
        f = prev;
    }
    if (f)
        e->flags |= EF_TRUNCATED;
}

INLINE struct config *config(void) {
    u32 z = 0;
    return map_lookup(&cfg, &z);
}

#define HEADER_SIZE 40

INLINE void emit(struct config *c, u64 tid, u8 kind, u64 addr, u64 size, u64 ret, u8 flags) {
    u32 z = 0;
    struct event *e = map_lookup(&scratch, &z);
    if (!e)
        return;
    e->ts = ktime_get_ns();
    e->tid = (u32)tid;
    e->kind = kind;
    e->flags = flags;
    e->addr = addr;
    e->size = size;
    e->ret_addr = ret;
    e->nframes = 0;
    walk(c, e, tid);
    u64 n = e->nframes;
    if (n > KMAX_FRAMES)
        n = KMAX_FRAMES;
    u64 len = HEADER_SIZE + n * sizeof(struct frame);
    if (len > sizeof(struct event))
        len = sizeof(struct event);
    if (ringbuf_output(&events, e, len, 0) != 0) {
        count(C_DROPPED);
        return;
    }
    count(C_SAMPLED);
}

// ---- arenas ---------------------------------------------------------------

#define NR_MMAP 9
#define MAP_ANONYMOUS 0x20
// x86_64 struct pt_regs offsets
#define R_R10 56
#define R_R8 72
#define R_AX 80
#define R_DX 96
#define R_SI 104
#define R_DI 112
#define R_ORIG_AX 120
#define R_SP 152

INLINE u64 kreg(void *regs, u32 off) {
    u64 v = 0;
    probe_read_kernel(&v, 8, (char *)regs + off);
    return v;
}

SEC("raw_tracepoint/sys_enter")
int sys_enter(u64 *ctx) {
    if (ctx[1] != NR_MMAP)
        return 0;
    struct config *c = config();
    if (!c || !c->arena_size)
        return 0;
    u64 pt = get_current_pid_tgid();
    if ((pt >> 32) != c->tgid)
        return 0;
    count(C_HITS);
    void *regs = (void *)ctx[0];
    if (kreg(regs, R_SI) != c->arena_size || kreg(regs, R_DI) != 0)
        return 0;
    if (!(kreg(regs, R_R10) & MAP_ANONYMOUS) || (u32)kreg(regs, R_R8) != 0xffffffffu)
        return 0;
    u64 tid = (u32)pt;
    u64 len = c->arena_size;
    map_update(&mmaps, &tid, &len, 0);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(u64 *ctx) {
    struct config *c = config();
    if (!c || !c->arena_size)
        return 0;
    u64 pt = get_current_pid_tgid();
    if ((pt >> 32) != c->tgid)
        return 0;
    u64 tid = (u32)pt;
    u64 *len = map_lookup(&mmaps, &tid);
    if (!len)
        return 0;
    u64 size = *len;
    map_delete(&mmaps, &tid);
    if (kreg((void *)ctx[0], R_ORIG_AX) != NR_MMAP)
        return 0;
    s64 ret = (s64)ctx[1];
    if (ret < 0 && ret > -4096)
        return 0;
    emit(c, tid, KIND_ARENA, (u64)ret, size, 0, 0);
    return 0;
}

// ---- large objects --------------------------------------------------------

INLINE int sampled(struct config *c, u64 size) {
    if (c->interval == 0)
        return 1;
    u32 z = 0;
    s64 *rem = map_lookup(&remaining, &z);
    if (!rem)
        return 0;
    if (*rem == 0) {
        // first use on this CPU: draw a fresh gap
        u32 k = prandom_u32() & (N_THRESHOLDS - 1);
        u64 *t = map_lookup(&thresholds, &k);
        *rem = t ? (s64)*t : (s64)c->interval;
    }
    *rem -= (s64)size;
    if (*rem > 0)
        return 0;
    // Memoryless: the next gap starts fresh after a sampled allocation.
    u32 k = prandom_u32() & (N_THRESHOLDS - 1);
    u64 *t = map_lookup(&thresholds, &k);
    s64 next = t ? (s64)*t : (s64)c->interval;
    *rem = next > 0 ? next : 1;
    return 1;
}

INLINE int on_entry(u64 *regs, u64 size) {
    struct config *c = config();
    if (!c || !c->large_on)
        return 0;
    u64 pt = get_current_pid_tgid();
    if ((pt >> 32) != c->tgid)
        return 0;
    count(C_HITS);
    if (size <= c->min_large || !sampled(c, size))
        return 0;
    u64 sp = regs[R_SP / 8];
    struct pkey k = {(u32)pt, sp};
    struct pending p = {size, rd(sp), ktime_get_ns()};
    struct pending *old = map_lookup(&pending, &k);
    if (old) {
        // Same call seen twice (the probe re-fired) or an earlier call at
        // this stack depth whose return probe never ran.
        if (old->size == size && old->ret_addr == p.ret_addr && p.ts - old->ts < 1000000)
            count(C_REFIRES);
        else
            count(C_ORPHANS);
    }
    map_update(&pending, &k, &p, 0);
    return 0;
}

// _PyMem_Raw*(void *ctx, ...): the context is the first argument.
SEC("uprobe/malloc_ctx") int malloc_ctx(u64 *r) { return on_entry(r, r[R_SI / 8]); }
SEC("uprobe/calloc_ctx") int calloc_ctx(u64 *r) { return on_entry(r, r[R_SI / 8] * r[R_DX / 8]); }
SEC("uprobe/realloc_ctx") int realloc_ctx(u64 *r) { return on_entry(r, r[R_DX / 8]); }
// libc
SEC("uprobe/malloc") int malloc_libc(u64 *r) { return on_entry(r, r[R_DI / 8]); }
SEC("uprobe/calloc") int calloc_libc(u64 *r) { return on_entry(r, r[R_DI / 8] * r[R_SI / 8]); }
SEC("uprobe/realloc") int realloc_libc(u64 *r) { return on_entry(r, r[R_SI / 8]); }

SEC("uretprobe/alloc_ret")
int alloc_ret(u64 *r) {
    struct config *c = config();
    if (!c)
        return 0;
    u64 pt = get_current_pid_tgid();
    if ((pt >> 32) != c->tgid)
        return 0;
    // `ret` popped the return address: sp is 8 above the entry sp.
    struct pkey k = {(u32)pt, r[R_SP / 8] - 8};
    struct pending *p = map_lookup(&pending, &k);
    if (!p)
        return 0;
    u64 size = p->size, ret = p->ret_addr;
    map_delete(&pending, &k);
    u64 addr = r[R_AX / 8];
    if (!addr)
        return 0;
    emit(c, k.tid, KIND_LARGE, addr, size, ret, EF_HAS_RET);
    return 0;
}
