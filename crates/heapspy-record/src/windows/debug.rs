//! The debugger path's event loop as a pure state machine, tested on every
//! platform with a fake target. `sys.rs` drives it with
//! `WaitForDebugEvent` / `ContinueDebugEvent` on Windows.
//!
//! # Breakpoints
//!
//! - **Entry** on `VirtualAlloc` (in `kernelbase.dll`). A hit is an arena
//!   allocation when `lpAddress == 0`, `dwSize == arena size`,
//!   `flAllocationType` has `MEM_COMMIT | MEM_RESERVE`, and the return
//!   address `[rsp]` is inside the Python DLL. Then the thread's Python
//!   stack is read at once (all threads are suspended while a debug event
//!   is pending, so it is exact) and a **return** breakpoint is set at that
//!   return address to get the arena's address from `rax`.
//! - Stepping over a breakpoint: write the original byte back, set `rip`
//!   to the breakpoint, set the trap flag; at the single-step exception,
//!   re-arm. A return breakpoint is removed when no thread waits on it.
//! - The first breakpoint that is not ours is the attach breakpoint
//!   (`DbgBreakPoint` in the thread the system injects) and is handled;
//!   later foreign breakpoints and every other exception are passed to the
//!   target (`DBG_EXCEPTION_NOT_HANDLED`), as without a debugger.
//!
//! # Leaving
//!
//! [`Machine::disarm`] writes every original byte back and clears pending
//! trap flags. The caller then drains debug events for a moment, passing
//! each to [`Machine::handle`] (which, once disarmed, rewinds `rip` for a
//! hit on a removed breakpoint instead of reporting it), and only then
//! detaches. So no `int3` and no trap flag of ours is left for the target
//! to trip over after `DebugActiveProcessStop`.

use std::collections::HashMap;

pub const INT3: u8 = 0xcc;
pub const MEM_COMMIT: u64 = 0x1000;
pub const MEM_RESERVE: u64 = 0x2000;

/// The registers the machine reads (x64).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub rip: u64,
    pub rsp: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
}

/// One debug event, reduced to what the machine needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `EXCEPTION_BREAKPOINT` at `addr` (the `int3`'s address).
    Breakpoint {
        tid: u32,
        addr: u64,
    },
    /// `EXCEPTION_SINGLE_STEP`.
    SingleStep {
        tid: u32,
    },
    /// Any other exception.
    Exception {
        tid: u32,
    },
    ExitProcess,
    /// Thread and module notifications.
    Other,
}

/// How to continue the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `DBG_CONTINUE`.
    Handled,
    /// `DBG_EXCEPTION_NOT_HANDLED`: the target sees the exception.
    NotHandled,
    /// The process exited.
    Exited,
}

/// Side effects on the target, and the two sample callbacks.
pub trait DebugIo {
    fn read_byte(&mut self, addr: u64) -> Option<u8>;
    fn write_byte(&mut self, addr: u64, b: u8) -> bool;
    fn read_u64(&mut self, addr: u64) -> Option<u64>;
    fn regs(&mut self, tid: u32) -> Option<Regs>;
    fn set_rip(&mut self, tid: u32, rip: u64) -> bool;
    fn set_trap(&mut self, tid: u32, on: bool) -> bool;
    /// An arena allocation is starting on `tid`: read its stack now.
    fn arena_entry(&mut self, tid: u32, size: u64, return_address: u64);
    /// The arena allocation on `tid` returned `addr` (0 if it failed).
    fn arena_exit(&mut self, tid: u32, addr: u64);
}

struct Bp {
    orig: u8,
    armed: bool,
    /// Threads waiting to return here (return breakpoints).
    waiters: u32,
    entry: bool,
}

/// See the module docs.
pub struct Machine {
    entry: u64,
    arena_size: u64,
    /// `[start, end)` of the Python DLL.
    python: (u64, u64),
    bps: HashMap<u64, Bp>,
    /// Thread -> breakpoint to re-arm after its single step.
    stepping: HashMap<u32, u64>,
    /// Thread -> return address of its pending arena call.
    pending: HashMap<u32, u64>,
    attach_break_seen: bool,
    disarmed: bool,
    /// Breakpoint hits (entry and return), for `probe_hits`.
    pub hits: u64,
}

impl Machine {
    pub fn new(entry: u64, arena_size: u64, python: (u64, u64)) -> Self {
        Self {
            entry,
            arena_size,
            python,
            bps: HashMap::new(),
            stepping: HashMap::new(),
            pending: HashMap::new(),
            attach_break_seen: false,
            disarmed: false,
            hits: 0,
        }
    }

    fn arm(&mut self, io: &mut dyn DebugIo, addr: u64, entry: bool) -> bool {
        if let Some(bp) = self.bps.get_mut(&addr) {
            if !entry {
                bp.waiters += 1;
            }
            if !bp.armed && !self.stepping.values().any(|&a| a == addr) {
                bp.armed = io.write_byte(addr, INT3);
            }
            return true;
        }
        let Some(orig) = io.read_byte(addr) else {
            return false;
        };
        if orig == INT3 {
            // Someone else's breakpoint (or ours, lost): do not stack on it.
            return false;
        }
        let armed = io.write_byte(addr, INT3);
        self.bps.insert(
            addr,
            Bp {
                orig,
                armed,
                waiters: u32::from(!entry),
                entry,
            },
        );
        armed
    }

    /// Arm the `VirtualAlloc` breakpoint. False if it could not be written.
    pub fn start(&mut self, io: &mut dyn DebugIo) -> bool {
        let e = self.entry;
        self.arm(io, e, true)
    }

    /// Step `tid` over the breakpoint at `addr` (it just trapped there).
    fn step_over(&mut self, io: &mut dyn DebugIo, tid: u32, addr: u64, rearm: bool) {
        if let Some(bp) = self.bps.get_mut(&addr) {
            if bp.armed {
                io.write_byte(addr, bp.orig);
                bp.armed = false;
            }
        }
        io.set_rip(tid, addr);
        if rearm && !self.disarmed {
            io.set_trap(tid, true);
            self.stepping.insert(tid, addr);
        }
    }

    pub fn handle(&mut self, io: &mut dyn DebugIo, ev: Event) -> Reply {
        match ev {
            Event::ExitProcess => Reply::Exited,
            Event::Other => Reply::Handled,
            Event::Exception { .. } => Reply::NotHandled,
            Event::SingleStep { tid } => match self.stepping.remove(&tid) {
                Some(addr) => {
                    io.set_trap(tid, false);
                    let keep = !self.disarmed
                        && self
                            .bps
                            .get(&addr)
                            .is_some_and(|b| b.entry || b.waiters > 0);
                    if keep {
                        if let Some(bp) = self.bps.get_mut(&addr) {
                            bp.armed = io.write_byte(addr, INT3);
                        }
                    }
                    Reply::Handled
                }
                None => Reply::NotHandled,
            },
            Event::Breakpoint { tid, addr } => {
                if !self.bps.contains_key(&addr) {
                    if !self.attach_break_seen {
                        self.attach_break_seen = true;
                        return Reply::Handled;
                    }
                    return Reply::NotHandled;
                }
                if self.disarmed {
                    // A thread trapped just before we removed the byte.
                    io.set_rip(tid, addr);
                    return Reply::Handled;
                }
                self.hits += 1;
                let is_entry = self.bps[&addr].entry;
                if is_entry {
                    if let Some(r) = io.regs(tid) {
                        let ret = io.read_u64(r.rsp).unwrap_or(0);
                        let arena = r.rcx == 0
                            && r.rdx == self.arena_size
                            && r.r8 & (MEM_COMMIT | MEM_RESERVE) == MEM_COMMIT | MEM_RESERVE
                            && (self.python.0..self.python.1).contains(&ret);
                        if arena && !self.pending.contains_key(&tid) {
                            io.arena_entry(tid, self.arena_size, ret);
                            if self.arm(io, ret, false) {
                                self.pending.insert(tid, ret);
                            } else {
                                io.arena_exit(tid, 0);
                            }
                        }
                    }
                    self.step_over(io, tid, addr, true);
                } else {
                    let mine = self.pending.get(&tid) == Some(&addr);
                    if mine {
                        self.pending.remove(&tid);
                        let rax = io.regs(tid).map_or(0, |r| r.rax);
                        io.arena_exit(tid, rax);
                        if let Some(bp) = self.bps.get_mut(&addr) {
                            bp.waiters = bp.waiters.saturating_sub(1);
                        }
                    }
                    let still = self.bps.get(&addr).is_some_and(|b| b.waiters > 0);
                    self.step_over(io, tid, addr, still);
                    if !still {
                        self.bps.remove(&addr);
                    }
                }
                Reply::Handled
            }
        }
    }

    /// Remove every breakpoint and trap flag. See the module docs.
    pub fn disarm(&mut self, io: &mut dyn DebugIo) {
        self.disarmed = true;
        for (&addr, bp) in &mut self.bps {
            if bp.armed {
                io.write_byte(addr, bp.orig);
                bp.armed = false;
            }
        }
        for (tid, _) in self.stepping.drain() {
            io.set_trap(tid, false);
        }
        for (tid, _) in std::mem::take(&mut self.pending) {
            io.arena_exit(tid, 0);
        }
    }

    /// The attach breakpoint has been seen: the initial burst of thread
    /// events is over.
    pub fn attach_break_seen(&self) -> bool {
        self.attach_break_seen
    }

    /// Every byte the machine wrote has its original value back.
    pub fn is_clean(&self) -> bool {
        self.bps.values().all(|b| !b.armed) && self.stepping.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u64 = 0x7ff0_0000;
    const PY: (u64, u64) = (0x1000_0000, 0x1100_0000);
    const RET: u64 = 0x1000_1234;
    const ARENA: u64 = 1 << 20;

    #[derive(Default)]
    struct Fake {
        mem: HashMap<u64, u8>,
        stack: HashMap<u64, u64>,
        regs: HashMap<u32, Regs>,
        trap: HashMap<u32, bool>,
        entries: Vec<(u32, u64, u64)>,
        exits: Vec<(u32, u64)>,
    }

    impl DebugIo for Fake {
        fn read_byte(&mut self, a: u64) -> Option<u8> {
            Some(*self.mem.get(&a).unwrap_or(&0x55))
        }
        fn write_byte(&mut self, a: u64, b: u8) -> bool {
            self.mem.insert(a, b);
            true
        }
        fn read_u64(&mut self, a: u64) -> Option<u64> {
            self.stack.get(&a).copied()
        }
        fn regs(&mut self, t: u32) -> Option<Regs> {
            self.regs.get(&t).copied()
        }
        fn set_rip(&mut self, t: u32, rip: u64) -> bool {
            self.regs.entry(t).or_default().rip = rip;
            true
        }
        fn set_trap(&mut self, t: u32, on: bool) -> bool {
            self.trap.insert(t, on);
            true
        }
        fn arena_entry(&mut self, t: u32, s: u64, r: u64) {
            self.entries.push((t, s, r));
        }
        fn arena_exit(&mut self, t: u32, a: u64) {
            self.exits.push((t, a));
        }
    }

    fn call(f: &mut Fake, tid: u32, size: u64, ret: u64) {
        f.stack.insert(0x5000 + tid as u64, ret);
        f.regs.insert(
            tid,
            Regs {
                rip: VA + 1,
                rsp: 0x5000 + tid as u64,
                rcx: 0,
                rdx: size,
                r8: MEM_COMMIT | MEM_RESERVE,
                ..Regs::default()
            },
        );
    }

    #[test]
    fn arena_call_entry_and_return() {
        let mut f = Fake::default();
        let mut m = Machine::new(VA, ARENA, PY);
        assert!(m.start(&mut f));
        assert_eq!(f.mem[&VA], INT3);
        // The attach breakpoint is handled; a later foreign one is not.
        assert_eq!(
            m.handle(&mut f, Event::Breakpoint { tid: 9, addr: 0x42 }),
            Reply::Handled
        );
        assert_eq!(
            m.handle(&mut f, Event::Breakpoint { tid: 9, addr: 0x42 }),
            Reply::NotHandled
        );

        call(&mut f, 1, ARENA, RET);
        assert_eq!(
            m.handle(&mut f, Event::Breakpoint { tid: 1, addr: VA }),
            Reply::Handled
        );
        assert_eq!(f.entries, [(1, ARENA, RET)]);
        assert_eq!(f.mem[&VA], 0x55, "stepping over: original byte back");
        assert_eq!(f.regs[&1].rip, VA, "rip rewound to the breakpoint");
        assert!(f.trap[&1]);
        assert_eq!(f.mem[&RET], INT3, "return breakpoint set");
        assert_eq!(
            m.handle(&mut f, Event::SingleStep { tid: 1 }),
            Reply::Handled
        );
        assert_eq!(f.mem[&VA], INT3, "re-armed");
        assert!(!f.trap[&1]);

        f.regs.get_mut(&1).unwrap().rax = 0xabc0_0000;
        assert_eq!(
            m.handle(&mut f, Event::Breakpoint { tid: 1, addr: RET }),
            Reply::Handled
        );
        assert_eq!(f.exits, [(1, 0xabc0_0000)]);
        assert_eq!(f.mem[&RET], 0x55, "return breakpoint removed");
        assert_eq!(f.regs[&1].rip, RET);
        assert!(m.stepping.is_empty());
        assert_eq!(m.hits, 2);
    }

    #[test]
    fn other_calls_are_stepped_over_without_samples() {
        let mut f = Fake::default();
        let mut m = Machine::new(VA, ARENA, PY);
        m.start(&mut f);
        call(&mut f, 1, 4096, RET); // wrong size
        m.handle(&mut f, Event::Breakpoint { tid: 1, addr: VA });
        m.handle(&mut f, Event::SingleStep { tid: 1 });
        call(&mut f, 2, ARENA, 0x9999); // not from the Python DLL
        m.handle(&mut f, Event::Breakpoint { tid: 2, addr: VA });
        m.handle(&mut f, Event::SingleStep { tid: 2 });
        assert!(f.entries.is_empty());
        assert_eq!(f.mem[&VA], INT3);
        assert_eq!(
            m.handle(&mut f, Event::Exception { tid: 1 }),
            Reply::NotHandled
        );
        assert_eq!(
            m.handle(&mut f, Event::SingleStep { tid: 7 }),
            Reply::NotHandled
        );
    }

    #[test]
    fn return_breakpoint_shared_by_two_threads() {
        let mut f = Fake::default();
        let mut m = Machine::new(VA, ARENA, PY);
        m.start(&mut f);
        call(&mut f, 1, ARENA, RET);
        m.handle(&mut f, Event::Breakpoint { tid: 1, addr: VA });
        m.handle(&mut f, Event::SingleStep { tid: 1 });
        call(&mut f, 2, ARENA, RET);
        m.handle(&mut f, Event::Breakpoint { tid: 2, addr: VA });
        m.handle(&mut f, Event::SingleStep { tid: 2 });
        // Thread 1 returns: the breakpoint stays for thread 2.
        m.handle(&mut f, Event::Breakpoint { tid: 1, addr: RET });
        assert!(f.trap[&1]);
        m.handle(&mut f, Event::SingleStep { tid: 1 });
        assert_eq!(f.mem[&RET], INT3);
        // A third thread passing the return site without a pending call.
        f.regs.insert(3, Regs::default());
        m.handle(&mut f, Event::Breakpoint { tid: 3, addr: RET });
        m.handle(&mut f, Event::SingleStep { tid: 3 });
        assert_eq!(f.exits.len(), 1);
        m.handle(&mut f, Event::Breakpoint { tid: 2, addr: RET });
        assert_eq!(f.exits.len(), 2);
        assert_eq!(f.mem[&RET], 0x55);
    }

    #[test]
    fn disarm_restores_everything() {
        let mut f = Fake::default();
        let mut m = Machine::new(VA, ARENA, PY);
        m.start(&mut f);
        call(&mut f, 1, ARENA, RET);
        m.handle(&mut f, Event::Breakpoint { tid: 1, addr: VA });
        // Thread 1 is mid-step, return breakpoint armed, call pending.
        m.disarm(&mut f);
        assert_eq!(f.mem[&VA], 0x55);
        assert_eq!(f.mem[&RET], 0x55);
        assert!(!f.trap[&1]);
        assert_eq!(f.exits, [(1, 0)]);
        assert!(m.is_clean());
        // A late hit on a removed breakpoint is rewound, not reported.
        f.regs.insert(2, Regs::default());
        assert_eq!(
            m.handle(&mut f, Event::Breakpoint { tid: 2, addr: VA }),
            Reply::Handled
        );
        assert_eq!(f.regs[&2].rip, VA);
        assert_eq!(
            m.handle(&mut f, Event::SingleStep { tid: 1 }),
            Reply::NotHandled
        );
        assert_eq!(m.handle(&mut f, Event::ExitProcess), Reply::Exited);
    }

    #[test]
    fn existing_int3_is_left_alone() {
        let mut f = Fake::default();
        f.mem.insert(VA, INT3);
        let mut m = Machine::new(VA, ARENA, PY);
        assert!(!m.start(&mut f));
    }
}
