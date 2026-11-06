//! Ending a recording early on Ctrl-C or SIGTERM.

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// A flag set by SIGINT and SIGTERM (Ctrl-C, Ctrl-Break and console close
/// on Windows), for [`crate::record`]'s `stop`. The first call installs
/// the handlers; the recording then ends cleanly, detaches, and writes a
/// profile flagged truncated. A second signal is handled the same way (the
/// default action is not restored), so detaching is never cut short; use
/// SIGKILL to end heapspy at once, which the kernel cleans up after too.
pub fn stop_on_signals() -> &'static AtomicBool {
    install();
    &STOP
}

#[cfg(unix)]
fn install() {
    extern "C" fn on_signal(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe.
    unsafe {
        let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
    }
}

#[cfg(windows)]
fn install() {
    use windows_sys::core::BOOL;
    unsafe extern "system" fn on_ctrl(_: u32) -> BOOL {
        STOP.store(true, Ordering::SeqCst);
        1
    }
    // SAFETY: registering a handler that only stores to an atomic.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

#[cfg(not(any(unix, windows)))]
fn install() {
    let _ = Ordering::SeqCst;
}
