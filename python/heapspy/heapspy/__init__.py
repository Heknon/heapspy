"""Send memory profiles of this Python process to Pyroscope.

The same interface as Pyroscope's Python client (``pyroscope-io``)::

    import heapspy

    heapspy.configure(
        application_name="shop",
        server_address="http://pyroscope:4040",
        tags={"env": "prod"},
    )

``configure()`` starts ``heapspy agent`` for this process, in the
background: a separate process that reads this one's memory from outside
and sends the profiles. Nothing runs inside the interpreter, and by default
the process is never paused. The agent stops when this process exits, or
at ``shutdown()``.

What is sent (see ``heapspy agent --help``), each profile labelled
``heapspy_profile``:

- ``memory=True``: where the memory is (Python objects by size, pymalloc's
  free space, malloc's heaps, the rest of RSS), every ``upload_interval``
  seconds. Read from counters; never pauses the process.
- ``retained=True``: who holds the memory, a snapshot every
  ``retained_interval`` seconds. Approximate (Linux) unless ``stop=True``,
  which pauses the process for each snapshot.
- ``alloc=True``: which code allocates, sampled for ``alloc_duration``
  seconds every ``alloc_interval``. Needs eBPF (root, or CAP_BPF and
  CAP_PERFMON) on Linux, an elevated process on Windows.

The options of ``pyroscope.configure()`` that are about CPU profiling
(``sample_rate``, ``oncpu``, ``gil_only``, ...) are accepted, so the same
call works with either module, and ignored.
"""

import atexit
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import warnings

__all__ = ["configure", "is_running", "shutdown"]

LOGGER = logging.getLogger(__name__)

# The agent of this process: (Popen, the pid that started it). A child made
# by fork() sees its parent's and must not stop it.
_agent = None
_lock = threading.Lock()

# Yama's PR_SET_PTRACER (linux/prctl.h).
_PR_SET_PTRACER = 0x59616D61


def configure(
    app_name=None,
    application_name=None,
    server_address="http://localhost:4040",
    basic_auth_username="",
    basic_auth_password="",
    enable_logging=False,
    sample_rate=None,
    oncpu=None,
    native=None,
    gil_only=None,
    report_pid=None,
    report_thread_id=None,
    report_thread_name=None,
    tags=None,
    tenant_id="",
    http_headers=None,
    line_no=None,
    upload_interval=15,
    mem_enabled=None,
    mem_max_nframe=None,
    mem_heap_sample_size=None,
    mem_enable_mem_domain=None,
    cpu_enabled=None,
    cpu_implementation=None,
    *,
    memory=True,
    retained=False,
    retained_interval=300,
    stop=False,
    alloc=False,
    alloc_interval=300,
    alloc_duration=30,
):
    """Start sending memory profiles of this process to Pyroscope.

    Takes the arguments of ``pyroscope.configure()``. Used here:
    ``application_name`` (the ``service_name``; default the script or
    module name), ``server_address``, ``basic_auth_username`` and
    ``basic_auth_password``, ``tags``, ``tenant_id``, ``http_headers``,
    ``enable_logging`` (the agent's messages go to the ``heapspy``
    logger), ``upload_interval`` (seconds between memory profiles; 15
    matches Grafana's default minimal step). Every profile has a ``pid``
    label, as with ``report_pid``. The CPU options are ignored.

    The heapspy profiles, keyword only: ``memory`` (on), ``retained``
    with ``retained_interval`` and ``stop``, ``alloc`` with
    ``alloc_interval`` and ``alloc_duration``; intervals in seconds.

    Calling it again replaces the running agent. Returns True when the
    agent was started.
    """
    global _agent

    if app_name is not None:
        warnings.warn(
            "app_name is deprecated, use application_name", DeprecationWarning, stacklevel=2
        )
        application_name = application_name or app_name
    LOGGER.disabled = not enable_logging
    if not (memory or retained or alloc):
        raise ValueError("choose at least one of memory, retained, alloc")
    if stop and not retained:
        raise ValueError("stop=True is about retained snapshots: add retained=True")

    args = ["agent", "--server", str(server_address), "--pid", str(os.getpid())]
    if application_name:
        args += ["--app-name", str(application_name)]
    for key, value in (tags or {}).items():
        args += ["--tag", f"{_tag_key(key)}={value}"]
    if tenant_id:
        args += ["--tenant-id", str(tenant_id)]
    if memory:
        args += ["--memory", "--memory-every", _duration(upload_interval, "upload_interval")]
    if retained:
        args += [
            "--retained",
            "--retained-every",
            _duration(retained_interval, "retained_interval"),
        ]
        if stop:
            args.append("--stop")
    if alloc:
        args += [
            "--alloc",
            "--alloc-every",
            _duration(alloc_interval, "alloc_interval"),
            "--alloc-for",
            _duration(alloc_duration, "alloc_duration"),
        ]

    # Secrets go through the environment, never the command line, where
    # other users can read them.
    env = dict(os.environ)
    for name in (
        "HEAPSPY_PYROSCOPE_PASSWORD",
        "HEAPSPY_PYROSCOPE_TOKEN",
        "HEAPSPY_PYROSCOPE_HEADERS",
    ):
        env.pop(name, None)
    if basic_auth_username:
        args += ["--basic-auth-user", str(basic_auth_username)]
        env["HEAPSPY_PYROSCOPE_PASSWORD"] = str(basic_auth_password)
    if http_headers:
        env["HEAPSPY_PYROSCOPE_HEADERS"] = json.dumps(
            {str(k): str(v) for k, v in http_headers.items()}
        )

    args.insert(0, _executable())
    with _lock:
        _stop_agent()
        proc = _spawn(args, env)
        _agent = (proc, os.getpid())
    threading.Thread(target=_relay, args=(proc,), name="heapspy-agent-log", daemon=True).start()
    LOGGER.info("heapspy agent started (pid %d)", proc.pid)
    return True


def shutdown():
    """Stop the agent; it sends what it has collected first. Returns True
    when an agent was running."""
    with _lock:
        stopped = _stop_agent()
    if stopped:
        LOGGER.info("heapspy agent stopped")
    return stopped


def is_running():
    """Whether this process's agent is running."""
    agent = _agent
    return agent is not None and agent[1] == os.getpid() and agent[0].poll() is None


def _stop_agent(timeout=10.0):
    global _agent
    agent, _agent = _agent, None
    if agent is None:
        return False
    proc, owner = agent
    if owner != os.getpid() or proc.poll() is not None:
        return False
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except OSError:
        pass
    return True


def _spawn(args, env):
    if os.name == "nt":
        return subprocess.Popen(
            args,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    # Its own session: Ctrl+C in a terminal goes to the application, which
    # may handle it and carry on, not to the agent.
    common = {
        "env": env,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
        "start_new_session": True,
    }
    if _ptrace_scope() != 1 or os.geteuid() == 0:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL, **common)
    # Yama (ptrace_scope 1) lets a process read only its descendants, and
    # the agent is this process's child. Start it held behind a shell that
    # waits for a line, name it as the process allowed to read this one,
    # then let it exec the agent (same pid).
    proc = subprocess.Popen(
        ["/bin/sh", "-c", 'read _ && exec "$@"', "sh"] + args, stdin=subprocess.PIPE, **common
    )
    if not _allow_ptracer(proc.pid):
        LOGGER.warning(
            "could not allow the agent to read this process (prctl PR_SET_PTRACER failed)"
        )
    try:
        proc.stdin.write(b"\n")
        proc.stdin.close()
    except OSError:
        pass
    return proc


def _ptrace_scope():
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _allow_ptracer(pid):
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(_PR_SET_PTRACER, ctypes.c_ulong(pid), 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def _relay(proc):
    """The agent's messages, to the ``heapspy`` logger."""
    for raw in proc.stderr:
        line = raw.decode("utf-8", "replace").rstrip()
        if line:
            LOGGER.info("%s", line)
    code = proc.wait()
    if code not in (0, None) and not (os.name != "nt" and code == -signal.SIGTERM):
        LOGGER.warning("heapspy agent exited with status %s", code)


def _executable():
    """The ``heapspy`` binary installed with this package."""
    path = os.environ.get("HEAPSPY_BIN")
    if path:
        return path
    name = "heapspy.exe" if os.name == "nt" else "heapspy"
    candidates = [sysconfig.get_path("scripts")]
    if sys.version_info >= (3, 10):
        candidates.append(sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user")))
    for directory in candidates:
        if directory:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    found = shutil.which("heapspy")
    if found:
        return found
    raise RuntimeError(
        "the heapspy binary was not found: install the heapspy package, or set HEAPSPY_BIN"
    )


def _duration(seconds, what):
    try:
        ms = round(float(seconds) * 1000)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a number of seconds")
    if ms <= 0:
        raise ValueError(f"{what} must be more than zero")
    return f"{ms}ms"


def _tag_key(key):
    key = str(key)
    ok = key and all(c == "_" or c.isascii() and c.isalnum() for c in key) and not key[0].isdigit()
    if not ok:
        raise ValueError(
            f"bad tag key {key!r}: use letters, digits and _, not starting with a digit"
        )
    if key in ("__name__", "service_name", "pid", "heapspy_profile"):
        raise ValueError(f"tag {key!r} is set by heapspy")
    return key


atexit.register(shutdown)
