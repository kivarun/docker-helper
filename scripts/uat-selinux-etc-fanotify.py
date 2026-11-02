#!/usr/bin/env python3
"""Guest-only fanotify attribution for SELinux host-label UAT.

Observe FAN_ATTRIB on the filesystem containing /etc. No permission events,
mutations, or scanning; report only exact (st_dev, st_ino) targets.
"""
import argparse
import ctypes
import errno
import os
import select
import signal
import struct
import sys
import time

FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_MARK_ADD = 0x00000001
FAN_MARK_FILESYSTEM = 0x00000100
FAN_ATTRIB = 0x00000004
FAN_Q_OVERFLOW = 0x00004000
FAN_NOFD = -1
AT_FDCWD = -100
METADATA = struct.Struct("=IBBHQii")

stop = False

def stop_signal(_sig, _frame):
    global stop
    stop = True

def read_proc(pid, name):
    try:
        if name == "exe":
            return os.readlink("/proc/%s/exe" % pid)
        with open("/proc/%s/%s" % (pid, name), "rb") as f:
            return f.read(96).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except (OSError, ValueError):
        return "<exited-or-unavailable>"

def log(msg):
    print(msg, flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()

    targets = {}
    for p in ("/etc", "/etc/passwd", args.probe):
        st = os.stat(p)
        targets[(st.st_dev, st.st_ino)] = p

    libc = ctypes.CDLL(None, use_errno=True)
    libc.fanotify_init.argtypes = (ctypes.c_uint, ctypes.c_uint)
    libc.fanotify_init.restype = ctypes.c_int
    libc.fanotify_mark.argtypes = (
        ctypes.c_int, ctypes.c_uint, ctypes.c_ulonglong,
        ctypes.c_int, ctypes.c_char_p)
    libc.fanotify_mark.restype = ctypes.c_int
    fd = libc.fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY | os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init failed")
    if libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                         FAN_ATTRIB, AT_FDCWD, b"/etc") != 0:
        raise OSError(ctypes.get_errno(), "fanotify_mark(FILESYSTEM, /etc) failed")

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    with open(args.ready, "w", encoding="ascii") as out:
        out.write("READY\n")
    log("FANOTIFY_READY filesystem=/etc targets=" +
        ",".join("%s:%s=%s" % (*key, path) for key, path in targets.items()))

    poll = select.poll()
    poll.register(fd, select.POLLIN)
    while not stop:
        try:
            if not poll.poll(250):
                continue
            chunk = os.read(fd, 1 << 16)
        except BlockingIOError:
            continue
        except InterruptedError:
            continue
        if not chunk:
            continue
        offset = 0
        while offset + METADATA.size <= len(chunk):
            event_len, ver, _, metadata_len, mask, eventfd, pid = METADATA.unpack_from(chunk, offset)
            if event_len < METADATA.size or offset + event_len > len(chunk):
                log("FANOTIFY_FATAL malformed_event_len=%d" % event_len)
                return 2
            offset += event_len
            if mask & FAN_Q_OVERFLOW:
                log("FANOTIFY_OVERFLOW")
                return 2
            if eventfd == FAN_NOFD:
                continue
            try:
                st = os.fstat(eventfd)
                path = targets.get((st.st_dev, st.st_ino))
                if path:
                    try:
                        seen_as = os.readlink("/proc/self/fd/%d" % eventfd)
                    except OSError:
                        seen_as = "<unavailable>"
                    log("FANOTIFY_TARGET path=%s dev=%d inode=%d mask=%#x pid=%d comm=%s exe=%s via=%s" %
                        (path, st.st_dev, st.st_ino, mask, pid,
                         read_proc(pid, "comm"), read_proc(pid, "exe"), seen_as))
            finally:
                os.close(eventfd)
    log("FANOTIFY_CLEAN_EXIT")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        log("FANOTIFY_FATAL errno=%s message=%s" % (exc.errno, exc))
        sys.exit(2)
