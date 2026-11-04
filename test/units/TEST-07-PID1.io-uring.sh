#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# NSS modules built with ASan can fail to load in the unsanitized Python process.
if [[ -v ASAN_OPTIONS ]]; then
    echo "ASan NSS modules cannot be loaded reliably by python3, skipping" >&2
    exit 77
fi

if ! command -v python3 >/dev/null; then
    echo "python3 not available, skipping" >&2
    exit 77
fi

HELPER="$(mktemp /var/tmp/io-uring-XXXXXX.py)"
WORKDIR="$(mktemp -d /var/tmp/io-uring-XXXXXX)"
chmod 0755 "$WORKDIR"
chmod 0644 "$HELPER"

at_exit() {
    set +e
    rm -rf "$HELPER" "$WORKDIR"
}

trap at_exit EXIT

# The helper submits a single io_uring request and prints the result of its completion, which is a negative
# errno number on failure. If io_uring_setup() fails, the helper prints "setup" and the negative errno number.
cat >"$HELPER" <<'EOF'
import ctypes
import mmap
import os
import socket
import struct
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

NR_IO_URING_SETUP = 425
NR_IO_URING_ENTER = 426
NR_IO_URING_REGISTER = 427
IORING_REGISTER_BPF_FILTER = 37
IORING_ENTER_GETEVENTS = 1
IORING_OFF_SQ_RING = 0
IORING_OFF_CQ_RING = 0x8000000
IORING_OFF_SQES = 0x10000000

IORING_OP_NOP = 0
IORING_OP_FSYNC = 3
IORING_OP_READV = 1
IORING_OP_OPENAT = 18
IORING_OP_OPENAT2 = 28
IORING_OP_SOCKET = 45

class Params(ctypes.Structure):
    _fields_ = [
        ("sq_entries", ctypes.c_uint32),
        ("cq_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("sq_thread_cpu", ctypes.c_uint32),
        ("sq_thread_idle", ctypes.c_uint32),
        ("features", ctypes.c_uint32),
        ("wq_fd", ctypes.c_uint32),
        ("resv", ctypes.c_uint32 * 3),
        ("sq_off", ctypes.c_uint32 * 10),
        ("cq_off", ctypes.c_uint32 * 10),
    ]

def u32(m, offset):
    return struct.unpack_from("=I", m, offset)[0]

def submit(opcode, fd=0, off=0, addr=0, length=0, op_flags=0):
    params = Params()
    ring = libc.syscall(NR_IO_URING_SETUP, 1, ctypes.byref(params))
    if ring < 0:
        print(f"setup {-ctypes.get_errno()}")
        return

    sq_off, cq_off = params.sq_off, params.cq_off
    sq = mmap.mmap(ring, sq_off[6] + params.sq_entries * 4, offset=IORING_OFF_SQ_RING)
    cq = mmap.mmap(ring, cq_off[5] + params.cq_entries * 16, offset=IORING_OFF_CQ_RING)
    sqes = mmap.mmap(ring, params.sq_entries * 64, offset=IORING_OFF_SQES)

    tail = u32(sq, sq_off[1])
    index = tail & u32(sq, sq_off[2])
    struct.pack_into("=BBHiQQIIQHHiQQ", sqes, index * 64,
                     opcode, 0, 0, fd, off, addr, length, op_flags, 0, 0, 0, 0, 0, 0)
    struct.pack_into("=I", sq, sq_off[6] + index * 4, index)
    struct.pack_into("=I", sq, sq_off[1], tail + 1)

    if libc.syscall(NR_IO_URING_ENTER, ring, 1, 1, IORING_ENTER_GETEVENTS, None, 0) < 0:
        sys.exit(f"io_uring_enter() failed: {os.strerror(ctypes.get_errno())}")

    head = u32(cq, cq_off[0])
    _, res, _ = struct.unpack_from("=QiI", cq, cq_off[5] + (head & u32(cq, cq_off[2])) * 16)
    print(res)

command = sys.argv[1]
if command == "probe":
    # The kernel reads the filter only after it checked that it supports task filters.
    r = libc.syscall(NR_IO_URING_REGISTER, -1, IORING_REGISTER_BPF_FILTER, None, 1)
    print("supported" if r < 0 and ctypes.get_errno() == 14 else "unsupported")
elif command == "nop":
    submit(IORING_OP_NOP)
elif command == "fsync":
    submit(IORING_OP_FSYNC, fd=os.open(sys.argv[2], os.O_RDONLY | os.O_CLOEXEC))
elif command == "readv":
    fd = os.open(sys.argv[2], os.O_RDONLY | os.O_CLOEXEC)
    buf = ctypes.create_string_buffer(1)
    class IOVec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
    iov = IOVec(ctypes.addressof(buf), 1)
    submit(IORING_OP_READV, fd=fd, addr=ctypes.addressof(iov), length=1)
elif command == "socket":
    family = {"unix": socket.AF_UNIX, "inet": socket.AF_INET, "inet6": socket.AF_INET6}[sys.argv[2]]
    submit(IORING_OP_SOCKET, fd=family, off=socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
elif command in ("openat", "openat2"):
    path = ctypes.create_string_buffer(sys.argv[2].encode())
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    mode = int(sys.argv[3], 8)
    if command == "openat":
        submit(IORING_OP_OPENAT, fd=-100, addr=ctypes.addressof(path), length=mode, op_flags=flags)
    else:
        how = ctypes.create_string_buffer(struct.pack("=QQQ", flags, mode, 0))
        submit(IORING_OP_OPENAT2, fd=-100, off=ctypes.addressof(how), addr=ctypes.addressof(path), length=24)
else:
    sys.exit(f"Unknown command {command}")
EOF

run() {
    systemd-run --wait --pipe --quiet "$@"
}

# LimitNPROC= counts every process with the same UID, so the test needs a separate user.
run -p DynamicUser=yes -p User=io-uring-limits -p LimitNPROC=1 -p RestrictAddressFamilies=AF_UNIX true
run -p TasksMax=1 -p RestrictAddressFamilies=AF_UNIX true

if [[ "$(run python3 "$HELPER" probe)" != "supported" ]]; then
    # Without io_uring BPF filters, IOUringFilter= denies io_uring_setup() with ENOSYS.
    [[ "$(run -p IOUringFilter=~nop python3 "$HELPER" nop)" == "setup -38" ]]
    echo "kernel does not support io_uring BPF filters, skipping" >&2
    exit 77
fi

EACCES=-13

[[ "$(run python3 "$HELPER" nop)" == 0 ]]
(( $(run python3 "$HELPER" socket inet) >= 0 ))

# RestrictAddressFamilies= applies to IORING_OP_SOCKET.
[[ "$(run -p RestrictAddressFamilies=AF_UNIX python3 "$HELPER" socket inet)" == "$EACCES" ]]
[[ "$(run -p RestrictAddressFamilies=AF_UNIX python3 "$HELPER" socket inet6)" == "$EACCES" ]]
(( $(run -p RestrictAddressFamilies=AF_UNIX python3 "$HELPER" socket unix) >= 0 ))
[[ "$(run -p RestrictAddressFamilies=~AF_INET python3 "$HELPER" socket inet)" == "$EACCES" ]]
(( $(run -p RestrictAddressFamilies=~AF_INET python3 "$HELPER" socket inet6) >= 0 ))

# RestrictSUIDSGID= applies to IORING_OP_OPENAT and IORING_OP_OPENAT2.
for op in openat openat2; do
    [[ "$(run -p RestrictSUIDSGID=yes python3 "$HELPER" "$op" "$WORKDIR/suid-$op" 4755)" == "$EACCES" ]]
    [[ "$(run -p RestrictSUIDSGID=yes python3 "$HELPER" "$op" "$WORKDIR/sgid-$op" 2755)" == "$EACCES" ]]
    (( $(run -p RestrictSUIDSGID=yes python3 "$HELPER" "$op" "$WORKDIR/plain-$op" 0755) >= 0 ))
    (( $(run python3 "$HELPER" "$op" "$WORKDIR/suid-$op" 4755) >= 0 ))
done

# SystemCallFilter= applies to the io_uring operations that can do the work of the denied system calls.
# The cases set SystemCallErrorNumber=, because python3 itself can make a system call that the filter denies.
# With the default action, the filter would kill python3 before the helper prints the result.
[[ "$(run -p SystemCallFilter=~socket -p SystemCallErrorNumber=EPERM python3 "$HELPER" socket unix)" == "$EACCES" ]]
[[ "$(run -p SystemCallFilter=~socket -p SystemCallErrorNumber=EPERM python3 "$HELPER" nop)" == 0 ]]
(( $(run -p SystemCallFilter=@system-service -p SystemCallErrorNumber=EPERM python3 "$HELPER" socket unix) >= 0 ))
[[ "$(run -p SystemCallFilter=@system-service -p SystemCallFilter=~@network-io -p SystemCallErrorNumber=EPERM python3 "$HELPER" socket unix)" == "$EACCES" ]]
# An allow list denies system calls that are listed with an error number.
[[ "$(run -p SystemCallFilter=@system-service -p SystemCallFilter=~socket:EPERM -p SystemCallErrorNumber=EPERM python3 "$HELPER" socket unix)" == "$EACCES" ]]
# The dynamic loader uses pread64(), so denying preadv() lets Python start.
[[ "$(run python3 "$HELPER" readv /dev/null)" == 0 ]]
[[ "$(run -p SystemCallFilter=~preadv -p SystemCallErrorNumber=EPERM python3 "$HELPER" readv /dev/null)" == "$EACCES" ]]
# A system call that is denied with an error number of 0 pretends to succeed, which io_uring can't do.
[[ "$(run -p SystemCallFilter=~fsync -p SystemCallErrorNumber=EPERM python3 "$HELPER" fsync "$HELPER")" == "$EACCES" ]]
[[ "$(run -p SystemCallFilter=~fsync:0 python3 "$HELPER" fsync "$HELPER")" == 0 ]]
[[ "$(run -p SystemCallFilter=~io_uring_setup -p SystemCallErrorNumber=ENOSYS python3 "$HELPER" nop)" == "setup -38" ]]

# IOUringFilter= works as a deny list and as an allow list.
[[ "$(run -p IOUringFilter=~nop python3 "$HELPER" nop)" == "$EACCES" ]]
(( $(run -p IOUringFilter=~nop python3 "$HELPER" socket unix) >= 0 ))
[[ "$(run -p IOUringFilter=nop python3 "$HELPER" nop)" == 0 ]]
[[ "$(run -p IOUringFilter=nop python3 "$HELPER" socket unix)" == "$EACCES" ]]
[[ "$(run -p IOUringFilter=nop -p IOUringFilter=~nop python3 "$HELPER" nop)" == "$EACCES" ]]
[[ "$(run -p IOUringFilter=~nop -p IOUringFilter= python3 "$HELPER" nop)" == 0 ]]

# Services that run as an unprivileged user get the filters as well.
[[ "$(run -p User=testuser -p IOUringFilter=~nop python3 "$HELPER" nop)" == "$EACCES" ]]
[[ "$(run -p User=testuser -p RestrictAddressFamilies=AF_UNIX python3 "$HELPER" socket inet)" == "$EACCES" ]]

# The property is visible over D-Bus.
systemd-run --unit=io-uring-filter-test --remain-after-exit -p IOUringFilter="~uring_cmd socket" true
[[ "$(systemctl show -P IOUringFilter io-uring-filter-test.service)" == "~socket uring_cmd" ]]
systemctl stop io-uring-filter-test.service
