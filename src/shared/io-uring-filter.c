/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/io_uring/bpf_filter.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "af-list.h"
#include "coredump-util.h"
#include "errno-util.h"
#include "io-uring-filter.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "string-table.h"

static const char* const io_uring_op_table[IORING_OP_LAST] = {
        [IORING_OP_NOP]              = "nop",
        [IORING_OP_READV]            = "readv",
        [IORING_OP_WRITEV]           = "writev",
        [IORING_OP_FSYNC]            = "fsync",
        [IORING_OP_READ_FIXED]       = "read_fixed",
        [IORING_OP_WRITE_FIXED]      = "write_fixed",
        [IORING_OP_POLL_ADD]         = "poll_add",
        [IORING_OP_POLL_REMOVE]      = "poll_remove",
        [IORING_OP_SYNC_FILE_RANGE]  = "sync_file_range",
        [IORING_OP_SENDMSG]          = "sendmsg",
        [IORING_OP_RECVMSG]          = "recvmsg",
        [IORING_OP_TIMEOUT]          = "timeout",
        [IORING_OP_TIMEOUT_REMOVE]   = "timeout_remove",
        [IORING_OP_ACCEPT]           = "accept",
        [IORING_OP_ASYNC_CANCEL]     = "async_cancel",
        [IORING_OP_LINK_TIMEOUT]     = "link_timeout",
        [IORING_OP_CONNECT]          = "connect",
        [IORING_OP_FALLOCATE]        = "fallocate",
        [IORING_OP_OPENAT]           = "openat",
        [IORING_OP_CLOSE]            = "close",
        [IORING_OP_FILES_UPDATE]     = "files_update",
        [IORING_OP_STATX]            = "statx",
        [IORING_OP_READ]             = "read",
        [IORING_OP_WRITE]            = "write",
        [IORING_OP_FADVISE]          = "fadvise",
        [IORING_OP_MADVISE]          = "madvise",
        [IORING_OP_SEND]             = "send",
        [IORING_OP_RECV]             = "recv",
        [IORING_OP_OPENAT2]          = "openat2",
        [IORING_OP_EPOLL_CTL]        = "epoll_ctl",
        [IORING_OP_SPLICE]           = "splice",
        [IORING_OP_PROVIDE_BUFFERS]  = "provide_buffers",
        [IORING_OP_REMOVE_BUFFERS]   = "remove_buffers",
        [IORING_OP_TEE]              = "tee",
        [IORING_OP_SHUTDOWN]         = "shutdown",
        [IORING_OP_RENAMEAT]         = "renameat",
        [IORING_OP_UNLINKAT]         = "unlinkat",
        [IORING_OP_MKDIRAT]          = "mkdirat",
        [IORING_OP_SYMLINKAT]        = "symlinkat",
        [IORING_OP_LINKAT]           = "linkat",
        [IORING_OP_MSG_RING]         = "msg_ring",
        [IORING_OP_FSETXATTR]        = "fsetxattr",
        [IORING_OP_SETXATTR]         = "setxattr",
        [IORING_OP_FGETXATTR]        = "fgetxattr",
        [IORING_OP_GETXATTR]         = "getxattr",
        [IORING_OP_SOCKET]           = "socket",
        [IORING_OP_URING_CMD]        = "uring_cmd",
        [IORING_OP_SEND_ZC]          = "send_zc",
        [IORING_OP_SENDMSG_ZC]       = "sendmsg_zc",
        [IORING_OP_READ_MULTISHOT]   = "read_multishot",
        [IORING_OP_WAITID]           = "waitid",
        [IORING_OP_FUTEX_WAIT]       = "futex_wait",
        [IORING_OP_FUTEX_WAKE]       = "futex_wake",
        [IORING_OP_FUTEX_WAITV]      = "futex_waitv",
        [IORING_OP_FIXED_FD_INSTALL] = "fixed_fd_install",
        [IORING_OP_FTRUNCATE]        = "ftruncate",
        [IORING_OP_BIND]             = "bind",
        [IORING_OP_LISTEN]           = "listen",
        [IORING_OP_RECV_ZC]          = "recv_zc",
        [IORING_OP_EPOLL_WAIT]       = "epoll_wait",
        [IORING_OP_READV_FIXED]      = "readv_fixed",
        [IORING_OP_WRITEV_FIXED]     = "writev_fixed",
        [IORING_OP_PIPE]             = "pipe",
        [IORING_OP_NOP128]           = "nop128",
        [IORING_OP_URING_CMD128]     = "uring_cmd128",
};

DEFINE_STRING_TABLE_LOOKUP(io_uring_op, int);

/* Each opcode maps to the system calls that it can do the work of. An opcode that is missing here has no
 * system call equivalent, because it only manages the ring itself. */
static const char* const io_uring_op_syscalls_table[IORING_OP_LAST] = {
        [IORING_OP_READV]            = "readv\0preadv\0preadv2\0",
        [IORING_OP_WRITEV]           = "writev\0pwritev\0pwritev2\0",
        [IORING_OP_FSYNC]            = "fsync\0fdatasync\0",
        [IORING_OP_READ_FIXED]       = "read\0pread64\0",
        [IORING_OP_WRITE_FIXED]      = "write\0pwrite64\0",
        [IORING_OP_POLL_ADD]         = "poll\0ppoll\0ppoll_time64\0",
        [IORING_OP_SYNC_FILE_RANGE]  = "sync_file_range\0sync_file_range2\0",
        [IORING_OP_SENDMSG]          = "sendmsg\0",
        [IORING_OP_RECVMSG]          = "recvmsg\0",
        [IORING_OP_ACCEPT]           = "accept\0accept4\0",
        [IORING_OP_CONNECT]          = "connect\0",
        [IORING_OP_FALLOCATE]        = "fallocate\0",
        [IORING_OP_OPENAT]           = "open\0openat\0",
        [IORING_OP_CLOSE]            = "close\0",
        [IORING_OP_STATX]            = "statx\0",
        [IORING_OP_READ]             = "read\0pread64\0",
        [IORING_OP_WRITE]            = "write\0pwrite64\0",
        [IORING_OP_FADVISE]          = "fadvise64\0fadvise64_64\0arm_fadvise64_64\0",
        [IORING_OP_MADVISE]          = "madvise\0",
        [IORING_OP_SEND]             = "sendto\0",
        [IORING_OP_RECV]             = "recvfrom\0",
        [IORING_OP_OPENAT2]          = "openat2\0",
        [IORING_OP_EPOLL_CTL]        = "epoll_ctl\0",
        [IORING_OP_SPLICE]           = "splice\0",
        [IORING_OP_TEE]              = "tee\0",
        [IORING_OP_SHUTDOWN]         = "shutdown\0",
        [IORING_OP_RENAMEAT]         = "rename\0renameat\0renameat2\0",
        [IORING_OP_UNLINKAT]         = "unlink\0unlinkat\0rmdir\0",
        [IORING_OP_MKDIRAT]          = "mkdir\0mkdirat\0",
        [IORING_OP_SYMLINKAT]        = "symlink\0symlinkat\0",
        [IORING_OP_LINKAT]           = "link\0linkat\0",
        [IORING_OP_FSETXATTR]        = "fsetxattr\0",
        [IORING_OP_SETXATTR]         = "setxattr\0setxattrat\0",
        [IORING_OP_FGETXATTR]        = "fgetxattr\0",
        [IORING_OP_GETXATTR]         = "getxattr\0getxattrat\0",
        [IORING_OP_SOCKET]           = "socket\0",
        [IORING_OP_URING_CMD]        = "ioctl\0setsockopt\0getsockopt\0getsockname\0",
        [IORING_OP_SEND_ZC]          = "sendto\0",
        [IORING_OP_SENDMSG_ZC]       = "sendmsg\0",
        [IORING_OP_READ_MULTISHOT]   = "read\0",
        [IORING_OP_WAITID]           = "waitid\0",
        [IORING_OP_FUTEX_WAIT]       = "futex\0futex_time64\0",
        [IORING_OP_FUTEX_WAKE]       = "futex\0futex_time64\0",
        [IORING_OP_FUTEX_WAITV]      = "futex_waitv\0",
        [IORING_OP_FTRUNCATE]        = "ftruncate\0ftruncate64\0",
        [IORING_OP_BIND]             = "bind\0",
        [IORING_OP_LISTEN]           = "listen\0",
        [IORING_OP_RECV_ZC]          = "recvfrom\0",
        [IORING_OP_EPOLL_WAIT]       = "epoll_wait\0epoll_pwait\0epoll_pwait2\0",
        [IORING_OP_READV_FIXED]      = "readv\0preadv\0preadv2\0",
        [IORING_OP_WRITEV_FIXED]     = "writev\0pwritev\0pwritev2\0",
        [IORING_OP_PIPE]             = "pipe\0pipe2\0",
        [IORING_OP_URING_CMD128]     = "ioctl\0setsockopt\0getsockopt\0getsockname\0",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(io_uring_op_syscalls, int);

/* Filters load 32-bit words from struct io_uring_bpf_ctx in native byte order. Flags and mode of an open
 * request are 64-bit fields, and all bits that we check are in their lower half. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define LOW_WORD(offset) (offset)
#else
#  define LOW_WORD(offset) ((offset) + 4)
#endif

static int register_bpf_filter(int op, const struct sock_filter *insns, size_t n_insns, uint8_t pdu_size) {
        assert(op >= 0);
        assert(insns);
        assert(n_insns > 0);

        struct io_uring_bpf reg = {
                .cmd_type = IO_URING_BPF_CMD_FILTER,
                .filter = {
                        .opcode = op,
                        .filter_len = n_insns,
                        .pdu_size = pdu_size,
                        .filter_ptr = PTR_TO_UINT64(insns),
                },
        };

        /* With -1 as the ring file descriptor, the kernel attaches the filter to the calling task. Every
         * ring that the task or its children create afterwards copies the filters of the task. */
        return RET_NERRNO(syscall(__NR_io_uring_register, /* fd= */ -1, IORING_REGISTER_BPF_FILTER, &reg, /* nr_args= */ 1));
}

int io_uring_bpf_filter_supported(void) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        static int cached = -1;
        siginfo_t si;
        int r;

        if (cached >= 0)
                return cached;

        /* A seccomp filter of an outer service manager or container manager can kill the process on
         * io_uring_register(). We probe in a child process, so that only the child gets killed. */
        r = pidref_safe_fork("(sd-iouring)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* If a seccomp filter kills the process on io_uring_register(), the kernel writes a core
                 * dump. systemd-coredump then reports the kill as a crash of the probe process. The kernel
                 * writes no core dump for a process that isn't dumpable. */
                (void) set_dumpable(SUID_DUMP_DISABLE);

                r = proc_set_nnp();
                if (r < 0) {
                        log_debug_errno(r, "Failed to set no_new_privs in io_uring probe: %m");
                        _exit(EXIT_FAILURE);
                }

                /* The kernel reads the filter from the NULL pointer only after it checked that it supports
                 * task filters and that we may register them. EFAULT thus means that we can register
                 * filters. Kernels without task filters return EINVAL for the register opcode. Kernels
                 * before 6.2 return EBADF, because they look up the ring file descriptor first. A seccomp
                 * filter can return any error. */
                r = RET_NERRNO(syscall(__NR_io_uring_register, /* fd= */ -1, IORING_REGISTER_BPF_FILTER, /* arg= */ NULL, /* nr_args= */ 1));
                if (r != -EFAULT) {
                        log_debug_errno(r, "io_uring_register() did not fail with EFAULT, assuming that io_uring BPF filters are not supported: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        r = pidref_wait_for_terminate(&pidref, &si);
        if (r < 0)
                return r;
        if (IN_SET(si.si_code, CLD_KILLED, CLD_DUMPED) && si.si_status == SIGSYS) {
                log_debug("io_uring_register() killed the probe process, assuming that io_uring BPF filters are not supported.");
                return (cached = false);
        }
        if (si.si_code != CLD_EXITED)
                return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "io_uring probe terminated by signal %s.", signal_to_string(si.si_status));

        return (cached = si.si_status == EXIT_SUCCESS);
}

static const struct sock_filter deny_insns[] = {
        BPF_STMT(BPF_RET|BPF_K, 0),
};

int io_uring_restrict_ops(Set *ops, bool allow_list) {
        int r;

        /* The set contains opcodes plus one, so that it can contain IORING_OP_NOP. */

        for (int op = 0; op < IORING_OP_LAST; op++) {
                if (set_contains(ops, INT_TO_PTR(op + 1)) == allow_list)
                        continue;

                r = register_bpf_filter(op, deny_insns, ELEMENTSOF(deny_insns), /* pdu_size= */ 0);
                if (r == -EINVAL) {
                        /* The kernel rejects filters for opcodes it does not implement. Requests with an
                         * opcode that the kernel does not implement fail anyway. */
                        log_debug("Kernel does not implement io_uring opcode %i, not filtering it.", op);
                        continue;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to deny io_uring opcode %i: %m", op);
        }

        if (!allow_list)
                return 0;

        /* An allow list also has to deny the opcodes that the kernel implements but we don't know about.
         * Opcodes are numbered without gaps, so the first opcode that the kernel rejects ends the range. */
        for (int op = IORING_OP_LAST; op <= UINT8_MAX; op++) {
                r = register_bpf_filter(op, deny_insns, ELEMENTSOF(deny_insns), /* pdu_size= */ 0);
                if (r == -EINVAL)
                        break;
                if (r < 0)
                        return log_debug_errno(r, "Failed to deny io_uring opcode %i: %m", op);
        }

        return 0;
}

int io_uring_restrict_address_families(Set *address_families, bool allow_list) {
        /* The filter has a load, a comparison for each listed family, and two return statements. */
        struct sock_filter insns[AF_MAX + 3];
        size_t n_insns = 0, n_families = 0, i = 0;
        int r;

        /* af_max() is one more than the highest AF_* constant of sys/socket.h. All AF_* constants are
         * below AF_MAX, so insns has room for a comparison with every family below af_max(). */
        assert(af_max() <= AF_MAX);

        for (int af = 1; af < af_max(); af++)
                if (set_contains(address_families, INT_TO_PTR(af)))
                        n_families++;

        /* An empty deny list allows every address family. */
        if (!allow_list && n_families == 0)
                return 0;

        insns[n_insns++] = (struct sock_filter) BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct io_uring_bpf_ctx, socket.family));

        for (int af = 1; af < af_max(); af++) {
                if (!set_contains(address_families, INT_TO_PTR(af)))
                        continue;

                /* A match jumps over the remaining comparisons and over the return statement for unlisted
                 * families. */
                insns[n_insns++] = (struct sock_filter) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, af, n_families - i, 0);
                i++;
        }

        insns[n_insns++] = (struct sock_filter) BPF_STMT(BPF_RET|BPF_K, !allow_list);
        insns[n_insns++] = (struct sock_filter) BPF_STMT(BPF_RET|BPF_K, allow_list);

        r = register_bpf_filter(IORING_OP_SOCKET, insns, n_insns, sizeof_field(struct io_uring_bpf_ctx, socket));
        if (r < 0)
                return log_debug_errno(r, "Failed to restrict address families of io_uring sockets: %m");

        return 0;
}

int io_uring_restrict_suid_sgid(void) {
        int op, r;

        /* O_TMPFILE includes the O_DIRECTORY bit. The other bit of O_TMPFILE marks requests that create a
         * file. */
        static const struct sock_filter insns[] = {
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS, LOW_WORD(offsetof(struct io_uring_bpf_ctx, open.flags))),
                BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_CREAT|(O_TMPFILE & ~O_DIRECTORY), 1, 0),
                BPF_STMT(BPF_RET|BPF_K, 1),
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS, LOW_WORD(offsetof(struct io_uring_bpf_ctx, open.mode))),
                BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, S_ISUID|S_ISGID, 0, 1),
                BPF_STMT(BPF_RET|BPF_K, 0),
                BPF_STMT(BPF_RET|BPF_K, 1),
        };

        FOREACH_ARGUMENT(op, IORING_OP_OPENAT, IORING_OP_OPENAT2) {
                r = register_bpf_filter(op, insns, ELEMENTSOF(insns), sizeof_field(struct io_uring_bpf_ctx, open));
                if (r < 0)
                        return log_debug_errno(r, "Failed to restrict SUID/SGID files of io_uring opcode %i: %m", op);
        }

        return 0;
}
