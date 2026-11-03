/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/io_uring/bpf_filter.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "af-list.h"
#include "errno-util.h"
#include "io-uring-filter.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "set.h"

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
                (void) prctl(PR_SET_DUMPABLE, 0);

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

        r = pidref_wait_for_terminate_and_check("(sd-iouring)", &pidref, /* flags= */ 0);
        if (r == -EPROTO) {
                log_debug("io_uring_register() killed the probe process, assuming that io_uring BPF filters are not supported.");
                return (cached = false);
        }
        if (r < 0)
                return r;

        return (cached = r == EXIT_SUCCESS);
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
