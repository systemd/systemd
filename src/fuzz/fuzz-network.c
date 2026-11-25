/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "errno-util.h"
#include "fuzz-network.h"

#if defined(__x86_64__)
#  define FUZZ_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
#  define FUZZ_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
#  define FUZZ_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

#if defined(FUZZ_AUDIT_ARCH) && defined(__NR_socket)
_noreturn_ static void fuzz_network_violation(int sig, siginfo_t *si, void *ctx) {
        static const char msg[] =
                "fuzz: a fuzz target tried to create a non-AF_UNIX socket. Fuzzers must never touch the "
                "network: feed input via buffers, memfds, pipes, socketpair(AF_UNIX) or ptys, and replace "
                "send/bind code paths with test seams.\n";

        (void) sig;
        (void) si;
        (void) ctx;

        /* Only async-signal-safe calls here. abort() makes libFuzzer and the sanitizers report a crash
         * with a stack trace that points at the offending code path. */
        (void) write(STDERR_FILENO, msg, strlen(msg));
        abort();
}
#endif

/* Make network access impossible for the rest of the process lifetime: socket() and socketpair() with any
 * address family other than AF_UNIX raise SIGSYS (reported as a crash via fuzz_network_violation()), and
 * io_uring is refused with ENOSYS so that it cannot be used to create or connect sockets either. Fuzzers
 * that exercise code which talks to the network in production must call this first, and must additionally
 * be written so that such code paths are never reached (test seams, injected AF_UNIX socketpair fds,
 * direct calls into the parsers). The filter is a backstop that turns a mistake into a crash instead of
 * real traffic.
 *
 * Only system calls of the native architecture are filtered: the filter is inherited by the programs the
 * fuzzer runs, e.g. llvm-symbolizer, which the sanitizers start and which is an x86-64 binary also when
 * the fuzzer is built for i386. On i386 glibc multiplexes socket() and socketpair() through socketcall(2),
 * whose arguments seccomp cannot inspect, so only the direct socket(2) and socketpair(2) syscalls are
 * filtered there. On x86_64, the x32 ABI's socket() is not filtered either, nothing in a fuzzer uses it.
 * On other architectures than x86-64, i386 and aarch64, which fuzzers are not run on, no filter is
 * installed and this does nothing. */
void fuzz_forbid_network(void) {
        static bool installed = false;

        if (installed)
                return;

#if defined(FUZZ_AUDIT_ARCH) && defined(__NR_socket)
        struct sock_filter filter[] = {
                /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
                /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUZZ_AUDIT_ARCH, 1, 0),
                /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 4, 0),
                /* 5 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 3, 0),
                /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 1, 0),
                /* 7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                /* 8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
                /* 9 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
                /* 10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
                /* 11 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
                /* 12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
                .len = ELEMENTSOF(filter),
                .filter = filter,
        };
        struct sigaction sa = {
                .sa_sigaction = fuzz_network_violation,
                .sa_flags = SA_SIGINFO,
        };

        assert_se(sigaction(SIGSYS, &sa, NULL) >= 0);
        assert_se(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) >= 0);
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) < 0)
                /* Kernel without CONFIG_SECCOMP_FILTER, or qemu-user, which refuses seccomp. The filter is
                 * only a backstop, the fuzzer must not reach the network either way. */
                assert_se(errno == EINVAL);
#endif

        installed = true;
}

/* For fuzzers that feed data to code which receives it on a netlink socket: binds the AF_UNIX datagram
 * socket fd that the data is sent from to an abstract address that the receiver, which reads the address
 * of the sender as struct sockaddr_nl, sees as the given netlink port ID (0 for the kernel) and multicast
 * groups. nl_pad overlaps the first two bytes of sun_path and is zero, which makes the address abstract.
 * What follows nl_groups makes it unique. */
int fuzz_bind_netlink_address(int fd, uint32_t nl_pid, uint32_t nl_groups) {
        static unsigned counter = 0;
        struct {
                struct sockaddr_nl nl;
                char unique[sizeof(struct sockaddr_un) - sizeof(struct sockaddr_nl)];
        } address = {
                .nl.nl_family = AF_UNIX,
                .nl.nl_pid = nl_pid,
                .nl.nl_groups = nl_groups,
        };
        int n;

        n = snprintf(address.unique, sizeof(address.unique), "fuzz/%i/%u", (int) getpid(), counter++);
        assert(n > 0 && (size_t) n < sizeof(address.unique));

        return RET_NERRNO(bind(fd, (const struct sockaddr*) &address, sizeof(address.nl) + n));
}
