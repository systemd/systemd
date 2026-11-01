/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "capability-util.h"
#include "errno-list.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "memory-util.h"
#include "nsflags.h"
#include "nulstr-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rm-rf.h"
#include "seccomp-util.h"
#include "set.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

/* __NR_socket may be invalid due to libseccomp */
#if !defined(__NR_socket) || __NR_socket < 0 || defined(__i386__) || defined(__s390x__) || defined(__s390__) || defined(__powerpc64__) || defined(__powerpc__)
/* On these archs, socket() is implemented via the socketcall() syscall multiplexer,
 * and we can't restrict it hence via seccomp. */
#  define SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN 1
#else
#  define SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN 0
#endif

#define CHECK_SECCOMP(refuse_container) \
        if (!is_seccomp_available())                                    \
                return (void) log_tests_skipped("Seccomp not available"); \
        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)   \
                return (void) log_tests_skipped("Not privileged");      \
        if (refuse_container && detect_container() > 0)                 \
                return (void) log_tests_skipped("Running in container");

TEST(parse_syscall_and_errno) {
        _cleanup_free_ char *n = NULL;
        int e;

        CHECK_SECCOMP(/* refuse_container= */ false);

        ASSERT_OK(parse_syscall_and_errno("uname:EILSEQ", &n, &e));
        ASSERT_STREQ(n, "uname");
        ASSERT_EQ(e, errno_from_name("EILSEQ"));
        ASSERT_GE(e, 0);
        n = mfree(n);

        ASSERT_OK(parse_syscall_and_errno("uname:EINVAL", &n, &e));
        ASSERT_STREQ(n, "uname");
        ASSERT_EQ(e, errno_from_name("EINVAL"));
        ASSERT_GE(e, 0);
        n = mfree(n);

        ASSERT_OK(parse_syscall_and_errno("@sync:4095", &n, &e));
        ASSERT_STREQ(n, "@sync");
        ASSERT_EQ(e, 4095);
        n = mfree(n);

        /* If errno is omitted, then e is set to -1 */
        ASSERT_OK(parse_syscall_and_errno("mount", &n, &e));
        ASSERT_STREQ(n, "mount");
        ASSERT_EQ(e, -1);
        n = mfree(n);

        /* parse_syscall_and_errno() does not check the syscall name is valid or not. */
        ASSERT_OK(parse_syscall_and_errno("hoge:255", &n, &e));
        ASSERT_STREQ(n, "hoge");
        ASSERT_EQ(e, 255);
        n = mfree(n);

        /* 0 is also a valid errno. */
        ASSERT_OK(parse_syscall_and_errno("hoge:0", &n, &e));
        ASSERT_STREQ(n, "hoge");
        ASSERT_EQ(e, 0);
        n = mfree(n);

        ASSERT_OK(parse_syscall_and_errno("hoge:kill", &n, &e));
        ASSERT_STREQ(n, "hoge");
        ASSERT_EQ(e, SECCOMP_ERROR_NUMBER_KILL);
        n = mfree(n);

        /* The function checks the syscall name is empty or not. */
        ASSERT_ERROR(parse_syscall_and_errno("", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno(":255", &n, &e), EINVAL);

        /* errno must be a valid errno name or number between 0 and ERRNO_MAX == 4095, or "kill" */
        ASSERT_ERROR(parse_syscall_and_errno("hoge:4096", &n, &e), ERANGE);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:-3", &n, &e), ERANGE);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:12.3", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:123junk", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:junk123", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:255:EILSEQ", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:-EINVAL", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:EINVALaaa", &n, &e), EINVAL);
        ASSERT_ERROR(parse_syscall_and_errno("hoge:", &n, &e), EINVAL);
}

TEST(seccomp_arch_to_string) {
        uint32_t a, b;
        const char *name;

        CHECK_SECCOMP(/* refuse_container= */ false);

        a = sym_seccomp_arch_native();
        ASSERT_GT(a, 0U);
        name = ASSERT_NOT_NULL(seccomp_arch_to_string(a));
        ASSERT_OK(seccomp_arch_from_string(name, &b));
        ASSERT_EQ(a, b);
}

TEST(architecture_table) {
        const char *n2;

        NULSTR_FOREACH(n,
                       "native\0"
                       "x86\0"
                       "x86-64\0"
                       "x32\0"
                       "arm\0"
                       "arm64\0"
#ifdef SCMP_ARCH_LOONGARCH64
                       "loongarch64\0"
#endif
                       "mips\0"
                       "mips64\0"
                       "mips64-n32\0"
                       "mips-le\0"
                       "mips64-le\0"
                       "mips64-le-n32\0"
                       "parisc\0"
                       "parisc64\0"
                       "ppc\0"
                       "ppc64\0"
                       "ppc64-le\0"
#ifdef SCMP_ARCH_RISCV64
                       "riscv64\0"
#endif
                       "s390\0"
                       "s390x\0") {
                uint32_t c;

                ASSERT_OK(seccomp_arch_from_string(n, &c));
                n2 = seccomp_arch_to_string(c);
                log_info("seccomp-arch: %s → 0x%"PRIx32" → %s", n, c, n2);
                ASSERT_STREQ(n, n2);
        }
}

TEST(syscall_filter_set_find) {
        ASSERT_NULL(syscall_filter_set_find(/* name= */ NULL));
        ASSERT_NULL(syscall_filter_set_find(""));
        ASSERT_NULL(syscall_filter_set_find("quux"));
        ASSERT_NULL(syscall_filter_set_find("@quux"));

        ASSERT_PTR_EQ(syscall_filter_set_find("@clock"), syscall_filter_sets + SYSCALL_FILTER_SET_CLOCK);
        ASSERT_PTR_EQ(syscall_filter_set_find("@default"), syscall_filter_sets + SYSCALL_FILTER_SET_DEFAULT);
        ASSERT_PTR_EQ(syscall_filter_set_find("@raw-io"), syscall_filter_sets + SYSCALL_FILTER_SET_RAW_IO);
}

TEST(filter_sets) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        for (unsigned i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {

#if HAVE_VALGRIND_VALGRIND_H
                if (RUNNING_ON_VALGRIND && IN_SET(i, SYSCALL_FILTER_SET_DEFAULT, SYSCALL_FILTER_SET_BASIC_IO, SYSCALL_FILTER_SET_SIGNAL)) {
                        /* valgrind at least requires rt_sigprocmask(), read(), write(). */
                        log_info("Running on valgrind, skipping %s", syscall_filter_sets[i].name);
                        continue;
                }
#endif
#if HAS_FEATURE_ADDRESS_SANITIZER
                if (IN_SET(i, SYSCALL_FILTER_SET_DEFAULT, SYSCALL_FILTER_SET_BASIC_IO, SYSCALL_FILTER_SET_SIGNAL)) {
                        /* ASAN at least requires sigaltstack(), read(), write(). */
                        log_info("Running on address sanitizer, skipping %s", syscall_filter_sets[i].name);
                        continue;
                }
#endif

                log_info("Testing %s", syscall_filter_sets[i].name);

                r = ASSERT_OK(pidref_safe_fork("(filter_sets)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
                if (r == 0) {
                        int fd;

                        /* If we look at the default set (or one that includes it), allow-list instead of deny-list */
                        if (IN_SET(i, SYSCALL_FILTER_SET_DEFAULT,
                                      SYSCALL_FILTER_SET_SYSTEM_SERVICE,
                                      SYSCALL_FILTER_SET_KNOWN))
                                r = seccomp_load_syscall_filter_set(SCMP_ACT_ERRNO(EUCLEAN), syscall_filter_sets + i, SCMP_ACT_ALLOW, /* log_missing= */ true);
                        else
                                r = seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + i, SCMP_ACT_ERRNO(EUCLEAN), /* log_missing= */ true);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        /* Test the sycall filter with one random system call */
                        fd = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC);
                        if (IN_SET(i, SYSCALL_FILTER_SET_IO_EVENT, SYSCALL_FILTER_SET_DEFAULT))
                                ASSERT_ERROR_ERRNO(fd, EUCLEAN);
                        else {
                                ASSERT_OK_ERRNO(fd);
                                safe_close(fd);
                        }

                        _exit(EXIT_SUCCESS);
                }
        }
}

TEST(filter_sets_ordered) {
        /* Ensure "@default" always remains at the beginning of the list */
        ASSERT_EQ(SYSCALL_FILTER_SET_DEFAULT, 0);
        ASSERT_STREQ(syscall_filter_sets[0].name, "@default");

        /* Ensure "@known" always remains at the end of the list */
        ASSERT_EQ(SYSCALL_FILTER_SET_KNOWN, _SYSCALL_FILTER_SET_MAX - 1);
        ASSERT_STREQ(syscall_filter_sets[SYSCALL_FILTER_SET_KNOWN].name, "@known");

        for (size_t i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                const char *p = NULL;

                /* Make sure each group has a description */
                ASSERT_FALSE(isempty(syscall_filter_sets[0].help));

                /* Make sure the groups are ordered alphabetically, except for the first and last entries */
                ASSERT_TRUE(i < 2 || i == _SYSCALL_FILTER_SET_MAX - 1 ||
                            strcmp(syscall_filter_sets[i-1].name, syscall_filter_sets[i].name) < 0);

                NULSTR_FOREACH(k, syscall_filter_sets[i].value) {
                        /* Ensure each syscall list is in itself ordered, but groups before names */
                        ASSERT_TRUE(!p ||
                                    (*p == '@' && *k != '@') ||
                                    (((*p == '@' && *k == '@') ||
                                      (*p != '@' && *k != '@')) &&
                                     strcmp(p, k) < 0));

                        p = k;
                }
        }
}

TEST(restrict_namespace) {
        char *s = NULL;
        unsigned long ul;
        int r;

        if (!have_namespaces())
                return (void) log_tests_skipped("Testing without namespaces");

        ASSERT_OK_ZERO(namespace_flags_to_string(/* flags= */ 0, &s));
        ASSERT_TRUE(isempty(s));
        s = mfree(s);
        ASSERT_OK_ZERO(namespace_flags_to_string(CLONE_NEWNS, &s));
        ASSERT_STREQ(s, "mnt");
        s = mfree(s);
        ASSERT_OK_ZERO(namespace_flags_to_string(CLONE_NEWNS|CLONE_NEWIPC, &s));
        ASSERT_STREQ(s, "ipc mnt");
        s = mfree(s);
        ASSERT_OK_ZERO(namespace_flags_to_string(CLONE_NEWCGROUP, &s));
        ASSERT_STREQ(s, "cgroup");
        s = mfree(s);

        ASSERT_OK_ZERO(namespace_flags_from_string("mnt", &ul));
        ASSERT_EQ(ul, (unsigned long) CLONE_NEWNS);
        ASSERT_OK_ZERO(namespace_flags_from_string(/* name= */ NULL, &ul));
        ASSERT_EQ(ul, 0U);
        ASSERT_OK_ZERO(namespace_flags_from_string("", &ul));
        ASSERT_EQ(ul, 0U);
        ASSERT_OK_ZERO(namespace_flags_from_string("uts", &ul));
        ASSERT_EQ(ul, (unsigned long) CLONE_NEWUTS);
        ASSERT_OK_ZERO(namespace_flags_from_string("mnt uts ipc", &ul));
        ASSERT_EQ(ul, (unsigned long) (CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC));

        ASSERT_OK_ZERO(namespace_flags_to_string(CLONE_NEWUTS, &s));
        ASSERT_STREQ(s, "uts");
        ASSERT_OK_ZERO(namespace_flags_from_string(s, &ul));
        ASSERT_EQ(ul, (unsigned long) CLONE_NEWUTS);
        s = mfree(s);
        ASSERT_OK_ZERO(namespace_flags_from_string("ipc", &ul));
        ASSERT_EQ(ul, (unsigned long) CLONE_NEWIPC);
        ASSERT_OK_ZERO(namespace_flags_to_string(ul, &s));
        ASSERT_STREQ(s, "ipc");
        s = mfree(s);

        ASSERT_OK_ZERO(namespace_flags_to_string(NAMESPACE_FLAGS_ALL, &s));
        ASSERT_STREQ(s, "cgroup ipc net mnt pid user uts time");
        ASSERT_OK_ZERO(namespace_flags_from_string(s, &ul));
        ASSERT_EQ(ul, NAMESPACE_FLAGS_ALL);
        s = mfree(s);

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(restrict-namespace)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(seccomp_restrict_namespaces(CLONE_NEWNS|CLONE_NEWNET));

                ASSERT_OK_ZERO_ERRNO(unshare(CLONE_NEWNS));
                ASSERT_OK_ZERO_ERRNO(unshare(CLONE_NEWNET));
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWUTS), EPERM);
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWIPC), EPERM);
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWNET|CLONE_NEWUTS), EPERM);

                /* We use fd 0 (stdin) here, which of course will fail with EINVAL on setns(). Except of course our
                 * seccomp filter worked, and hits first and makes it return EPERM */
                ASSERT_ERROR_ERRNO(setns(0, CLONE_NEWNS), EINVAL);
                ASSERT_ERROR_ERRNO(setns(0, CLONE_NEWNET), EINVAL);
                ASSERT_ERROR_ERRNO(setns(0, CLONE_NEWUTS), EPERM);
                ASSERT_ERROR_ERRNO(setns(0, CLONE_NEWIPC), EPERM);
                ASSERT_ERROR_ERRNO(setns(0, CLONE_NEWNET|CLONE_NEWUTS), EPERM);
                ASSERT_ERROR_ERRNO(setns(0, 0), EPERM);

                /* The kernel truncates nstype to 32 bits, make sure setting upper bits doesn't bypass the filter */
                if (sizeof(long) == 8)
                        ASSERT_ERROR_ERRNO(syscall(__NR_setns, 0, (unsigned long) (UINT64_C(1) << 32)),
                                           EPERM);

                pid_t pid = ASSERT_OK_ERRNO(raw_clone(CLONE_NEWNS));
                if (pid == 0)
                        _exit(EXIT_SUCCESS);
                pid = ASSERT_OK_ERRNO(raw_clone(CLONE_NEWNET));
                if (pid == 0)
                        _exit(EXIT_SUCCESS);
                ASSERT_ERROR_ERRNO(raw_clone(CLONE_NEWUTS), EPERM);
                ASSERT_ERROR_ERRNO(raw_clone(CLONE_NEWIPC), EPERM);
                ASSERT_ERROR_ERRNO(raw_clone(CLONE_NEWNET|CLONE_NEWUTS), EPERM);

                _exit(EXIT_SUCCESS);
        }
}

TEST(protect_sysctl) {
        int r;

        /* in containers _sysctl() is likely missing anyway */
        CHECK_SECCOMP(/* skip_container= */ true);

        _cleanup_free_ char *seccomp = NULL;
        ASSERT_OK_ZERO(get_proc_field("/proc/self/status", "Seccomp", &seccomp));
        if (!streq(seccomp, "0"))
                log_warning("Warning: seccomp filter detected, results may be unreliable for %s", __func__);

        r = ASSERT_OK(pidref_safe_fork("(protect-sysctl)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
#if defined __NR__sysctl && __NR__sysctl >= 0
                ASSERT_FAIL(syscall(__NR__sysctl, NULL));
                ASSERT_TRUE(IN_SET(errno, EFAULT, ENOSYS));
#endif

                ASSERT_OK(seccomp_protect_sysctl());

#if HAVE_VALGRIND_VALGRIND_H
                if (RUNNING_ON_VALGRIND) {
                        log_info("Running on valgrind, skipping syscall/EPERM test");
                        _exit(EXIT_SUCCESS);
                }
#endif

#if defined __NR__sysctl && __NR__sysctl >= 0
                ASSERT_ERROR_ERRNO(syscall(__NR__sysctl, 0, 0, 0), EPERM);
#endif

                _exit(EXIT_SUCCESS);
        }
}

TEST(protect_syslog) {
        int r;

        /* in containers syslog() is likely missing anyway */
        CHECK_SECCOMP(/* skip_container= */ true);

        r = ASSERT_OK(pidref_safe_fork("(protect-syslog)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
#if defined __NR_syslog && __NR_syslog >= 0
                ASSERT_ERROR_ERRNO(syscall(__NR_syslog, -1, NULL, 0), EINVAL);
#endif

                ASSERT_OK(seccomp_protect_syslog());

#if defined __NR_syslog && __NR_syslog >= 0
                ASSERT_ERROR_ERRNO(syscall(__NR_syslog, 0, 0, 0), EPERM);
#endif

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_address_families) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(restrict-address-families)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                int fd;
                Set *s;

                fd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM, 0));
                safe_close(fd);

                fd = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_DGRAM, 0));
                safe_close(fd);

                fd = ASSERT_OK_ERRNO(socket(AF_NETLINK, SOCK_DGRAM, 0));
                safe_close(fd);

                ASSERT_NOT_NULL(s = set_new(/* hash_ops= */ NULL));
                ASSERT_OK(set_put(s, INT_TO_PTR(AF_UNIX)));

                ASSERT_OK(seccomp_restrict_address_families(s, /* allow_list= */ false));

                fd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM, 0));
                safe_close(fd);

                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                ASSERT_OK_ERRNO(fd);
                safe_close(fd);
#else
                ASSERT_ERROR_ERRNO(fd, EAFNOSUPPORT);

                /* The kernel truncates the domain to 32 bits, make sure setting upper bits doesn't bypass the filter */
                if (sizeof(long) == 8)
                        ASSERT_ERROR_ERRNO(syscall(__NR_socket, UINT64_C(1) << 32 | AF_UNIX, SOCK_DGRAM, 0),
                                           EAFNOSUPPORT);
#endif

                fd = ASSERT_OK_ERRNO(socket(AF_NETLINK, SOCK_DGRAM, 0));
                safe_close(fd);

                set_clear(s);

                ASSERT_OK(set_put(s, INT_TO_PTR(AF_INET)));

                ASSERT_OK(seccomp_restrict_address_families(s, /* allow_list= */ true));

                fd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_DGRAM, 0));
                safe_close(fd);

                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                ASSERT_OK_ERRNO(fd);
                safe_close(fd);
#else
                ASSERT_ERROR_ERRNO(fd, EAFNOSUPPORT);

                /* Same as above, the allow list must not be bypassed by setting upper bits either */
                if (sizeof(long) == 8)
                        ASSERT_ERROR_ERRNO(syscall(__NR_socket, UINT64_C(1) << 32 | AF_UNIX, SOCK_DGRAM, 0),
                                           EAFNOSUPPORT);
#endif

                fd = socket(AF_NETLINK, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                ASSERT_OK_ERRNO(fd);
                safe_close(fd);
#else
                ASSERT_ERROR_ERRNO(fd, EAFNOSUPPORT);
#endif

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_realtime) {
        int r;

        /* in containers RT privs are likely missing anyway */
        CHECK_SECCOMP(/* skip_container= */ true);

        r = ASSERT_OK(pidref_safe_fork("(restrict-realtime)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                /* On some CI environments, the restriction may be already enabled. */
                if (sched_setscheduler(0, SCHED_FIFO, &(struct sched_param) { .sched_priority = 1 }) < 0) {
                        if (errno == ENOSYS) {
                                log_tests_skipped("sched_setscheduler() is not available or already filtered");
                                _exit(EXIT_SUCCESS);
                        }

                        log_full_errno(errno == EPERM ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to set scheduler parameter for FIFO: %m");
                        assert(errno == EPERM);
                }
                if (sched_setscheduler(0, SCHED_RR, &(struct sched_param) { .sched_priority = 1 }) < 0) {
                        log_full_errno(errno == EPERM ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to set scheduler parameter for RR: %m");
                        assert(errno == EPERM);
                }

                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_IDLE, &(struct sched_param) { .sched_priority = 0 }));
                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_BATCH, &(struct sched_param) { .sched_priority = 0 }));
                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_OTHER, &(struct sched_param) {}));

                ASSERT_OK(seccomp_restrict_realtime_full(ENOANO));

                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_IDLE, &(struct sched_param) { .sched_priority = 0 }));
                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_BATCH, &(struct sched_param) { .sched_priority = 0 }));
                ASSERT_OK_ERRNO(sched_setscheduler(0, SCHED_OTHER, &(struct sched_param) {}));

                ASSERT_ERROR_ERRNO(sched_setscheduler(0, SCHED_FIFO, &(struct sched_param) { .sched_priority = 1 }), ENOANO);
                ASSERT_ERROR_ERRNO(sched_setscheduler(0, SCHED_RR, &(struct sched_param) { .sched_priority = 1 }), ENOANO);

                /* sched_setattr() is refused entirely, as its policy argument cannot be filtered on */
                struct sched_attr attr = {
                        .size = sizeof(attr),
                        .sched_policy = SCHED_FIFO,
                        .sched_priority = 1,
                };
                ASSERT_ERROR_ERRNO(sched_setattr(0, &attr, 0), ENOANO);

                attr = (struct sched_attr) {
                        .size = sizeof(attr),
                        .sched_policy = SCHED_DEADLINE,
                        .sched_runtime = 1000000,
                        .sched_deadline = 10000000,
                        .sched_period = 10000000,
                };
                ASSERT_ERROR_ERRNO(sched_setattr(0, &attr, 0), ENOANO);

                attr = (struct sched_attr) {
                        .size = sizeof(attr),
                        .sched_policy = SCHED_OTHER,
                };
                ASSERT_ERROR_ERRNO(sched_setattr(0, &attr, 0), ENOANO);

                _exit(EXIT_SUCCESS);
        }
}

TEST(memory_deny_write_execute_mmap) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND) {
                log_notice("Running on valgrind, skipping %s", __func__);
                return;
        }
#endif
#if HAS_FEATURE_ADDRESS_SANITIZER
        log_notice("Running on address sanitizer, skipping %s", __func__);
        return;
#endif

        r = ASSERT_OK(pidref_safe_fork("(memory_deny_write_execute_mmap)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                void *p;

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                ASSERT_TRUE(p != MAP_FAILED);
                munmap_safe(p, page_size());

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                ASSERT_TRUE(p != MAP_FAILED);
                munmap_safe(p, page_size());

                ASSERT_OK(seccomp_memory_deny_write_execute());

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#if defined(__x86_64__) || defined(__i386__) || defined(__powerpc64__) || defined(__arm__) || defined(__aarch64__) || defined(__loongarch_lp64)
                ASSERT_PTR_EQ(p, MAP_FAILED);
#  ifdef __GLIBC__
                ASSERT_EQ(errno, EPERM);
#  else
                ASSERT_EQ(errno, ENOMEM); /* musl maps EPERM to ENOMEM. See src/mman/mmap.c in musl. */
#  endif
#endif
                /* Depending on kernel, libseccomp, and glibc versions, other architectures
                 * might fail or not. Let's not assert success. */
                munmap_safe(p, page_size());

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                ASSERT_TRUE(p != MAP_FAILED);
                munmap_safe(p, page_size());

                _exit(EXIT_SUCCESS);
        }
}

TEST(memory_deny_write_execute_shmat) {
        uint32_t arch;
        int r, shmid;

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                log_debug("arch %s: SCMP_SYS(mmap) = %d", seccomp_arch_to_string(arch), SCMP_SYS(mmap));
                log_debug("arch %s: SCMP_SYS(mmap2) = %d", seccomp_arch_to_string(arch), SCMP_SYS(mmap2));
                log_debug("arch %s: SCMP_SYS(shmget) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmget));
                log_debug("arch %s: SCMP_SYS(shmat) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmat));
                log_debug("arch %s: SCMP_SYS(shmdt) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmdt));
        }

        CHECK_SECCOMP(/* skip_container= */ false);

#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND) {
                log_notice("Running on valgrind, skipping %s", __func__);
                return;
        }
#endif
#if HAS_FEATURE_ADDRESS_SANITIZER
        log_notice("Running on address sanitizer, skipping %s", __func__);
        return;
#endif

        shmid = ASSERT_OK_ERRNO(shmget(IPC_PRIVATE, page_size(), 0));

        r = ASSERT_OK(pidref_safe_fork("(memory-deny-write-execute)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                void *p;

                p = shmat(shmid, NULL, 0);
                if (p == MAP_FAILED) {
                        log_tests_skipped_errno(errno, "shmat() is already disabled");
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK_ZERO_ERRNO(shmdt(p));

                p = shmat(shmid, NULL, SHM_EXEC);
                ASSERT_TRUE(p != MAP_FAILED);
                ASSERT_OK_ZERO_ERRNO(shmdt(p));

                ASSERT_OK(seccomp_memory_deny_write_execute());

                p = shmat(shmid, NULL, SHM_EXEC);
                log_debug_errno(p == MAP_FAILED ? errno : 0, "shmat(SHM_EXEC): %m");
#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) || defined(__loongarch_lp64)
                ASSERT_PTR_EQ(p, MAP_FAILED);
                ASSERT_EQ(errno, EPERM);
#endif
                /* Depending on kernel, libseccomp, and glibc versions, other architectures
                 * might fail or not. Let's not assert success. */
                if (p != MAP_FAILED)
                        ASSERT_OK_ZERO_ERRNO(shmdt(p));

                p = shmat(shmid, NULL, 0);
                log_debug_errno(p == MAP_FAILED ? errno : 0, "shmat(0): %m");
                ASSERT_TRUE(p != MAP_FAILED);
                ASSERT_OK_ZERO_ERRNO(shmdt(p));

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_ptrace) {
        int r;

        CHECK_SECCOMP(/* refuse_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(restrict-ptrace)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                void *addr = (void*) (uintptr_t) &ptrace;
                int status;
                pid_t pid;
                long word;

                /* A tracee that stops right away; PTRACE_TRACEME is not filtered. */
                pid = fork();
                ASSERT_OK_ERRNO(pid);
                if (pid == 0) {
                        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
                                _exit(EXIT_FAILURE);
                        raise(SIGSTOP);
                        _exit(EXIT_SUCCESS);
                }

                ASSERT_OK_ERRNO(waitpid(pid, &status, WUNTRACED));
                if (WIFEXITED(status)) {
                        log_tests_skipped("ptrace() not permitted");
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_TRUE(WIFSTOPPED(status));

                /* Positive control: without the filter, writing the word back works. */
                errno = 0;
                word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
                ASSERT_TRUE(word != -1 || errno == 0);
                if (ptrace(PTRACE_POKETEXT, pid, addr, (void*) (uintptr_t) word) < 0) {
                        log_tests_skipped_errno(errno, "PTRACE_POKETEXT not permitted");
                        (void) kill(pid, SIGKILL);
                        _exit(EXIT_SUCCESS);
                }

                ASSERT_OK(seccomp_restrict_ptrace());

                /* Reading stays allowed... */
                errno = 0;
                word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
                ASSERT_TRUE(word != -1 || errno == 0);

                /* ...writing is refused by the filter. */
                ASSERT_ERROR_ERRNO(ptrace(PTRACE_POKETEXT, pid, addr, (void*) (uintptr_t) word), EPERM);
                ASSERT_ERROR_ERRNO(ptrace(PTRACE_POKEDATA, pid, addr, (void*) (uintptr_t) word), EPERM);

                ASSERT_OK_ERRNO(kill(pid, SIGKILL));
                ASSERT_OK_ERRNO(waitpid(pid, &status, 0));

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_read_implies_exec) {
        int r;

        CHECK_SECCOMP(/* refuse_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(restrict-read-implies-exec)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                int current;

                current = ASSERT_OK(safe_personality(PERSONALITY_INVALID));

                /* Positive control: without the filter the flag can be set. */
                r = safe_personality(current | READ_IMPLIES_EXEC);
                if (r == -EPERM) {
                        log_tests_skipped("personality() is restricted already");
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK(r);
                ASSERT_OK(safe_personality(current));

                ASSERT_OK(seccomp_restrict_read_implies_exec());

                ASSERT_ERROR(safe_personality(current | READ_IMPLIES_EXEC), EPERM);
                ASSERT_ERROR(safe_personality(PER_LINUX | READ_IMPLIES_EXEC | ADDR_NO_RANDOMIZE), EPERM);

                /* Every value with the flag but the query is refused... */
                ASSERT_ERROR(safe_personality(PERSONALITY_INVALID & ~UINT32_C(1)), EPERM);
                ASSERT_ERROR(safe_personality(PERSONALITY_INVALID >> 1), EPERM);

                /* ...also with bits above the 32 the kernel looks at. */
                ASSERT_ERROR_ERRNO(syscall(__NR_personality,
                                           (unsigned long) ((UINT64_C(1) << 32) | READ_IMPLIES_EXEC)),
                                   EPERM);

                /* Querying and setting other flags keeps working. */
                ASSERT_EQ(safe_personality(PERSONALITY_INVALID), current);
                ASSERT_OK(safe_personality(current | ADDR_NO_RANDOMIZE));
                ASSERT_OK(safe_personality(current));
                ASSERT_EQ(safe_personality(PERSONALITY_INVALID), current);

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_archs) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(restrict-archs)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_set_free_ Set *s = NULL;

                ASSERT_OK_ERRNO(access("/", F_OK));

                ASSERT_NOT_NULL(s = set_new(/* hash_ops= */ NULL));

#ifdef __x86_64__
                ASSERT_OK(set_put(s, UINT32_TO_PTR(SCMP_ARCH_X86+1)));
#endif
                ASSERT_OK(seccomp_restrict_archs(s));

                ASSERT_OK_ERRNO(access("/", F_OK));
                ASSERT_OK(seccomp_restrict_archs(/* archs= */ NULL));

                ASSERT_OK_ERRNO(access("/", F_OK));

                _exit(EXIT_SUCCESS);
        }
}

TEST(load_syscall_filter_set_raw) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(load-filter)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_hashmap_free_ Hashmap *s = NULL;

                ASSERT_OK_ERRNO(access("/", F_OK));
                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, /* filter= */ NULL, SCMP_ACT_KILL_PROCESS, /* log_missing= */ true));
                ASSERT_OK_ERRNO(access("/", F_OK));
                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                ASSERT_NOT_NULL(s = hashmap_new(/* hash_ops= */ NULL));
#if defined __NR_access && __NR_access >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(-1)));
                log_debug("has access()");
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(-1)));
                log_debug("has faccessat()");
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(-1)));
                log_debug("has faccessat2()");
#endif

                ASSERT_FALSE(hashmap_isempty(s));
                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), /* log_missing= */ true));

                ASSERT_ERROR_ERRNO(access("/", F_OK), EUCLEAN);

                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                hashmap_clear(s);
#if defined __NR_access && __NR_access >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(EILSEQ)));
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(EILSEQ)));
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(EILSEQ)));
#endif

                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), /* log_missing= */ true));

                ASSERT_ERROR_ERRNO(access("/", F_OK), EILSEQ);

                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                hashmap_clear(s);
#if defined __NR_poll && __NR_poll >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_poll + 1), INT_TO_PTR(-1)));
                log_debug("has poll()");
#endif
#if defined __NR_ppoll && __NR_ppoll >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll + 1), INT_TO_PTR(-1)));
                log_debug("has ppoll()");
#endif
#if defined __NR_ppoll_time64 && __NR_ppoll_time64 >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll_time64 + 1), INT_TO_PTR(-1)));
                log_debug("has ppoll_time64()");
#endif

                ASSERT_FALSE(hashmap_isempty(s));
                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUNATCH), /* log_missing= */ true));

                ASSERT_ERROR_ERRNO(access("/", F_OK), EILSEQ);

                ASSERT_ERROR_ERRNO(poll(NULL, 0, 0), EUNATCH);

                hashmap_clear(s);
#if defined __NR_poll && __NR_poll >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_poll + 1), INT_TO_PTR(EILSEQ)));
#endif
#if defined __NR_ppoll && __NR_ppoll >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll + 1), INT_TO_PTR(EILSEQ)));
#endif
#if defined __NR_ppoll_time64 && __NR_ppoll_time64 >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll_time64 + 1), INT_TO_PTR(EILSEQ)));
#endif

                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUNATCH), /* log_missing= */ true));

                ASSERT_ERROR_ERRNO(access("/", F_OK), EILSEQ);

                ASSERT_ERROR_ERRNO(poll(NULL, 0, 0), EILSEQ);

                _exit(EXIT_SUCCESS);
        }
}

TEST(native_syscalls_filtered) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(native-syscalls)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_set_free_ Set *arch_s = NULL;
                _cleanup_hashmap_free_ Hashmap *s = NULL;

                /* Passing "native" or an empty set is equivalent, just do both here. */
                ASSERT_NOT_NULL(arch_s = set_new(/* hash_ops= */ NULL));
                ASSERT_OK(seccomp_restrict_archs(arch_s));
                ASSERT_OK(set_put(arch_s, (void*) SCMP_ARCH_NATIVE));
                ASSERT_OK(seccomp_restrict_archs(arch_s));

                ASSERT_OK_ERRNO(access("/", F_OK));
                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, /* filter= */ NULL, SCMP_ACT_KILL_PROCESS, /* log_missing= */ true));
                ASSERT_OK_ERRNO(access("/", F_OK));
                ASSERT_OK_ZERO_ERRNO(poll(NULL, 0, 0));

                ASSERT_NOT_NULL(s = hashmap_new(/* hash_ops= */ NULL));
#if defined __NR_access && __NR_access >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(-1)));
                log_debug("has access()");
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(-1)));
                log_debug("has faccessat()");
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                ASSERT_OK(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(-1)));
                log_debug("has faccessat2()");
#endif

                ASSERT_FALSE(hashmap_isempty(s));
                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), /* log_missing= */ true));

                ASSERT_ERROR_ERRNO(access("/", F_OK), EUCLEAN);

                _exit(EXIT_SUCCESS);
        }
}

static void assert_personality_locked(unsigned long personality) {
        for (unsigned bit = 0; bit < 32U; bit++) {
                ASSERT_ERROR(safe_personality(personality ^ (UINT32_C(1) << bit)), EPERM);
                ASSERT_ERROR(safe_personality(PERSONALITY_INVALID ^ (UINT32_C(1) << bit)), EPERM);
        }

        /* Also refused with bits above the 32 the kernel looks at. */
        ASSERT_ERROR_ERRNO(syscall(__NR_personality,
                                   (unsigned long) ((UINT64_C(1) << 32) | (personality ^ 1))),
                           EPERM);

        ASSERT_EQ(safe_personality(PERSONALITY_INVALID), (int) personality);
}

TEST(lock_personality) {
        unsigned long current_opinionated;
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        ASSERT_OK(opinionated_personality(&current_opinionated));

        log_info("current personality=0x%lX", (unsigned long) safe_personality(PERSONALITY_INVALID));
        log_info("current opinionated personality=0x%lX", current_opinionated);

        r = ASSERT_OK(pidref_safe_fork("(lock-personality)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                unsigned long current;

                ASSERT_OK(seccomp_lock_personality(current_opinionated));

                current = safe_personality(current_opinionated);
                ASSERT_EQ(current & OPINIONATED_PERSONALITY_MASK, current_opinionated);

                /* Note, we also test that safe_personality() works correctly, by checking whether errno is properly
                 * set, in addition to the return value */
                errno = 0;
                ASSERT_ERROR(safe_personality(PER_LINUX | MMAP_PAGE_ZERO), EPERM);
                ASSERT_EQ(errno, EPERM);

                if (!FLAGS_SET(current, ADDR_NO_RANDOMIZE))
                        ASSERT_ERROR(safe_personality(PER_LINUX | ADDR_NO_RANDOMIZE), EPERM);
                ASSERT_ERROR(safe_personality(PER_LINUX | ADDR_COMPAT_LAYOUT), EPERM);
                ASSERT_ERROR(safe_personality(PER_LINUX | READ_IMPLIES_EXEC), EPERM);
                ASSERT_ERROR(safe_personality(PER_LINUX_32BIT), EPERM);
                ASSERT_ERROR(safe_personality(PER_SVR4), EPERM);
                ASSERT_ERROR(safe_personality(PER_BSD), EPERM);
                ASSERT_ERROR(safe_personality(current_opinionated == PER_LINUX ? PER_LINUX32 : PER_LINUX), EPERM);
                ASSERT_ERROR(safe_personality(PER_LINUX32_3GB), EPERM);
                ASSERT_ERROR(safe_personality(PER_UW7), EPERM);
                ASSERT_ERROR(safe_personality(0x42), EPERM);

                assert_personality_locked(current_opinionated);

                current = safe_personality(current_opinionated);
                ASSERT_EQ(current & OPINIONATED_PERSONALITY_MASK, current_opinionated);
                _exit(EXIT_SUCCESS);
        }

        /* Each bit set in the locked personality takes a rule of its own. */
        r = ASSERT_OK(pidref_safe_fork("(lock-personality-flags)", FORK_LOG|FORK_WAIT, NULL));
        if (r == 0) {
                unsigned long personality = current_opinionated | ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT;

                ASSERT_OK(seccomp_lock_personality(personality));
                ASSERT_OK(safe_personality(personality));
                assert_personality_locked(personality);
                _exit(EXIT_SUCCESS);
        }
}

static int real_open(const char *path, int flags, mode_t mode) {
        /* glibc internally calls openat() when open() is requested. Let's hence define our own wrapper for
         * testing purposes that calls the real syscall, on architectures where SYS_open is defined. On
         * other architectures, let's just fall back to the glibc call. */

#if defined __NR_open && __NR_open >= 0
        return (int) syscall(__NR_open, path, flags, mode);
#else
        return open(path, flags, mode);
#endif
}

static int try_fchmodat2(int dirfd, const char *path, mode_t mode, int flags) {
        int r;

        /* glibc does not provide a direct wrapper for fchmodat2(). Let's hence define our own wrapper for
         * testing purposes that calls the real syscall, on architectures and in environments where
         * SYS_fchmodat2 is defined. Otherwise, let's just fall back to the glibc fchmodat() call. */

        /* Not supported by fchmodat() */
        ASSERT_FALSE(FLAGS_SET(flags, AT_EMPTY_PATH));

        r = RET_NERRNO(fchmodat2(dirfd, path, mode, flags));
        if (r != -ENOSYS)
                return r;

        /* The syscall might still be unsupported by kernel or libseccomp. */
        return RET_NERRNO(fchmodat(dirfd, path, mode, flags));
}

TEST(restrict_suid_sgid) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(suid-sgid)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                char path[] = "/tmp/suidsgidXXXXXX", dir[] = "/tmp/suidsgiddirXXXXXX";
                int fd = -EBADF, k = -EBADF;
                const char *z;

                fd = ASSERT_OK(mkostemp_safe(path));

                ASSERT_NOT_NULL(mkdtemp(dir));
                z = strjoina(dir, "/test");

                ASSERT_OK_ERRNO(chmod(path, 0755 | S_ISUID));
                ASSERT_OK_ERRNO(chmod(path, 0755 | S_ISGID));
                ASSERT_OK_ERRNO(chmod(path, 0755 | S_ISGID | S_ISUID));
                ASSERT_OK_ERRNO(chmod(path, 0755));

                ASSERT_OK_ERRNO(fchmod(fd, 0755 | S_ISUID));
                ASSERT_OK_ERRNO(fchmod(fd, 0755 | S_ISGID));
                ASSERT_OK_ERRNO(fchmod(fd, 0755 | S_ISGID | S_ISUID));
                ASSERT_OK_ERRNO(fchmod(fd, 0755));

                ASSERT_OK_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISUID, 0));
                ASSERT_OK_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISGID, 0));
                ASSERT_OK_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, 0));
                ASSERT_OK_ERRNO(fchmodat(AT_FDCWD, path, 0755, 0));

                ASSERT_OK(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISUID, /* flags= */ 0));
                ASSERT_OK(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISGID, /* flags= */ 0));
                ASSERT_OK(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, /* flags= */ 0));
                ASSERT_OK(try_fchmodat2(AT_FDCWD, path, 0755, /* flags= */ 0));

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = creat(z, 0644 | S_ISUID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = creat(z, 0644 | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = creat(z, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = creat(z, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_OK_ERRNO(mkdir(z, 0755 | S_ISUID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdir(z, 0755 | S_ISGID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdir(z, 0755 | S_ISUID | S_ISGID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdir(z, 0755));
                ASSERT_OK_ERRNO(rmdir(z));

                ASSERT_OK_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISUID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISGID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISUID | S_ISGID));
                ASSERT_OK_ERRNO(rmdir(z));
                ASSERT_OK_ERRNO(mkdirat(AT_FDCWD, z, 0755));
                ASSERT_OK_ERRNO(rmdir(z));

                ASSERT_OK_ERRNO(mknod(z, S_IFREG | 0755 | S_ISUID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknod(z, S_IFREG | 0755 | S_ISGID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknod(z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknod(z, S_IFREG | 0755, 0));
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_OK_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISGID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0));
                ASSERT_OK_ERRNO(unlink(z));
                ASSERT_OK_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755, 0));
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_OK(seccomp_restrict_suid_sgid());

                ASSERT_ERROR_ERRNO(chmod(path, 0775 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(chmod(path, 0775 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(chmod(path, 0775 | S_ISGID | S_ISUID), EPERM);
                ASSERT_OK_ERRNO(chmod(path, 0775));

                ASSERT_ERROR_ERRNO(fchmod(fd, 0775 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(fchmod(fd, 0775 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(fchmod(fd, 0775 | S_ISGID | S_ISUID), EPERM);
                ASSERT_OK_ERRNO(fchmod(fd, 0775));

                ASSERT_ERROR_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISUID, 0), EPERM);
                ASSERT_ERROR_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISGID, 0), EPERM);
                ASSERT_ERROR_ERRNO(fchmodat(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, 0), EPERM);
                ASSERT_OK_ERRNO(fchmodat(AT_FDCWD, path, 0755, 0));

                ASSERT_ERROR(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISUID, /* flags= */ 0), EPERM);
                ASSERT_ERROR(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISGID, /* flags= */ 0), EPERM);
                ASSERT_ERROR(try_fchmodat2(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, /* flags= */ 0), EPERM);
                ASSERT_OK(try_fchmodat2(AT_FDCWD, path, 0755, /* flags= */ 0));

                ASSERT_ERROR_ERRNO(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID), EPERM);
                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_ERROR_ERRNO(creat(z, 0644 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(creat(z, 0644 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(creat(z, 0644 | S_ISUID | S_ISGID), EPERM);
                k = creat(z, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_ERROR_ERRNO(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID), EPERM);
                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_ERROR_ERRNO(mkdir(z, 0755 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(z, 0755 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(z, 0755 | S_ISUID | S_ISGID), EPERM);
                ASSERT_OK_ERRNO(mkdir(z, 0755));
                ASSERT_OK_ERRNO(rmdir(z));

                ASSERT_ERROR_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(AT_FDCWD, z, 0755 | S_ISUID | S_ISGID), EPERM);
                ASSERT_OK_ERRNO(mkdirat(AT_FDCWD, z, 0755));
                ASSERT_OK_ERRNO(rmdir(z));

                ASSERT_ERROR_ERRNO(mknod(z, S_IFREG | 0755 | S_ISUID, 0), EPERM);
                ASSERT_ERROR_ERRNO(mknod(z, S_IFREG | 0755 | S_ISGID, 0), EPERM);
                ASSERT_ERROR_ERRNO(mknod(z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0), EPERM);
                ASSERT_OK_ERRNO(mknod(z, S_IFREG | 0755, 0));
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_ERROR_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID, 0), EPERM);
                ASSERT_ERROR_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISGID, 0), EPERM);
                ASSERT_ERROR_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0), EPERM);
                ASSERT_OK_ERRNO(mknodat(AT_FDCWD, z, S_IFREG | 0755, 0));
                ASSERT_OK_ERRNO(unlink(z));

                ASSERT_OK_ERRNO(unlink(path));
                ASSERT_OK(rm_rf(dir, REMOVE_ROOT|REMOVE_PHYSICAL));

                _exit(EXIT_SUCCESS);
        }
}

static void test_seccomp_suppress_sync_child(void) {
        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(tempfn_random("/tmp/seccomp_suppress_sync", /* extra= */ NULL, &path));
        fd = open(path, O_RDWR | O_CREAT | O_SYNC | O_CLOEXEC, 0666);
        /* We might be running in an environment where sync() is already suppressed. */
        if (fd >= 0) {
                ASSERT_ERROR_ERRNO(fdatasync(-1), EBADF);
                ASSERT_ERROR_ERRNO(fsync(-1), EBADF);
                ASSERT_ERROR_ERRNO(syncfs(-1), EBADF);

                ASSERT_ERROR_ERRNO(fdatasync(INT_MAX), EBADF);
                ASSERT_ERROR_ERRNO(fsync(INT_MAX), EBADF);
                ASSERT_ERROR_ERRNO(syncfs(INT_MAX), EBADF);
        } else if (errno != EINVAL)
                ASSERT_OK_ERRNO(fd);

        ASSERT_OK(seccomp_suppress_sync());

        fd = safe_close(fd);
        fd = ASSERT_ERROR_ERRNO(open(path, O_RDWR | O_CREAT | O_SYNC | O_CLOEXEC, 0666), EINVAL);

        ASSERT_OK_ERRNO(fdatasync(INT_MAX));
        ASSERT_OK_ERRNO(fsync(INT_MAX));
        ASSERT_OK_ERRNO(syncfs(INT_MAX));

        ASSERT_ERROR_ERRNO(fdatasync(-1), EBADF);
        ASSERT_ERROR_ERRNO(fsync(-1), EBADF);
        ASSERT_ERROR_ERRNO(syncfs(-1), EBADF);
}

TEST(seccomp_suppress_sync) {
        int r;

        CHECK_SECCOMP(/* skip_container= */ false);

        r = ASSERT_OK(pidref_safe_fork("(suppress-sync)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                test_seccomp_suppress_sync_child();
                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
