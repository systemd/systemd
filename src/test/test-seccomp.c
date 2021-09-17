/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_sched.h"
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

static bool have_seccomp_privs(void) {
        return geteuid() == 0 && have_effective_cap(CAP_SYS_ADMIN) > 0; /* If we are root but CAP_SYS_ADMIN we can't do caps (unless we also do NNP) */
}

static void test_parse_syscall_and_errno(void) {
        _cleanup_free_ char *n = NULL;
        int e;

        assert_se(parse_syscall_and_errno("uname:EILSEQ", &n, &e) >= 0);
        assert_se(streq(n, "uname"));
        assert_se(e == errno_from_name("EILSEQ") && e >= 0);
        n = mfree(n);

        assert_se(parse_syscall_and_errno("uname:EINVAL", &n, &e) >= 0);
        assert_se(streq(n, "uname"));
        assert_se(e == errno_from_name("EINVAL") && e >= 0);
        n = mfree(n);

        assert_se(parse_syscall_and_errno("@sync:4095", &n, &e) >= 0);
        assert_se(streq(n, "@sync"));
        assert_se(e == 4095);
        n = mfree(n);

        /* If errno is omitted, then e is set to -1 */
        assert_se(parse_syscall_and_errno("mount", &n, &e) >= 0);
        assert_se(streq(n, "mount"));
        assert_se(e == -1);
        n = mfree(n);

        /* parse_syscall_and_errno() does not check the syscall name is valid or not. */
        assert_se(parse_syscall_and_errno("hoge:255", &n, &e) >= 0);
        assert_se(streq(n, "hoge"));
        assert_se(e == 255);
        n = mfree(n);

        /* 0 is also a valid errno. */
        assert_se(parse_syscall_and_errno("hoge:0", &n, &e) >= 0);
        assert_se(streq(n, "hoge"));
        assert_se(e == 0);
        n = mfree(n);

        assert_se(parse_syscall_and_errno("hoge:kill", &n, &e) >= 0);
        assert_se(streq(n, "hoge"));
        assert_se(e == SECCOMP_ERROR_NUMBER_KILL);
        n = mfree(n);

        /* The function checks the syscall name is empty or not. */
        assert_se(parse_syscall_and_errno("", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno(":255", &n, &e) == -EINVAL);

        /* errno must be a valid errno name or number between 0 and ERRNO_MAX == 4095, or "kill" */
        assert_se(parse_syscall_and_errno("hoge:4096", &n, &e) == -ERANGE);
        assert_se(parse_syscall_and_errno("hoge:-3", &n, &e) == -ERANGE);
        assert_se(parse_syscall_and_errno("hoge:12.3", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:123junk", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:junk123", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:255:EILSEQ", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:-EINVAL", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:EINVALaaa", &n, &e) == -EINVAL);
        assert_se(parse_syscall_and_errno("hoge:", &n, &e) == -EINVAL);
}

static void test_seccomp_arch_to_string(void) {
        uint32_t a, b;
        const char *name;

        log_info("/* %s */", __func__);

        a = seccomp_arch_native();
        assert_se(a > 0);
        name = seccomp_arch_to_string(a);
        assert_se(name);
        assert_se(seccomp_arch_from_string(name, &b) >= 0);
        assert_se(a == b);
}

static void test_architecture_table(void) {
        const char *n, *n2;

        log_info("/* %s */", __func__);

        NULSTR_FOREACH(n,
                       "native\0"
                       "x86\0"
                       "x86-64\0"
                       "x32\0"
                       "arm\0"
                       "arm64\0"
                       "mips\0"
                       "mips64\0"
                       "mips64-n32\0"
                       "mips-le\0"
                       "mips64-le\0"
                       "mips64-le-n32\0"
                       "ppc\0"
                       "ppc64\0"
                       "ppc64-le\0"
#ifdef SCMP_ARCH_RISCV64
                       "riscv64\0"
#endif
                       "s390\0"
                       "s390x\0") {
                uint32_t c;

                assert_se(seccomp_arch_from_string(n, &c) >= 0);
                n2 = seccomp_arch_to_string(c);
                log_info("seccomp-arch: %s → 0x%"PRIx32" → %s", n, c, n2);
                assert_se(streq_ptr(n, n2));
        }
}

static void test_syscall_filter_set_find(void) {
        log_info("/* %s */", __func__);

        assert_se(!syscall_filter_set_find(NULL));
        assert_se(!syscall_filter_set_find(""));
        assert_se(!syscall_filter_set_find("quux"));
        assert_se(!syscall_filter_set_find("@quux"));

        assert_se(syscall_filter_set_find("@clock") == syscall_filter_sets + SYSCALL_FILTER_SET_CLOCK);
        assert_se(syscall_filter_set_find("@default") == syscall_filter_sets + SYSCALL_FILTER_SET_DEFAULT);
        assert_se(syscall_filter_set_find("@raw-io") == syscall_filter_sets + SYSCALL_FILTER_SET_RAW_IO);
}

static void test_filter_sets(void) {
        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        for (unsigned i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                pid_t pid;

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

                pid = fork();
                assert_se(pid >= 0);

                if (pid == 0) { /* Child? */
                        int fd, r;

                        /* If we look at the default set (or one that includes it), allow-list instead of deny-list */
                        if (IN_SET(i, SYSCALL_FILTER_SET_DEFAULT,
                                      SYSCALL_FILTER_SET_SYSTEM_SERVICE,
                                      SYSCALL_FILTER_SET_KNOWN))
                                r = seccomp_load_syscall_filter_set(SCMP_ACT_ERRNO(EUCLEAN), syscall_filter_sets + i, SCMP_ACT_ALLOW, true);
                        else
                                r = seccomp_load_syscall_filter_set(SCMP_ACT_ALLOW, syscall_filter_sets + i, SCMP_ACT_ERRNO(EUCLEAN), true);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        /* Test the sycall filter with one random system call */
                        fd = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC);
                        if (IN_SET(i, SYSCALL_FILTER_SET_IO_EVENT, SYSCALL_FILTER_SET_DEFAULT))
                                assert_se(fd < 0 && errno == EUCLEAN);
                        else {
                                assert_se(fd >= 0);
                                safe_close(fd);
                        }

                        _exit(EXIT_SUCCESS);
                }

                assert_se(wait_for_terminate_and_check(syscall_filter_sets[i].name, pid, WAIT_LOG) == EXIT_SUCCESS);
        }
}

static void test_filter_sets_ordered(void) {
        log_info("/* %s */", __func__);

        /* Ensure "@default" always remains at the beginning of the list */
        assert_se(SYSCALL_FILTER_SET_DEFAULT == 0);
        assert_se(streq(syscall_filter_sets[0].name, "@default"));

        /* Ensure "@known" always remains at the end of the list */
        assert_se(SYSCALL_FILTER_SET_KNOWN == _SYSCALL_FILTER_SET_MAX - 1);
        assert_se(streq(syscall_filter_sets[SYSCALL_FILTER_SET_KNOWN].name, "@known"));

        for (size_t i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                const char *k, *p = NULL;

                /* Make sure each group has a description */
                assert_se(!isempty(syscall_filter_sets[0].help));

                /* Make sure the groups are ordered alphabetically, except for the first and last entries */
                assert_se(i < 2 || i == _SYSCALL_FILTER_SET_MAX - 1 ||
                          strcmp(syscall_filter_sets[i-1].name, syscall_filter_sets[i].name) < 0);

                NULSTR_FOREACH(k, syscall_filter_sets[i].value) {

                        /* Ensure each syscall list is in itself ordered, but groups before names */
                        assert_se(!p ||
                                  (*p == '@' && *k != '@') ||
                                  (((*p == '@' && *k == '@') ||
                                    (*p != '@' && *k != '@')) &&
                                   strcmp(p, k) < 0));

                        p = k;
                }
        }
}

static void test_restrict_namespace(void) {
        char *s = NULL;
        unsigned long ul;
        pid_t pid;

        if (!have_namespaces()) {
                log_notice("Testing without namespaces, skipping %s", __func__);
                return;
        }

        log_info("/* %s */", __func__);

        assert_se(namespace_flags_to_string(0, &s) == 0 && isempty(s));
        s = mfree(s);
        assert_se(namespace_flags_to_string(CLONE_NEWNS, &s) == 0 && streq(s, "mnt"));
        s = mfree(s);
        assert_se(namespace_flags_to_string(CLONE_NEWNS|CLONE_NEWIPC, &s) == 0 && streq(s, "ipc mnt"));
        s = mfree(s);
        assert_se(namespace_flags_to_string(CLONE_NEWCGROUP, &s) == 0 && streq(s, "cgroup"));
        s = mfree(s);

        assert_se(namespace_flags_from_string("mnt", &ul) == 0 && ul == CLONE_NEWNS);
        assert_se(namespace_flags_from_string(NULL, &ul) == 0 && ul == 0);
        assert_se(namespace_flags_from_string("", &ul) == 0 && ul == 0);
        assert_se(namespace_flags_from_string("uts", &ul) == 0 && ul == CLONE_NEWUTS);
        assert_se(namespace_flags_from_string("mnt uts ipc", &ul) == 0 && ul == (CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC));

        assert_se(namespace_flags_to_string(CLONE_NEWUTS, &s) == 0 && streq(s, "uts"));
        assert_se(namespace_flags_from_string(s, &ul) == 0 && ul == CLONE_NEWUTS);
        s = mfree(s);
        assert_se(namespace_flags_from_string("ipc", &ul) == 0 && ul == CLONE_NEWIPC);
        assert_se(namespace_flags_to_string(ul, &s) == 0 && streq(s, "ipc"));
        s = mfree(s);

        assert_se(namespace_flags_to_string(NAMESPACE_FLAGS_ALL, &s) == 0);
        assert_se(streq(s, "cgroup ipc net mnt pid user uts"));
        assert_se(namespace_flags_from_string(s, &ul) == 0 && ul == NAMESPACE_FLAGS_ALL);
        s = mfree(s);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping remaining tests in %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping remaining tests in %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {

                assert_se(seccomp_restrict_namespaces(CLONE_NEWNS|CLONE_NEWNET) >= 0);

                assert_se(unshare(CLONE_NEWNS) == 0);
                assert_se(unshare(CLONE_NEWNET) == 0);
                assert_se(unshare(CLONE_NEWUTS) == -1);
                assert_se(errno == EPERM);
                assert_se(unshare(CLONE_NEWIPC) == -1);
                assert_se(errno == EPERM);
                assert_se(unshare(CLONE_NEWNET|CLONE_NEWUTS) == -1);
                assert_se(errno == EPERM);

                /* We use fd 0 (stdin) here, which of course will fail with EINVAL on setns(). Except of course our
                 * seccomp filter worked, and hits first and makes it return EPERM */
                assert_se(setns(0, CLONE_NEWNS) == -1);
                assert_se(errno == EINVAL);
                assert_se(setns(0, CLONE_NEWNET) == -1);
                assert_se(errno == EINVAL);
                assert_se(setns(0, CLONE_NEWUTS) == -1);
                assert_se(errno == EPERM);
                assert_se(setns(0, CLONE_NEWIPC) == -1);
                assert_se(errno == EPERM);
                assert_se(setns(0, CLONE_NEWNET|CLONE_NEWUTS) == -1);
                assert_se(errno == EPERM);
                assert_se(setns(0, 0) == -1);
                assert_se(errno == EPERM);

                pid = raw_clone(CLONE_NEWNS);
                assert_se(pid >= 0);
                if (pid == 0)
                        _exit(EXIT_SUCCESS);
                pid = raw_clone(CLONE_NEWNET);
                assert_se(pid >= 0);
                if (pid == 0)
                        _exit(EXIT_SUCCESS);
                pid = raw_clone(CLONE_NEWUTS);
                assert_se(pid < 0);
                assert_se(errno == EPERM);
                pid = raw_clone(CLONE_NEWIPC);
                assert_se(pid < 0);
                assert_se(errno == EPERM);
                pid = raw_clone(CLONE_NEWNET|CLONE_NEWUTS);
                assert_se(pid < 0);
                assert_se(errno == EPERM);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("nsseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_protect_sysctl(void) {
        pid_t pid;
        _cleanup_free_ char *seccomp = NULL;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        /* in containers _sysctl() is likely missing anyway */
        if (detect_container() > 0) {
                log_notice("Testing in container, skipping %s", __func__);
                return;
        }

        assert_se(get_proc_field("/proc/self/status", "Seccomp", WHITESPACE, &seccomp) == 0);
        if (!streq(seccomp, "0"))
                log_warning("Warning: seccomp filter detected, results may be unreliable for %s", __func__);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
#if defined __NR__sysctl && __NR__sysctl >= 0
                assert_se(syscall(__NR__sysctl, NULL) < 0);
                assert_se(IN_SET(errno, EFAULT, ENOSYS));
#endif

                assert_se(seccomp_protect_sysctl() >= 0);

#if HAVE_VALGRIND_VALGRIND_H
                if (RUNNING_ON_VALGRIND) {
                        log_info("Running on valgrind, skipping syscall/EPERM test");
                        _exit(EXIT_SUCCESS);
                }
#endif

#if defined __NR__sysctl && __NR__sysctl >= 0
                assert_se(syscall(__NR__sysctl, 0, 0, 0) < 0);
                assert_se(errno == EPERM);
#endif

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("sysctlseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_protect_syslog(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        /* in containers syslog() is likely missing anyway */
        if (detect_container() > 0) {
                log_notice("Testing in container, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
#if defined __NR_syslog && __NR_syslog >= 0
                assert_se(syscall(__NR_syslog, -1, NULL, 0) < 0);
                assert_se(errno == EINVAL);
#endif

                assert_se(seccomp_protect_syslog() >= 0);

#if defined __NR_syslog && __NR_syslog >= 0
                assert_se(syscall(__NR_syslog, 0, 0, 0) < 0);
                assert_se(errno == EPERM);
#endif

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("syslogseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_restrict_address_families(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                int fd;
                Set *s;

                fd = socket(AF_INET, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                fd = socket(AF_NETLINK, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                assert_se(s = set_new(NULL));
                assert_se(set_put(s, INT_TO_PTR(AF_UNIX)) >= 0);

                assert_se(seccomp_restrict_address_families(s, false) >= 0);

                fd = socket(AF_INET, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                assert_se(fd >= 0);
                safe_close(fd);
#else
                assert_se(fd < 0);
                assert_se(errno == EAFNOSUPPORT);
#endif

                fd = socket(AF_NETLINK, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                set_clear(s);

                assert_se(set_put(s, INT_TO_PTR(AF_INET)) >= 0);

                assert_se(seccomp_restrict_address_families(s, true) >= 0);

                fd = socket(AF_INET, SOCK_DGRAM, 0);
                assert_se(fd >= 0);
                safe_close(fd);

                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                assert_se(fd >= 0);
                safe_close(fd);
#else
                assert_se(fd < 0);
                assert_se(errno == EAFNOSUPPORT);
#endif

                fd = socket(AF_NETLINK, SOCK_DGRAM, 0);
#if SECCOMP_RESTRICT_ADDRESS_FAMILIES_BROKEN
                assert_se(fd >= 0);
                safe_close(fd);
#else
                assert_se(fd < 0);
                assert_se(errno == EAFNOSUPPORT);
#endif

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("socketseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_restrict_realtime(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        /* in containers RT privs are likely missing anyway */
        if (detect_container() > 0) {
                log_notice("Testing in container, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                assert_se(sched_setscheduler(0, SCHED_FIFO, &(struct sched_param) { .sched_priority = 1 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_RR, &(struct sched_param) { .sched_priority = 1 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_IDLE, &(struct sched_param) { .sched_priority = 0 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_BATCH, &(struct sched_param) { .sched_priority = 0 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_OTHER, &(struct sched_param) {}) >= 0);

                assert_se(seccomp_restrict_realtime() >= 0);

                assert_se(sched_setscheduler(0, SCHED_IDLE, &(struct sched_param) { .sched_priority = 0 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_BATCH, &(struct sched_param) { .sched_priority = 0 }) >= 0);
                assert_se(sched_setscheduler(0, SCHED_OTHER, &(struct sched_param) {}) >= 0);

                assert_se(sched_setscheduler(0, SCHED_FIFO, &(struct sched_param) { .sched_priority = 1 }) < 0);
                assert_se(errno == EPERM);
                assert_se(sched_setscheduler(0, SCHED_RR, &(struct sched_param) { .sched_priority = 1 }) < 0);
                assert_se(errno == EPERM);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("realtimeseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_memory_deny_write_execute_mmap(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }
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

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                void *p;

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1,0);
                assert_se(p != MAP_FAILED);
                assert_se(munmap(p, page_size()) >= 0);

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1,0);
                assert_se(p != MAP_FAILED);
                assert_se(munmap(p, page_size()) >= 0);

                assert_se(seccomp_memory_deny_write_execute() >= 0);

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1,0);
#if defined(__x86_64__) || defined(__i386__) || defined(__powerpc64__) || defined(__arm__) || defined(__aarch64__)
                assert_se(p == MAP_FAILED);
                assert_se(errno == EPERM);
#endif
                /* Depending on kernel, libseccomp, and glibc versions, other architectures
                 * might fail or not. Let's not assert success. */
                if (p != MAP_FAILED)
                        assert_se(munmap(p, page_size()) == 0);

                p = mmap(NULL, page_size(), PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1,0);
                assert_se(p != MAP_FAILED);
                assert_se(munmap(p, page_size()) >= 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("memoryseccomp-mmap", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_memory_deny_write_execute_shmat(void) {
        int shmid;
        pid_t pid;
        uint32_t arch;

        log_info("/* %s */", __func__);

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                log_debug("arch %s: SCMP_SYS(mmap) = %d", seccomp_arch_to_string(arch), SCMP_SYS(mmap));
                log_debug("arch %s: SCMP_SYS(mmap2) = %d", seccomp_arch_to_string(arch), SCMP_SYS(mmap2));
                log_debug("arch %s: SCMP_SYS(shmget) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmget));
                log_debug("arch %s: SCMP_SYS(shmat) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmat));
                log_debug("arch %s: SCMP_SYS(shmdt) = %d", seccomp_arch_to_string(arch), SCMP_SYS(shmdt));
        }

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }
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

        shmid = shmget(IPC_PRIVATE, page_size(), 0);
        assert_se(shmid >= 0);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                void *p;

                p = shmat(shmid, NULL, 0);
                assert_se(p != MAP_FAILED);
                assert_se(shmdt(p) == 0);

                p = shmat(shmid, NULL, SHM_EXEC);
                assert_se(p != MAP_FAILED);
                assert_se(shmdt(p) == 0);

                assert_se(seccomp_memory_deny_write_execute() >= 0);

                p = shmat(shmid, NULL, SHM_EXEC);
                log_debug_errno(p == MAP_FAILED ? errno : 0, "shmat(SHM_EXEC): %m");
#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
                assert_se(p == MAP_FAILED);
                assert_se(errno == EPERM);
#endif
                /* Depending on kernel, libseccomp, and glibc versions, other architectures
                 * might fail or not. Let's not assert success. */
                if (p != MAP_FAILED)
                        assert_se(shmdt(p) == 0);

                p = shmat(shmid, NULL, 0);
                log_debug_errno(p == MAP_FAILED ? errno : 0, "shmat(0): %m");
                assert_se(p != MAP_FAILED);
                assert_se(shmdt(p) == 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("memoryseccomp-shmat", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_restrict_archs(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                _cleanup_set_free_ Set *s = NULL;

                assert_se(access("/", F_OK) >= 0);

                assert_se(s = set_new(NULL));

#ifdef __x86_64__
                assert_se(set_put(s, UINT32_TO_PTR(SCMP_ARCH_X86+1)) >= 0);
#endif
                assert_se(seccomp_restrict_archs(s) >= 0);

                assert_se(access("/", F_OK) >= 0);
                assert_se(seccomp_restrict_archs(NULL) >= 0);

                assert_se(access("/", F_OK) >= 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("archseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_load_syscall_filter_set_raw(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                _cleanup_hashmap_free_ Hashmap *s = NULL;

                assert_se(access("/", F_OK) >= 0);
                assert_se(poll(NULL, 0, 0) == 0);

                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, NULL, scmp_act_kill_process(), true) >= 0);
                assert_se(access("/", F_OK) >= 0);
                assert_se(poll(NULL, 0, 0) == 0);

                assert_se(s = hashmap_new(NULL));
#if defined __NR_access && __NR_access >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has access()");
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has faccessat()");
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has faccessat2()");
#endif

                assert_se(!hashmap_isempty(s));
                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), true) >= 0);

                assert_se(access("/", F_OK) < 0);
                assert_se(errno == EUCLEAN);

                assert_se(poll(NULL, 0, 0) == 0);

                hashmap_clear(s);
#if defined __NR_access && __NR_access >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif

                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), true) >= 0);

                assert_se(access("/", F_OK) < 0);
                assert_se(errno == EILSEQ);

                assert_se(poll(NULL, 0, 0) == 0);

                hashmap_clear(s);
#if defined __NR_poll && __NR_poll >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_poll + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has poll()");
#endif
#if defined __NR_ppoll && __NR_ppoll >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has ppoll()");
#endif
#if defined __NR_ppoll_time64 && __NR_ppoll_time64 >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll_time64 + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has ppoll_time64()");
#endif

                assert_se(!hashmap_isempty(s));
                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUNATCH), true) >= 0);

                assert_se(access("/", F_OK) < 0);
                assert_se(errno == EILSEQ);

                assert_se(poll(NULL, 0, 0) < 0);
                assert_se(errno == EUNATCH);

                hashmap_clear(s);
#if defined __NR_poll && __NR_poll >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_poll + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif
#if defined __NR_ppoll && __NR_ppoll >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif
#if defined __NR_ppoll_time64 && __NR_ppoll_time64 >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_ppoll_time64 + 1), INT_TO_PTR(EILSEQ)) >= 0);
#endif

                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUNATCH), true) >= 0);

                assert_se(access("/", F_OK) < 0);
                assert_se(errno == EILSEQ);

                assert_se(poll(NULL, 0, 0) < 0);
                assert_se(errno == EILSEQ);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("syscallrawseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_native_syscalls_filtered(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                _cleanup_set_free_ Set *arch_s = NULL;
                _cleanup_hashmap_free_ Hashmap *s = NULL;

                /* Passing "native" or an empty set is equivalent, just do both here. */
                assert_se(arch_s = set_new(NULL));
                assert_se(seccomp_restrict_archs(arch_s) >= 0);
                assert_se(set_put(arch_s, SCMP_ARCH_NATIVE) >= 0);
                assert_se(seccomp_restrict_archs(arch_s) >= 0);

                assert_se(access("/", F_OK) >= 0);
                assert_se(poll(NULL, 0, 0) == 0);

                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, NULL, scmp_act_kill_process(), true) >= 0);
                assert_se(access("/", F_OK) >= 0);
                assert_se(poll(NULL, 0, 0) == 0);

                assert_se(s = hashmap_new(NULL));
#if defined __NR_access && __NR_access >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_access + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has access()");
#endif
#if defined __NR_faccessat && __NR_faccessat >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has faccessat()");
#endif
#if defined __NR_faccessat2 && __NR_faccessat2 >= 0
                assert_se(hashmap_put(s, UINT32_TO_PTR(__NR_faccessat2 + 1), INT_TO_PTR(-1)) >= 0);
                log_debug("has faccessat2()");
#endif

                assert_se(!hashmap_isempty(s));
                assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EUCLEAN), true) >= 0);

                assert_se(access("/", F_OK) < 0);
                assert_se(errno == EUCLEAN);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("nativeseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

static void test_lock_personality(void) {
        unsigned long current;
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        assert_se(opinionated_personality(&current) >= 0);

        log_info("current personality=%lu", current);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                assert_se(seccomp_lock_personality(current) >= 0);

                assert_se((unsigned long) safe_personality(current) == current);

                /* Note, we also test that safe_personality() works correctly, by checkig whether errno is properly
                 * set, in addition to the return value */
                errno = 0;
                assert_se(safe_personality(PER_LINUX | ADDR_NO_RANDOMIZE) == -EPERM);
                assert_se(errno == EPERM);

                assert_se(safe_personality(PER_LINUX | MMAP_PAGE_ZERO) == -EPERM);
                assert_se(safe_personality(PER_LINUX | ADDR_COMPAT_LAYOUT) == -EPERM);
                assert_se(safe_personality(PER_LINUX | READ_IMPLIES_EXEC) == -EPERM);
                assert_se(safe_personality(PER_LINUX_32BIT) == -EPERM);
                assert_se(safe_personality(PER_SVR4) == -EPERM);
                assert_se(safe_personality(PER_BSD) == -EPERM);
                assert_se(safe_personality(current == PER_LINUX ? PER_LINUX32 : PER_LINUX) == -EPERM);
                assert_se(safe_personality(PER_LINUX32_3GB) == -EPERM);
                assert_se(safe_personality(PER_UW7) == -EPERM);
                assert_se(safe_personality(0x42) == -EPERM);

                assert_se(safe_personality(PERSONALITY_INVALID) == -EPERM); /* maybe remove this later */

                assert_se((unsigned long) personality(current) == current);
                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("lockpersonalityseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
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

static void test_restrict_suid_sgid(void) {
        pid_t pid;

        log_info("/* %s */", __func__);

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }
        if (!have_seccomp_privs()) {
                log_notice("Not privileged, skipping %s", __func__);
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                char path[] = "/tmp/suidsgidXXXXXX", dir[] = "/tmp/suidsgiddirXXXXXX";
                int fd = -1, k = -1;
                const char *z;

                fd = mkostemp_safe(path);
                assert_se(fd >= 0);

                assert_se(mkdtemp(dir));
                z = strjoina(dir, "/test");

                assert_se(chmod(path, 0755 | S_ISUID) >= 0);
                assert_se(chmod(path, 0755 | S_ISGID) >= 0);
                assert_se(chmod(path, 0755 | S_ISGID | S_ISUID) >= 0);
                assert_se(chmod(path, 0755) >= 0);

                assert_se(fchmod(fd, 0755 | S_ISUID) >= 0);
                assert_se(fchmod(fd, 0755 | S_ISGID) >= 0);
                assert_se(fchmod(fd, 0755 | S_ISGID | S_ISUID) >= 0);
                assert_se(fchmod(fd, 0755) >= 0);

                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISUID, 0) >= 0);
                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISGID, 0) >= 0);
                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, 0) >= 0);
                assert_se(fchmodat(AT_FDCWD, path, 0755, 0) >= 0);

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = creat(z, 0644 | S_ISUID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = creat(z, 0644 | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = creat(z, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = creat(z, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                assert_se(mkdir(z, 0755 | S_ISUID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdir(z, 0755 | S_ISGID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdir(z, 0755 | S_ISUID | S_ISGID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdir(z, 0755) >= 0);
                assert_se(rmdir(z) >= 0);

                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISUID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISGID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISUID | S_ISGID) >= 0);
                assert_se(rmdir(z) >= 0);
                assert_se(mkdirat(AT_FDCWD, z, 0755) >= 0);
                assert_se(rmdir(z) >= 0);

                assert_se(mknod(z, S_IFREG | 0755 | S_ISUID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknod(z, S_IFREG | 0755 | S_ISGID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknod(z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknod(z, S_IFREG | 0755, 0) >= 0);
                assert_se(unlink(z) >= 0);

                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISGID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0) >= 0);
                assert_se(unlink(z) >= 0);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755, 0) >= 0);
                assert_se(unlink(z) >= 0);

                assert_se(seccomp_restrict_suid_sgid() >= 0);

                assert_se(chmod(path, 0775 | S_ISUID) < 0 && errno == EPERM);
                assert_se(chmod(path, 0775 | S_ISGID) < 0  && errno == EPERM);
                assert_se(chmod(path, 0775 | S_ISGID | S_ISUID) < 0  && errno == EPERM);
                assert_se(chmod(path, 0775) >= 0);

                assert_se(fchmod(fd, 0775 | S_ISUID) < 0 && errno == EPERM);
                assert_se(fchmod(fd, 0775 | S_ISGID) < 0  && errno == EPERM);
                assert_se(fchmod(fd, 0775 | S_ISGID | S_ISUID) < 0  && errno == EPERM);
                assert_se(fchmod(fd, 0775) >= 0);

                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISUID, 0) < 0 && errno == EPERM);
                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISGID, 0) < 0 && errno == EPERM);
                assert_se(fchmodat(AT_FDCWD, path, 0755 | S_ISGID | S_ISUID, 0) < 0 && errno == EPERM);
                assert_se(fchmodat(AT_FDCWD, path, 0755, 0) >= 0);

                assert_se(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID) < 0 && errno == EPERM);
                assert_se(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID) < 0 && errno == EPERM);
                assert_se(real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID) < 0 && errno == EPERM);
                k = real_open(z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                assert_se(creat(z, 0644 | S_ISUID) < 0 && errno == EPERM);
                assert_se(creat(z, 0644 | S_ISGID) < 0 && errno == EPERM);
                assert_se(creat(z, 0644 | S_ISUID | S_ISGID) < 0 && errno == EPERM);
                k = creat(z, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                assert_se(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID) < 0 && errno == EPERM);
                assert_se(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISGID) < 0 && errno == EPERM);
                assert_se(openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644 | S_ISUID | S_ISGID) < 0 && errno == EPERM);
                k = openat(AT_FDCWD, z, O_CREAT|O_RDWR|O_CLOEXEC|O_EXCL, 0644);
                k = safe_close(k);
                assert_se(unlink(z) >= 0);

                assert_se(mkdir(z, 0755 | S_ISUID) < 0 && errno == EPERM);
                assert_se(mkdir(z, 0755 | S_ISGID) < 0 && errno == EPERM);
                assert_se(mkdir(z, 0755 | S_ISUID | S_ISGID) < 0 && errno == EPERM);
                assert_se(mkdir(z, 0755) >= 0);
                assert_se(rmdir(z) >= 0);

                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISUID) < 0 && errno == EPERM);
                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISGID) < 0 && errno == EPERM);
                assert_se(mkdirat(AT_FDCWD, z, 0755 | S_ISUID | S_ISGID) < 0 && errno == EPERM);
                assert_se(mkdirat(AT_FDCWD, z, 0755) >= 0);
                assert_se(rmdir(z) >= 0);

                assert_se(mknod(z, S_IFREG | 0755 | S_ISUID, 0) < 0 && errno == EPERM);
                assert_se(mknod(z, S_IFREG | 0755 | S_ISGID, 0) < 0 && errno == EPERM);
                assert_se(mknod(z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0) < 0 && errno == EPERM);
                assert_se(mknod(z, S_IFREG | 0755, 0) >= 0);
                assert_se(unlink(z) >= 0);

                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID, 0) < 0 && errno == EPERM);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISGID, 0) < 0 && errno == EPERM);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755 | S_ISUID | S_ISGID, 0) < 0 && errno == EPERM);
                assert_se(mknodat(AT_FDCWD, z, S_IFREG | 0755, 0) >= 0);
                assert_se(unlink(z) >= 0);

                assert_se(unlink(path) >= 0);
                assert_se(rm_rf(dir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("suidsgidseccomp", pid, WAIT_LOG) == EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_parse_syscall_and_errno();
        test_seccomp_arch_to_string();
        test_architecture_table();
        test_syscall_filter_set_find();
        test_filter_sets();
        test_filter_sets_ordered();
        test_restrict_namespace();
        test_protect_sysctl();
        test_protect_syslog();
        test_restrict_address_families();
        test_restrict_realtime();
        test_memory_deny_write_execute_mmap();
        test_memory_deny_write_execute_shmat();
        test_restrict_archs();
        test_load_syscall_filter_set_raw();
        test_native_syscalls_filtered();
        test_lock_personality();
        test_restrict_suid_sgid();

        return 0;
}
