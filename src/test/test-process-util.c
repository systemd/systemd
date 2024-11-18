/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/oom.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "architecture.h"
#include "dirent-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "fd-util.h"
#include "ioprio-util.h"
#include "log.h"
#include "macro.h"
#include "missing_sched.h"
#include "missing_syscall.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"
#include "user-util.h"
#include "virt.h"

static void test_pid_get_comm_one(pid_t pid) {
        struct stat st;
        _cleanup_free_ char *a = NULL, *c = NULL, *d = NULL, *f = NULL, *i = NULL;
        _cleanup_free_ char *env = NULL;
        char path[STRLEN("/proc//comm") + DECIMAL_STR_MAX(pid_t)];
        pid_t e;
        uid_t u;
        gid_t g;
        dev_t h;
        int r;

        log_info("/* %s */", __func__);

        xsprintf(path, "/proc/"PID_FMT"/comm", pid);

        if (stat(path, &st) == 0) {
                ASSERT_OK(pid_get_comm(pid, &a));
                log_info("PID"PID_FMT" comm: '%s'", pid, a);
        } else
                log_warning("%s not exist.", path);

        ASSERT_OK(pid_get_cmdline(pid, 0, PROCESS_CMDLINE_COMM_FALLBACK, &c));
        log_info("PID"PID_FMT" cmdline: '%s'", pid, c);

        ASSERT_OK(pid_get_cmdline(pid, 8, 0, &d));
        log_info("PID"PID_FMT" cmdline truncated to 8: '%s'", pid, d);

        free(d);
        ASSERT_OK(pid_get_cmdline(pid, 1, 0, &d));
        log_info("PID"PID_FMT" cmdline truncated to 1: '%s'", pid, d);

        r = pid_get_ppid(pid, &e);
        if (pid == 1)
                ASSERT_ERROR(r, EADDRNOTAVAIL);
        else
                ASSERT_OK(r);
        if (r >= 0) {
                log_info("PID"PID_FMT" PPID: "PID_FMT, pid, e);
                ASSERT_GT(e, 0);
        }

        ASSERT_TRUE(pid_is_kernel_thread(pid) == 0 || pid != 1);

        r = get_process_exe(pid, &f);
        if (r != -EACCES)
                ASSERT_OK(r);
        log_info("PID"PID_FMT" exe: '%s'", pid, strna(f));

        ASSERT_OK_ZERO(pid_get_uid(pid, &u));
        log_info("PID"PID_FMT" UID: "UID_FMT, pid, u);

        ASSERT_OK_ZERO(get_process_gid(pid, &g));
        log_info("PID"PID_FMT" GID: "GID_FMT, pid, g);

        r = get_process_environ(pid, &env);
        if (r != -EACCES)
                ASSERT_OK(r);
        log_info("PID"PID_FMT" strlen(environ): %zi", pid, env ? (ssize_t)strlen(env) : (ssize_t)-errno);

        if (!detect_container() && pid == 1)
                ASSERT_ERROR(get_ctty_devnr(pid, &h), ENXIO);

        (void) getenv_for_pid(pid, "PATH", &i);
        log_info("PID"PID_FMT" $PATH: '%s'", pid, strna(i));
}

TEST(pid_get_comm) {
        if (saved_argc > 1) {
                pid_t pid = 0;

                (void) parse_pid(saved_argv[1], &pid);
                test_pid_get_comm_one(pid);
        } else {
                TEST_REQ_RUNNING_SYSTEMD(test_pid_get_comm_one(1));
                test_pid_get_comm_one(getpid());
        }
}

static void test_pid_get_cmdline_one(pid_t pid) {
        _cleanup_free_ char *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL, *h = NULL, *joined = NULL;
        _cleanup_strv_free_ char **strv_a = NULL, **strv_b = NULL;
        int r;

        r = pid_get_cmdline(pid, SIZE_MAX, 0, &c);
        log_info("PID "PID_FMT": %s", pid, r >= 0 ? c : errno_to_name(r));

        r = pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &d);
        log_info("      %s", r >= 0 ? d : errno_to_name(r));

        r = pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &e);
        log_info("      %s", r >= 0 ? e : errno_to_name(r));

        r = pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE | PROCESS_CMDLINE_COMM_FALLBACK, &f);
        log_info("      %s", r >= 0 ? f : errno_to_name(r));

        r = pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &g);
        log_info("      %s", r >= 0 ? g : errno_to_name(r));

        r = pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX | PROCESS_CMDLINE_COMM_FALLBACK, &h);
        log_info("      %s", r >= 0 ? h : errno_to_name(r));

        r = pid_get_cmdline_strv(pid, 0, &strv_a);
        if (r >= 0)
                ASSERT_NOT_NULL(joined = strv_join(strv_a, "\", \""));
        log_info("      \"%s\"", r >= 0 ? joined : errno_to_name(r));

        joined = mfree(joined);

        r = pid_get_cmdline_strv(pid, PROCESS_CMDLINE_COMM_FALLBACK, &strv_b);
        if (r >= 0)
                ASSERT_NOT_NULL(joined = strv_join(strv_b, "\", \""));
        log_info("      \"%s\"", r >= 0 ? joined : errno_to_name(r));
}

TEST(pid_get_cmdline) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        ASSERT_OK(proc_dir_open(&d));

        for (;;) {
                pid_t pid;

                r = proc_dir_read(d, &pid);
                ASSERT_OK(r);

                if (r == 0) /* EOF */
                        break;

                test_pid_get_cmdline_one(pid);
        }
}

static void test_pid_get_comm_escape_one(const char *input, const char *output) {
        _cleanup_free_ char *n = NULL;

        log_debug("input: <%s> — output: <%s>", input, output);

        ASSERT_OK_ERRNO(prctl(PR_SET_NAME, input));
        ASSERT_OK(pid_get_comm(0, &n));

        log_debug("got: <%s>", n);

        ASSERT_STREQ(n, output);
}

TEST(pid_get_comm_escape) {
        _cleanup_free_ char *saved = NULL;

        ASSERT_OK(pid_get_comm(0, &saved));

        test_pid_get_comm_escape_one("", "");
        test_pid_get_comm_escape_one("foo", "foo");
        test_pid_get_comm_escape_one("012345678901234", "012345678901234");
        test_pid_get_comm_escape_one("0123456789012345", "012345678901234");
        test_pid_get_comm_escape_one("äöüß", "\\303\\244\\303\\266\\303\\274\\303\\237");
        test_pid_get_comm_escape_one("xäöüß", "x\\303\\244\\303\\266\\303\\274\\303\\237");
        test_pid_get_comm_escape_one("xxäöüß", "xx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_pid_get_comm_escape_one("xxxäöüß", "xxx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_pid_get_comm_escape_one("xxxxäöüß", "xxxx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_pid_get_comm_escape_one("xxxxxäöüß", "xxxxx\\303\\244\\303\\266\\303\\274\\303\\237");

        ASSERT_OK_ERRNO(prctl(PR_SET_NAME, saved));
}

TEST(pid_is_unwaited) {
        pid_t pid;

        pid = fork();
        ASSERT_OK_ERRNO(pid);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                ASSERT_OK_EQ_ERRNO(waitpid(pid, &status, 0), pid);
                ASSERT_OK_ZERO(pid_is_unwaited(pid));
        }
        ASSERT_OK_POSITIVE(pid_is_unwaited(getpid_cached()));
        ASSERT_FAIL(pid_is_unwaited(-1));
}

TEST(pid_is_alive) {
        pid_t pid;

        pid = fork();
        ASSERT_OK_ERRNO(pid);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                ASSERT_OK_EQ_ERRNO(waitpid(pid, &status, 0), pid);
                ASSERT_OK_ZERO(pid_is_alive(pid));
        }
        ASSERT_OK_POSITIVE(pid_is_alive(getpid_cached()));
        ASSERT_FAIL(pid_is_alive(-1));
}

TEST(personality) {
        ASSERT_NOT_NULL(personality_to_string(PER_LINUX));
        ASSERT_NULL(personality_to_string(PERSONALITY_INVALID));

        ASSERT_STREQ(personality_to_string(PER_LINUX), architecture_to_string(native_architecture()));

        ASSERT_EQ(personality_from_string(personality_to_string(PER_LINUX)), (unsigned long) PER_LINUX);
        ASSERT_EQ(personality_from_string(architecture_to_string(native_architecture())), (unsigned long) PER_LINUX);

#ifdef __x86_64__
        ASSERT_STREQ(personality_to_string(PER_LINUX), "x86-64");
        ASSERT_STREQ(personality_to_string(PER_LINUX32), "x86");

        ASSERT_EQ(personality_from_string("x86-64"), (unsigned long) PER_LINUX);
        ASSERT_EQ(personality_from_string("x86"), (unsigned long) PER_LINUX32);
        ASSERT_EQ(personality_from_string("ia64"), PERSONALITY_INVALID);
        ASSERT_EQ(personality_from_string(NULL), PERSONALITY_INVALID);

        ASSERT_EQ(personality_from_string(personality_to_string(PER_LINUX32)), (unsigned long) PER_LINUX32);
#endif
}

TEST(pid_get_cmdline_harder) {
        char path[] = "/tmp/test-cmdlineXXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *line = NULL;
        _cleanup_strv_free_ char **args = NULL;
        pid_t pid;
        int r;

        if (geteuid() != 0) {
                log_info("Skipping %s: not root", __func__);
                return;
        }

        if (!have_namespaces()) {
                log_notice("Testing without namespaces, skipping %s", __func__);
                return;
        }

#if HAVE_VALGRIND_VALGRIND_H
        /* valgrind patches open(/proc//cmdline)
         * so, test_pid_get_cmdline_harder fails always
         * See https://github.com/systemd/systemd/pull/3555#issuecomment-226564908 */
        if (RUNNING_ON_VALGRIND) {
                log_info("Skipping %s: running on valgrind", __func__);
                return;
        }
#endif

        pid = fork();
        if (pid > 0) {
                siginfo_t si;

                (void) wait_for_terminate(pid, &si);

                ASSERT_EQ(si.si_code, CLD_EXITED);
                ASSERT_OK_ZERO(si.si_status);

                return;
        }

        ASSERT_OK_ZERO(pid);

        r = detach_mount_namespace();
        if (r < 0) {
                log_warning_errno(r, "detach mount namespace failed: %m");
                if (!ERRNO_IS_PRIVILEGE(r))
                        ASSERT_OK(r);
                return;
        }

        fd = mkostemp(path, O_CLOEXEC);
        ASSERT_OK_ERRNO(fd);

        /* Note that we don't unmount the following bind-mount at the end of the test because the kernel
         * will clear up its /proc/PID/ hierarchy automatically as soon as the test stops. */
        if (mount(path, "/proc/self/cmdline", "bind", MS_BIND, NULL) < 0) {
                /* This happens under selinux… Abort the test in this case. */
                log_warning_errno(errno, "mount(..., \"/proc/self/cmdline\", \"bind\", ...) failed: %m");
                ASSERT_TRUE(IN_SET(errno, EPERM, EACCES));
                return;
        }

        /* Set RLIMIT_STACK to infinity to test we don't try to allocate unnecessarily large values to read
         * the cmdline. */
        if (setrlimit(RLIMIT_STACK, &RLIMIT_MAKE_CONST(RLIM_INFINITY)) < 0)
                log_warning("Testing without RLIMIT_STACK=infinity");

        ASSERT_OK_ERRNO(unlink(path));

        ASSERT_OK_ERRNO(prctl(PR_SET_NAME, "testa"));

        ASSERT_ERROR(pid_get_cmdline(0, SIZE_MAX, 0, &line), ENOENT);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "[testa]");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK | PROCESS_CMDLINE_QUOTE, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "\"[testa]\""); /* quoting is enabled here */
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 0, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 1, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 2, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 3, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[t…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 4, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[te…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 5, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[tes…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 6, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[test…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 7, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[testa]");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 8, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "[testa]");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, PROCESS_CMDLINE_COMM_FALLBACK, &args));
        ASSERT_TRUE(strv_equal(args, STRV_MAKE("[testa]")));
        args = strv_free(args);

        /* Test with multiple arguments that don't require quoting */

        ASSERT_OK_EQ_ERRNO(write(fd, "foo\0bar", 8), 8);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, 0, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        ASSERT_STREQ(line, "foo bar");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, PROCESS_CMDLINE_COMM_FALLBACK, &args));
        ASSERT_TRUE(strv_equal(args, STRV_MAKE("foo", "bar")));
        args = strv_free(args);

        ASSERT_OK_EQ_ERRNO(write(fd, "quux", 4), 4);
        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, 0, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 1, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 2, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "f…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 3, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "fo…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 4, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 5, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo …");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 6, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo b…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 7, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo ba…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 8, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 9, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar …");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 10, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar q…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 11, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar qu…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 12, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 13, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 14, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 1000, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "foo bar quux");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, PROCESS_CMDLINE_COMM_FALLBACK, &args));
        ASSERT_TRUE(strv_equal(args, STRV_MAKE("foo", "bar", "quux")));
        args = strv_free(args);

        ASSERT_OK_ERRNO(ftruncate(fd, 0));
        ASSERT_OK_ERRNO(prctl(PR_SET_NAME, "aaaa bbbb cccc"));

        ASSERT_ERROR(pid_get_cmdline(0, SIZE_MAX, 0, &line), ENOENT);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "[aaaa bbbb cccc]");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 10, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "[aaaa bbb…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 11, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "[aaaa bbbb…");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, 12, PROCESS_CMDLINE_COMM_FALLBACK, &line));
        log_debug("'%s'", line);
        ASSERT_STREQ(line, "[aaaa bbbb …");
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, PROCESS_CMDLINE_COMM_FALLBACK, &args));
        ASSERT_TRUE(strv_equal(args, STRV_MAKE("[aaaa bbbb cccc]")));
        args = strv_free(args);

        /* Test with multiple arguments that do require quoting */

#define CMDLINE1 "foo\0'bar'\0\"bar$\"\0x y z\0!``\0"
#define EXPECT1  "foo \"'bar'\" \"\\\"bar\\$\\\"\" \"x y z\" \"!\\`\\`\""
#define EXPECT1p "foo $'\\'bar\\'' $'\"bar$\"' $'x y z' $'!``'"
#define EXPECT1v STRV_MAKE("foo", "'bar'", "\"bar$\"", "x y z", "!``")

        ASSERT_OK_ZERO_ERRNO(lseek(fd, SEEK_SET, 0));
        ASSERT_OK_EQ_ERRNO(write(fd, CMDLINE1, sizeof(CMDLINE1)), (ssize_t) sizeof(CMDLINE1));
        ASSERT_OK_ZERO_ERRNO(ftruncate(fd, sizeof(CMDLINE1)));

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &line));
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT1);
        ASSERT_STREQ(line, EXPECT1);
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &line));
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT1p);
        ASSERT_STREQ(line, EXPECT1p);
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, 0, &args));
        ASSERT_TRUE(strv_equal(args, EXPECT1v));
        args = strv_free(args);

#define CMDLINE2 "foo\0\1\2\3\0\0"
#define EXPECT2  "foo \"\\001\\002\\003\""
#define EXPECT2p "foo $'\\001\\002\\003'"
#define EXPECT2v STRV_MAKE("foo", "\1\2\3")

        ASSERT_OK_ZERO_ERRNO(lseek(fd, SEEK_SET, 0));
        ASSERT_OK_EQ_ERRNO(write(fd, CMDLINE2, sizeof(CMDLINE2)), (ssize_t) sizeof(CMDLINE2));
        ASSERT_OK_ZERO_ERRNO(ftruncate(fd, sizeof CMDLINE2));

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &line));
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT2);
        ASSERT_STREQ(line, EXPECT2);
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &line));
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT2p);
        ASSERT_STREQ(line, EXPECT2p);
        line = mfree(line);

        ASSERT_OK(pid_get_cmdline_strv(0, 0, &args));
        ASSERT_TRUE(strv_equal(args, EXPECT2v));
        args = strv_free(args);

        safe_close(fd);
        _exit(EXIT_SUCCESS);
}

TEST(getpid_cached) {
        siginfo_t si;
        pid_t a, b, c, d, e, f, child;

        a = raw_getpid();
        b = getpid_cached();
        c = getpid();

        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);

        child = fork();
        ASSERT_OK_ERRNO(child);

        if (child == 0) {
                /* In child */
                a = raw_getpid();
                b = getpid_cached();
                c = getpid();

                ASSERT_EQ(a, b);
                ASSERT_EQ(a, c);
                _exit(EXIT_SUCCESS);
        }

        d = raw_getpid();
        e = getpid_cached();
        f = getpid();

        ASSERT_EQ(a, d);
        ASSERT_EQ(a, e);
        ASSERT_EQ(a, f);

        ASSERT_OK(wait_for_terminate(child, &si));
        ASSERT_EQ(si.si_status, 0);
        ASSERT_EQ(si.si_code, CLD_EXITED);
}

TEST(getpid_measure) {
        usec_t t, q;

        unsigned long long iterations = slow_tests_enabled() ? 1000000 : 1000;

        log_info("/* %s (%llu iterations) */", __func__, iterations);

        t = now(CLOCK_MONOTONIC);
        for (unsigned long long i = 0; i < iterations; i++)
                (void) getpid();
        q = now(CLOCK_MONOTONIC) - t;

        log_info(" glibc getpid(): %lf μs each", (double) q / iterations);

        iterations *= 50; /* _cached() is about 50 times faster, so we need more iterations */

        t = now(CLOCK_MONOTONIC);
        for (unsigned long long i = 0; i < iterations; i++)
                (void) getpid_cached();
        q = now(CLOCK_MONOTONIC) - t;

        log_info("getpid_cached(): %lf μs each", (double) q / iterations);
}

TEST(safe_fork) {
        siginfo_t status;
        pid_t pid;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_REOPEN_LOG, &pid);
        ASSERT_OK(r);

        if (r == 0) {
                /* child */
                usleep_safe(100 * USEC_PER_MSEC);

                _exit(88);
        }

        ASSERT_OK(wait_for_terminate(pid, &status));
        ASSERT_EQ(status.si_code, CLD_EXITED);
        ASSERT_EQ(status.si_status, 88);
}

TEST(pid_to_ptr) {
        ASSERT_EQ(PTR_TO_PID(NULL), 0);
        ASSERT_NULL(PID_TO_PTR(0));

        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(1)), 1);
        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(2)), 2);
        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(-1)), -1);
        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(-2)), -2);

        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(INT16_MAX)), INT16_MAX);
        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(INT16_MIN)), INT16_MIN);

        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(INT32_MAX)), INT32_MAX);
        ASSERT_EQ(PTR_TO_PID(PID_TO_PTR(INT32_MIN)), INT32_MIN);
}

static void test_ioprio_class_from_to_string_one(const char *val, int expected, int normalized) {
        ASSERT_EQ(ioprio_class_from_string(val), expected);
        if (expected >= 0) {
                _cleanup_free_ char *s = NULL;
                unsigned ret;
                int combined;

                ASSERT_OK_ZERO(ioprio_class_to_string_alloc(expected, &s));
                /* We sometimes get a class number and sometimes a name back */
                ASSERT_TRUE(streq(s, val) || safe_atou(val, &ret) == 0);

                /* Make sure normalization works, i.e. NONE → BE gets normalized */
                combined = ioprio_normalize(ioprio_prio_value(expected, 0));
                ASSERT_EQ(ioprio_prio_class(combined), normalized);
                ASSERT_TRUE(expected != IOPRIO_CLASS_NONE || ioprio_prio_data(combined) == 4);
        }
}

TEST(ioprio_class_from_to_string) {
        test_ioprio_class_from_to_string_one("none", IOPRIO_CLASS_NONE, IOPRIO_CLASS_BE);
        test_ioprio_class_from_to_string_one("realtime", IOPRIO_CLASS_RT, IOPRIO_CLASS_RT);
        test_ioprio_class_from_to_string_one("best-effort", IOPRIO_CLASS_BE, IOPRIO_CLASS_BE);
        test_ioprio_class_from_to_string_one("idle", IOPRIO_CLASS_IDLE, IOPRIO_CLASS_IDLE);
        test_ioprio_class_from_to_string_one("0", IOPRIO_CLASS_NONE, IOPRIO_CLASS_BE);
        test_ioprio_class_from_to_string_one("1", 1, 1);
        test_ioprio_class_from_to_string_one("7", 7, 7);
        test_ioprio_class_from_to_string_one("8", 8, 8);
        test_ioprio_class_from_to_string_one("9", -EINVAL, -EINVAL);
        test_ioprio_class_from_to_string_one("-1", -EINVAL, -EINVAL);
}

TEST(setpriority_closest) {
        int r;

        r = safe_fork("(test-setprio)",
                      FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG|FORK_REOPEN_LOG, NULL);
        ASSERT_OK(r);

        if (r == 0) {
                bool full_test;
                int p, q;
                /* child */

                /* rlimit of 30 equals nice level of -10 */
                if (setrlimit(RLIMIT_NICE, &RLIMIT_MAKE_CONST(30)) < 0) {
                        /* If this fails we are probably unprivileged or in a userns of some kind, let's skip
                         * the full test */
                        if (!ERRNO_IS_PRIVILEGE(errno))
                                ASSERT_OK_ERRNO(-1);
                        full_test = false;
                } else {
                        /* However, if the hard limit was above 30, setrlimit would succeed unprivileged, so
                         * check if the UID/GID can be changed before enabling the full test. */
                        if (setresgid(GID_NOBODY, GID_NOBODY, GID_NOBODY) < 0) {
                                /* If the nobody user does not exist (user namespace) we get EINVAL. */
                                if (!ERRNO_IS_PRIVILEGE(errno) && errno != EINVAL)
                                        ASSERT_OK_ERRNO(-1);
                                full_test = false;
                        } else if (setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY) < 0) {
                                /* If the nobody user does not exist (user namespace) we get EINVAL. */
                                if (!ERRNO_IS_PRIVILEGE(errno) && errno != EINVAL)
                                        ASSERT_OK_ERRNO(-1);
                                full_test = false;
                        } else
                                full_test = true;
                }

                errno = 0;
                p = getpriority(PRIO_PROCESS, 0);
                ASSERT_EQ(errno, 0);

                /* It should always be possible to set our nice level to the current one */
                ASSERT_OK_POSITIVE(setpriority_closest(p));

                errno = 0;
                q = getpriority(PRIO_PROCESS, 0);
                ASSERT_EQ(errno, 0);
                ASSERT_EQ(p, q);

                /* It should also be possible to set the nice level to one higher */
                if (p < PRIO_MAX-1) {
                        ASSERT_OK_POSITIVE(setpriority_closest(++p));

                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(p, q);
                }

                /* It should also be possible to set the nice level to two higher */
                if (p < PRIO_MAX-1) {
                        ASSERT_OK_POSITIVE(setpriority_closest(++p));

                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(p, q);
                }

                if (full_test) {
                        /* These two should work, given the RLIMIT_NICE we set above */
                        ASSERT_OK_POSITIVE(setpriority_closest(-10));
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(q, -10);

                        ASSERT_OK_POSITIVE(setpriority_closest(-9));
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(q, -9);

                        /* This should succeed but should be clamped to the limit */
                        ASSERT_OK_ZERO(setpriority_closest(-11));
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(q, -10);

                        ASSERT_OK_POSITIVE(setpriority_closest(-8));
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(q, -8);

                        /* This should succeed but should be clamped to the limit */
                        ASSERT_OK_ZERO(setpriority_closest(-12));
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        ASSERT_EQ(errno, 0);
                        ASSERT_EQ(q, -10);
                }

                _exit(EXIT_SUCCESS);
        }
}

TEST(pid_get_ppid) {
        uint64_t limit;
        int r;

        ASSERT_ERROR(pid_get_ppid(1, NULL), EADDRNOTAVAIL);

        /* the process with the PID above the global limit definitely doesn't exist. Verify that */
        ASSERT_OK(procfs_get_pid_max(&limit));
        log_debug("kernel.pid_max = %"PRIu64, limit);

        if (limit < INT_MAX) {
                r = pid_get_ppid(limit + 1, NULL);
                log_debug_errno(r, "get_process_limit(%"PRIu64") → %d/%m", limit + 1, r);
                assert(r == -ESRCH);
        }

        for (pid_t pid = 0;;) {
                _cleanup_free_ char *c1 = NULL, *c2 = NULL;
                pid_t ppid;

                r = pid_get_ppid(pid, &ppid);
                if (r == -EADDRNOTAVAIL) {
                        log_info("No further parent PID");
                        break;
                }

                ASSERT_OK(r);

                ASSERT_OK(pid_get_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c1));
                ASSERT_OK(pid_get_cmdline(ppid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c2));

                log_info("Parent of " PID_FMT " (%s) is " PID_FMT " (%s).", pid, c1, ppid, c2);

                pid = ppid;
        }

        /* the same via pidref */
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        ASSERT_OK(pidref_set_self(&pidref));
        for (;;) {
                _cleanup_free_ char *c1 = NULL, *c2 = NULL;
                _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;
                r = pidref_get_ppid_as_pidref(&pidref, &parent);
                if (r == -EADDRNOTAVAIL) {
                        log_info("No further parent PID");
                        break;
                }

                ASSERT_OK(r);

                ASSERT_OK(pidref_get_cmdline(&pidref, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c1));
                ASSERT_OK(pidref_get_cmdline(&parent, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c2));

                log_info("Parent of " PID_FMT " (%s) is " PID_FMT " (%s).", pidref.pid, c1, parent.pid, c2);

                pidref_done(&pidref);
                pidref = TAKE_PIDREF(parent);
        }
}

TEST(set_oom_score_adjust) {
        int a, b, r;

        ASSERT_OK(get_oom_score_adjust(&a));

        r = set_oom_score_adjust(OOM_SCORE_ADJ_MIN);
        if (!ERRNO_IS_PRIVILEGE(r))
                ASSERT_OK(r);

        if (r >= 0) {
                ASSERT_OK(get_oom_score_adjust(&b));
                ASSERT_EQ(b, OOM_SCORE_ADJ_MIN);
        }

        ASSERT_OK(set_oom_score_adjust(a));
        ASSERT_OK(get_oom_score_adjust(&b));
        ASSERT_EQ(b, a);
}

static void* dummy_thread(void *p) {
        int fd = PTR_TO_FD(p);
        char x;

        /* let main thread know we are ready */
        ASSERT_OK_EQ_ERRNO(write(fd, &(const char) { 'x' }, 1), 1);

        /* wait for the main thread to tell us to shut down */
        ASSERT_OK_EQ_ERRNO(read(fd, &x, 1), 1);
        return NULL;
}

TEST(get_process_threads) {
        int r;

        /* Run this test in a child, so that we can guarantee there's exactly one thread around in the child */
        r = safe_fork("(nthreads)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG, NULL);
        ASSERT_OK(r);

        if (r == 0) {
                _cleanup_close_pair_ int pfd[2] = EBADF_PAIR, ppfd[2] = EBADF_PAIR;
                pthread_t t, tt;
                char x;

                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, pfd));
                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, ppfd));

                ASSERT_OK_EQ(get_process_threads(0), 1);
                ASSERT_OK_ZERO_ERRNO(pthread_create(&t, NULL, &dummy_thread, FD_TO_PTR(pfd[0])));
                ASSERT_OK_EQ_ERRNO(read(pfd[1], &x, 1), 1);
                ASSERT_OK_EQ(get_process_threads(0), 2);
                ASSERT_OK_ZERO_ERRNO(pthread_create(&tt, NULL, &dummy_thread, FD_TO_PTR(ppfd[0])));
                ASSERT_OK_EQ_ERRNO(read(ppfd[1], &x, 1), 1);
                ASSERT_OK_EQ(get_process_threads(0), 3);

                ASSERT_OK_EQ_ERRNO(write(pfd[1], &(const char) { 'x' }, 1), 1);
                ASSERT_OK_ZERO_ERRNO(pthread_join(t, NULL));

                /* the value reported via /proc/ is decreased asynchronously, and there appears to be no nice
                 * way to sync on it. Hence we do the weak >= 2 check, even though == 2 is what we'd actually
                 * like to check here */
                r = get_process_threads(0);
                ASSERT_OK(r);
                ASSERT_GE(r, 2);

                ASSERT_OK_EQ_ERRNO(write(ppfd[1], &(const char) { 'x' }, 1), 1);
                ASSERT_OK_ZERO_ERRNO(pthread_join(tt, NULL));

                /* similar here */
                r = get_process_threads(0);
                ASSERT_OK(r);
                ASSERT_GE(r, 1);

                _exit(EXIT_SUCCESS);
        }
}

TEST(is_reaper_process) {
        int r;

        r = safe_fork("(regular)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_WAIT, NULL);
        ASSERT_OK(r);
        if (r == 0) {
                /* child */

                ASSERT_OK_ZERO(is_reaper_process());
                _exit(EXIT_SUCCESS);
        }

        r = safe_fork("(newpid)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_WAIT, NULL);
        ASSERT_OK(r);
        if (r == 0) {
                /* child */

                if (unshare(CLONE_NEWPID) < 0) {
                        if (ERRNO_IS_PRIVILEGE(errno) || ERRNO_IS_NOT_SUPPORTED(errno)) {
                                log_notice("Skipping CLONE_NEWPID reaper check, lacking privileges/support");
                                _exit(EXIT_SUCCESS);
                        }
                }

                r = safe_fork("(newpid1)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_WAIT, NULL);
                ASSERT_OK(r);
                if (r == 0) {
                        /* grandchild, which is PID1 in a pidns */
                        ASSERT_OK_EQ(getpid_cached(), 1);
                        ASSERT_OK_POSITIVE(is_reaper_process());
                        _exit(EXIT_SUCCESS);
                }

                _exit(EXIT_SUCCESS);
        }

        r = safe_fork("(subreaper)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_WAIT, NULL);
        ASSERT_OK(r);
        if (r == 0) {
                /* child */
                ASSERT_OK(make_reaper_process(true));

                ASSERT_OK_POSITIVE(is_reaper_process());
                _exit(EXIT_SUCCESS);
        }
}

TEST(pid_get_start_time) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        ASSERT_OK(pidref_set_self(&pidref));

        usec_t start_time;
        ASSERT_OK(pidref_get_start_time(&pidref, &start_time));
        log_info("our starttime: " USEC_FMT, start_time);

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(stub)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_FREEZE, &child));

        usec_t start_time2;
        ASSERT_OK(pidref_get_start_time(&child, &start_time2));

        log_info("child starttime: " USEC_FMT, start_time2);

        ASSERT_GE(start_time2, start_time);
}

TEST(pidref_from_same_root_fs) {
        int r;

        _cleanup_(pidref_done) PidRef pid1 = PIDREF_NULL, self = PIDREF_NULL;

        ASSERT_OK(pidref_set_self(&self));
        ASSERT_OK(pidref_set_pid(&pid1, 1));

        ASSERT_OK_POSITIVE(pidref_from_same_root_fs(&self, &self));
        ASSERT_OK_POSITIVE(pidref_from_same_root_fs(&pid1, &pid1));

        r = pidref_from_same_root_fs(&pid1, &self);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped("skipping pidref_from_same_root_fs() test, lacking privileged.");
        ASSERT_OK(r);
        log_info("PID1 and us have the same rootfs: %s", yes_no(r));

        int q = pidref_from_same_root_fs(&self, &pid1);
        ASSERT_OK(q);
        ASSERT_EQ(r, q);

        _cleanup_(pidref_done_sigkill_wait) PidRef child1 = PIDREF_NULL;
        ASSERT_OK(pidref_safe_fork("(child1)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_FREEZE, &child1));
        ASSERT_OK_POSITIVE(pidref_from_same_root_fs(&self, &child1));

        _cleanup_close_ int efd = eventfd(0, EFD_CLOEXEC);
        ASSERT_OK_ERRNO(efd);

        _cleanup_(pidref_done_sigkill_wait) PidRef child2 = PIDREF_NULL;
        r = pidref_safe_fork("(child2)", FORK_RESET_SIGNALS|FORK_REOPEN_LOG, &child2);
        ASSERT_OK(r);

        if (r == 0) {
                ASSERT_OK_ERRNO(chroot("/usr"));
                uint64_t u = 1;

                ASSERT_OK_EQ_ERRNO(write(efd, &u, sizeof(u)), (ssize_t) sizeof(u));
                freeze();
        }

        uint64_t u;
        ASSERT_OK_EQ_ERRNO(read(efd, &u, sizeof(u)), (ssize_t) sizeof(u));

        ASSERT_OK_ZERO(pidref_from_same_root_fs(&self, &child2));
        ASSERT_OK_ZERO(pidref_from_same_root_fs(&child2, &self));
}

TEST(pidfd_get_inode_id_self_cached) {
        int r;

        log_info("pid=" PID_FMT, getpid_cached());

        uint64_t id;
        r = pidfd_get_inode_id_self_cached(&id);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                log_info("pidfdid not supported");
        else {
                assert(r >= 0);
                log_info("pidfdid=%" PRIu64, id);
        }
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
