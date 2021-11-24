/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/oom.h>
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
#include "parse-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

static void test_get_process_comm_one(pid_t pid) {
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
                assert_se(get_process_comm(pid, &a) >= 0);
                log_info("PID"PID_FMT" comm: '%s'", pid, a);
        } else
                log_warning("%s not exist.", path);

        assert_se(get_process_cmdline(pid, 0, PROCESS_CMDLINE_COMM_FALLBACK, &c) >= 0);
        log_info("PID"PID_FMT" cmdline: '%s'", pid, c);

        assert_se(get_process_cmdline(pid, 8, 0, &d) >= 0);
        log_info("PID"PID_FMT" cmdline truncated to 8: '%s'", pid, d);

        free(d);
        assert_se(get_process_cmdline(pid, 1, 0, &d) >= 0);
        log_info("PID"PID_FMT" cmdline truncated to 1: '%s'", pid, d);

        r = get_process_ppid(pid, &e);
        assert_se(pid == 1 ? r == -EADDRNOTAVAIL : r >= 0);
        if (r >= 0) {
                log_info("PID"PID_FMT" PPID: "PID_FMT, pid, e);
                assert_se(e > 0);
        }

        assert_se(is_kernel_thread(pid) == 0 || pid != 1);

        r = get_process_exe(pid, &f);
        assert_se(r >= 0 || r == -EACCES);
        log_info("PID"PID_FMT" exe: '%s'", pid, strna(f));

        assert_se(get_process_uid(pid, &u) == 0);
        log_info("PID"PID_FMT" UID: "UID_FMT, pid, u);

        assert_se(get_process_gid(pid, &g) == 0);
        log_info("PID"PID_FMT" GID: "GID_FMT, pid, g);

        r = get_process_environ(pid, &env);
        assert_se(r >= 0 || r == -EACCES);
        log_info("PID"PID_FMT" strlen(environ): %zi", pid, env ? (ssize_t)strlen(env) : (ssize_t)-errno);

        if (!detect_container())
                assert_se(get_ctty_devnr(pid, &h) == -ENXIO || pid != 1);

        (void) getenv_for_pid(pid, "PATH", &i);
        log_info("PID"PID_FMT" $PATH: '%s'", pid, strna(i));
}

TEST(get_process_comm) {
        if (saved_argc > 1) {
                pid_t pid = 0;

                (void) parse_pid(saved_argv[1], &pid);
                test_get_process_comm_one(pid);
        } else {
                TEST_REQ_RUNNING_SYSTEMD(test_get_process_comm_one(1));
                test_get_process_comm_one(getpid());
        }
}

static void test_get_process_cmdline_one(pid_t pid) {
        _cleanup_free_ char *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL, *h = NULL;
        int r;

        r = get_process_cmdline(pid, SIZE_MAX, 0, &c);
        log_info("PID "PID_FMT": %s", pid, r >= 0 ? c : errno_to_name(r));

        r = get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &d);
        log_info("      %s", r >= 0 ? d : errno_to_name(r));

        r = get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &e);
        log_info("      %s", r >= 0 ? e : errno_to_name(r));

        r = get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE | PROCESS_CMDLINE_COMM_FALLBACK, &f);
        log_info("      %s", r >= 0 ? f : errno_to_name(r));

        r = get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &g);
        log_info("      %s", r >= 0 ? g : errno_to_name(r));

        r = get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX | PROCESS_CMDLINE_COMM_FALLBACK, &h);
        log_info("      %s", r >= 0 ? h : errno_to_name(r));
}

TEST(get_process_cmdline) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;

        assert_se(d = opendir("/proc"));

        FOREACH_DIRENT(de, d, return) {
                pid_t pid;

                if (de->d_type != DT_DIR)
                        continue;

                if (parse_pid(de->d_name, &pid) < 0)
                        continue;

                test_get_process_cmdline_one(pid);
        }
}

static void test_get_process_comm_escape_one(const char *input, const char *output) {
        _cleanup_free_ char *n = NULL;

        log_debug("input: <%s> — output: <%s>", input, output);

        assert_se(prctl(PR_SET_NAME, input) >= 0);
        assert_se(get_process_comm(0, &n) >= 0);

        log_debug("got: <%s>", n);

        assert_se(streq_ptr(n, output));
}

TEST(get_process_comm_escape) {
        _cleanup_free_ char *saved = NULL;

        assert_se(get_process_comm(0, &saved) >= 0);

        test_get_process_comm_escape_one("", "");
        test_get_process_comm_escape_one("foo", "foo");
        test_get_process_comm_escape_one("012345678901234", "012345678901234");
        test_get_process_comm_escape_one("0123456789012345", "012345678901234");
        test_get_process_comm_escape_one("äöüß", "\\303\\244\\303\\266\\303\\274\\303\\237");
        test_get_process_comm_escape_one("xäöüß", "x\\303\\244\\303\\266\\303\\274\\303\\237");
        test_get_process_comm_escape_one("xxäöüß", "xx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_get_process_comm_escape_one("xxxäöüß", "xxx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_get_process_comm_escape_one("xxxxäöüß", "xxxx\\303\\244\\303\\266\\303\\274\\303\\237");
        test_get_process_comm_escape_one("xxxxxäöüß", "xxxxx\\303\\244\\303\\266\\303\\274\\303\\237");

        assert_se(prctl(PR_SET_NAME, saved) >= 0);
}

TEST(pid_is_unwaited) {
        pid_t pid;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
                assert_se(!pid_is_unwaited(pid));
        }
        assert_se(pid_is_unwaited(getpid_cached()));
        assert_se(!pid_is_unwaited(-1));
}

TEST(pid_is_alive) {
        pid_t pid;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
                assert_se(!pid_is_alive(pid));
        }
        assert_se(pid_is_alive(getpid_cached()));
        assert_se(!pid_is_alive(-1));
}

TEST(personality) {
        assert_se(personality_to_string(PER_LINUX));
        assert_se(!personality_to_string(PERSONALITY_INVALID));

        assert_se(streq(personality_to_string(PER_LINUX), architecture_to_string(native_architecture())));

        assert_se(personality_from_string(personality_to_string(PER_LINUX)) == PER_LINUX);
        assert_se(personality_from_string(architecture_to_string(native_architecture())) == PER_LINUX);

#ifdef __x86_64__
        assert_se(streq_ptr(personality_to_string(PER_LINUX), "x86-64"));
        assert_se(streq_ptr(personality_to_string(PER_LINUX32), "x86"));

        assert_se(personality_from_string("x86-64") == PER_LINUX);
        assert_se(personality_from_string("x86") == PER_LINUX32);
        assert_se(personality_from_string("ia64") == PERSONALITY_INVALID);
        assert_se(personality_from_string(NULL) == PERSONALITY_INVALID);

        assert_se(personality_from_string(personality_to_string(PER_LINUX32)) == PER_LINUX32);
#endif
}

TEST(get_process_cmdline_harder) {
        char path[] = "/tmp/test-cmdlineXXXXXX";
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *line = NULL;
        pid_t pid;

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
         * so, test_get_process_cmdline_harder fails always
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

                assert_se(si.si_code == CLD_EXITED);
                assert_se(si.si_status == 0);

                return;
        }

        assert_se(pid == 0);
        assert_se(unshare(CLONE_NEWNS) >= 0);

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                log_warning_errno(errno, "mount(..., \"/\", MS_SLAVE|MS_REC, ...) failed: %m");
                assert_se(IN_SET(errno, EPERM, EACCES));
                return;
        }

        fd = mkostemp(path, O_CLOEXEC);
        assert_se(fd >= 0);

        /* Note that we don't unmount the following bind-mount at the end of the test because the kernel
         * will clear up its /proc/PID/ hierarchy automatically as soon as the test stops. */
        if (mount(path, "/proc/self/cmdline", "bind", MS_BIND, NULL) < 0) {
                /* This happens under selinux… Abort the test in this case. */
                log_warning_errno(errno, "mount(..., \"/proc/self/cmdline\", \"bind\", ...) failed: %m");
                assert_se(IN_SET(errno, EPERM, EACCES));
                return;
        }

        /* Set RLIMIT_STACK to infinity to test we don't try to allocate unncessarily large values to read
         * the cmdline. */
        if (setrlimit(RLIMIT_STACK, &RLIMIT_MAKE_CONST(RLIM_INFINITY)) < 0)
                log_warning("Testing without RLIMIT_STACK=infinity");

        assert_se(unlink(path) >= 0);

        assert_se(prctl(PR_SET_NAME, "testa") >= 0);

        assert_se(get_process_cmdline(0, SIZE_MAX, 0, &line) == -ENOENT);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK | PROCESS_CMDLINE_QUOTE, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "\"[testa]\"")); /* quoting is enabled here */
        line = mfree(line);

        assert_se(get_process_cmdline(0, 0, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, ""));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 1, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 2, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 3, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[t…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 4, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[te…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 5, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[tes…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 6, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[test…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 7, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 8, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        /* Test with multiple arguments that don't require quoting */

        assert_se(write(fd, "foo\0bar", 8) == 8);

        assert_se(get_process_cmdline(0, SIZE_MAX, 0, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        assert_se(streq(line, "foo bar"));
        line = mfree(line);

        assert_se(write(fd, "quux", 4) == 4);
        assert_se(get_process_cmdline(0, SIZE_MAX, 0, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 1, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 2, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "f…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 3, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "fo…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 4, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 5, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo …"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 6, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo b…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 7, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo ba…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 8, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 9, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar …"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 10, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar q…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 11, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar qu…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 12, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 13, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 14, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 1000, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(prctl(PR_SET_NAME, "aaaa bbbb cccc") >= 0);

        assert_se(get_process_cmdline(0, SIZE_MAX, 0, &line) == -ENOENT);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "[aaaa bbbb cccc]"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 10, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "[aaaa bbb…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 11, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "[aaaa bbbb…"));
        line = mfree(line);

        assert_se(get_process_cmdline(0, 12, PROCESS_CMDLINE_COMM_FALLBACK, &line) >= 0);
        log_debug("'%s'", line);
        assert_se(streq(line, "[aaaa bbbb …"));
        line = mfree(line);

        /* Test with multiple arguments that do require quoting */

#define CMDLINE1 "foo\0'bar'\0\"bar$\"\0x y z\0!``\0"
#define EXPECT1  "foo \"'bar'\" \"\\\"bar\\$\\\"\" \"x y z\" \"!\\`\\`\" \"\""
#define EXPECT1p  "foo $'\\'bar\\'' $'\"bar$\"' $'x y z' $'!``' \"\""
        assert_se(lseek(fd, SEEK_SET, 0) == 0);
        assert_se(write(fd, CMDLINE1, sizeof CMDLINE1) == sizeof CMDLINE1);
        assert_se(ftruncate(fd, sizeof CMDLINE1) == 0);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &line) >= 0);
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT1);
        assert_se(streq(line, EXPECT1));
        line = mfree(line);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &line) >= 0);
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT1p);
        assert_se(streq(line, EXPECT1p));
        line = mfree(line);

#define CMDLINE2 "foo\0\1\2\3\0\0"
#define EXPECT2  "foo \"\\001\\002\\003\" \"\" \"\""
#define EXPECT2p  "foo $'\\001\\002\\003' \"\" \"\""
        assert_se(lseek(fd, SEEK_SET, 0) == 0);
        assert_se(write(fd, CMDLINE2, sizeof CMDLINE2) == sizeof CMDLINE2);
        assert_se(ftruncate(fd, sizeof CMDLINE2) == 0);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE, &line) >= 0);
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT2);
        assert_se(streq(line, EXPECT2));
        line = mfree(line);

        assert_se(get_process_cmdline(0, SIZE_MAX, PROCESS_CMDLINE_QUOTE_POSIX, &line) >= 0);
        log_debug("got: ==%s==", line);
        log_debug("exp: ==%s==", EXPECT2p);
        assert_se(streq(line, EXPECT2p));
        line = mfree(line);

        safe_close(fd);
        _exit(EXIT_SUCCESS);
}

static void test_rename_process_now(const char *p, int ret) {
        _cleanup_free_ char *comm = NULL, *cmdline = NULL;
        int r;

        log_info("/* %s */", __func__);

        r = rename_process(p);
        assert_se(r == ret ||
                  (ret == 0 && r >= 0) ||
                  (ret > 0 && r > 0));

        log_debug_errno(r, "rename_process(%s): %m", p);

        if (r < 0)
                return;

#if HAVE_VALGRIND_VALGRIND_H
        /* see above, valgrind is weird, we can't verify what we are doing here */
        if (RUNNING_ON_VALGRIND)
                return;
#endif

        assert_se(get_process_comm(0, &comm) >= 0);
        log_debug("comm = <%s>", comm);
        assert_se(strneq(comm, p, TASK_COMM_LEN-1));
        /* We expect comm to be at most 16 bytes (TASK_COMM_LEN). The kernel may raise this limit in the
         * future. We'd only check the initial part, at least until we recompile, but this will still pass. */

        r = get_process_cmdline(0, SIZE_MAX, 0, &cmdline);
        assert_se(r >= 0);
        /* we cannot expect cmdline to be renamed properly without privileges */
        if (geteuid() == 0) {
                if (r == 0 && detect_container() > 0)
                        log_info("cmdline = <%s> (not verified, Running in unprivileged container?)", cmdline);
                else {
                        log_info("cmdline = <%s> (expected <%.*s>)", cmdline, (int) strlen("test-process-util"), p);

                        bool skip = cmdline[0] == '"'; /* A shortcut to check if the string is quoted */

                        assert_se(strneq(cmdline + skip, p, strlen("test-process-util")));
                        assert_se(startswith(cmdline + skip, p));
                }
        } else
                log_info("cmdline = <%s> (not verified)", cmdline);
}

static void test_rename_process_one(const char *p, int ret) {
        siginfo_t si;
        pid_t pid;

        log_info("/* %s */", __func__);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */
                test_rename_process_now(p, ret);
                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate(pid, &si) >= 0);
        assert_se(si.si_code == CLD_EXITED);
        assert_se(si.si_status == EXIT_SUCCESS);
}

TEST(rename_process_multi) {
        pid_t pid;

        pid = fork();
        assert_se(pid >= 0);

        if (pid > 0) {
                siginfo_t si;

                assert_se(wait_for_terminate(pid, &si) >= 0);
                assert_se(si.si_code == CLD_EXITED);
                assert_se(si.si_status == EXIT_SUCCESS);

                return;
        }

        /* child */
        test_rename_process_now("one", 1);
        test_rename_process_now("more", 0); /* longer than "one", hence truncated */
        (void) setresuid(99, 99, 99); /* change uid when running privileged */
        test_rename_process_now("time!", 0);
        test_rename_process_now("0", 1); /* shorter than "one", should fit */
        test_rename_process_one("", -EINVAL);
        test_rename_process_one(NULL, -EINVAL);
        _exit(EXIT_SUCCESS);
}

TEST(rename_process) {
        test_rename_process_one(NULL, -EINVAL);
        test_rename_process_one("", -EINVAL);
        test_rename_process_one("foo", 1); /* should always fit */
        test_rename_process_one("this is a really really long process name, followed by some more words", 0); /* unlikely to fit */
        test_rename_process_one("1234567", 1); /* should always fit */
}

TEST(getpid_cached) {
        siginfo_t si;
        pid_t a, b, c, d, e, f, child;

        a = raw_getpid();
        b = getpid_cached();
        c = getpid();

        assert_se(a == b && a == c);

        child = fork();
        assert_se(child >= 0);

        if (child == 0) {
                /* In child */
                a = raw_getpid();
                b = getpid_cached();
                c = getpid();

                assert_se(a == b && a == c);
                _exit(EXIT_SUCCESS);
        }

        d = raw_getpid();
        e = getpid_cached();
        f = getpid();

        assert_se(a == d && a == e && a == f);

        assert_se(wait_for_terminate(child, &si) >= 0);
        assert_se(si.si_status == 0);
        assert_se(si.si_code == CLD_EXITED);
}

TEST(getpid_measure) {
        usec_t t, q;

        unsigned long long iterations = slow_tests_enabled() ? 1000000 : 1000;

        log_info("/* %s (%llu iterations) */", __func__, iterations);

        t = now(CLOCK_MONOTONIC);
        for (unsigned long long i = 0; i < iterations; i++)
                (void) getpid();
        q = now(CLOCK_MONOTONIC) - t;

        log_info(" glibc getpid(): %lf µs each\n", (double) q / iterations);

        iterations *= 50; /* _cached() is about 50 times faster, so we need more iterations */

        t = now(CLOCK_MONOTONIC);
        for (unsigned long long i = 0; i < iterations; i++)
                (void) getpid_cached();
        q = now(CLOCK_MONOTONIC) - t;

        log_info("getpid_cached(): %lf µs each\n", (double) q / iterations);
}

TEST(safe_fork) {
        siginfo_t status;
        pid_t pid;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_NULL_STDIO|FORK_REOPEN_LOG, &pid);
        assert_se(r >= 0);

        if (r == 0) {
                /* child */
                usleep(100 * USEC_PER_MSEC);

                _exit(88);
        }

        assert_se(wait_for_terminate(pid, &status) >= 0);
        assert_se(status.si_code == CLD_EXITED);
        assert_se(status.si_status == 88);
}

TEST(pid_to_ptr) {
        assert_se(PTR_TO_PID(NULL) == 0);
        assert_se(PID_TO_PTR(0) == NULL);

        assert_se(PTR_TO_PID(PID_TO_PTR(1)) == 1);
        assert_se(PTR_TO_PID(PID_TO_PTR(2)) == 2);
        assert_se(PTR_TO_PID(PID_TO_PTR(-1)) == -1);
        assert_se(PTR_TO_PID(PID_TO_PTR(-2)) == -2);

        assert_se(PTR_TO_PID(PID_TO_PTR(INT16_MAX)) == INT16_MAX);
        assert_se(PTR_TO_PID(PID_TO_PTR(INT16_MIN)) == INT16_MIN);

        assert_se(PTR_TO_PID(PID_TO_PTR(INT32_MAX)) == INT32_MAX);
        assert_se(PTR_TO_PID(PID_TO_PTR(INT32_MIN)) == INT32_MIN);
}

static void test_ioprio_class_from_to_string_one(const char *val, int expected, int normalized) {
        assert_se(ioprio_class_from_string(val) == expected);
        if (expected >= 0) {
                _cleanup_free_ char *s = NULL;
                unsigned ret;
                int combined;

                assert_se(ioprio_class_to_string_alloc(expected, &s) == 0);
                /* We sometimes get a class number and sometimes a name back */
                assert_se(streq(s, val) ||
                          safe_atou(val, &ret) == 0);

                /* Make sure normalization works, i.e. NONE → BE gets normalized */
                combined = ioprio_normalize(ioprio_prio_value(expected, 0));
                assert_se(ioprio_prio_class(combined) == normalized);
                assert_se(expected != IOPRIO_CLASS_NONE || ioprio_prio_data(combined) == 4);
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
                      FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_WAIT|FORK_LOG, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                bool full_test;
                int p, q;
                /* child */

                /* rlimit of 30 equals nice level of -10 */
                if (setrlimit(RLIMIT_NICE, &RLIMIT_MAKE_CONST(30)) < 0) {
                        /* If this fails we are probably unprivileged or in a userns of some kind, let's skip
                         * the full test */
                        assert_se(ERRNO_IS_PRIVILEGE(errno));
                        full_test = false;
                } else {
                        assert_se(setresgid(GID_NOBODY, GID_NOBODY, GID_NOBODY) >= 0);
                        assert_se(setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY) >= 0);
                        full_test = true;
                }

                errno = 0;
                p = getpriority(PRIO_PROCESS, 0);
                assert_se(errno == 0);

                /* It should always be possible to set our nice level to the current one */
                assert_se(setpriority_closest(p) > 0);

                errno = 0;
                q = getpriority(PRIO_PROCESS, 0);
                assert_se(errno == 0 && p == q);

                /* It should also be possible to set the nice level to one higher */
                if (p < PRIO_MAX-1) {
                        assert_se(setpriority_closest(++p) > 0);

                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && p == q);
                }

                /* It should also be possible to set the nice level to two higher */
                if (p < PRIO_MAX-1) {
                        assert_se(setpriority_closest(++p) > 0);

                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && p == q);
                }

                if (full_test) {
                        /* These two should work, given the RLIMIT_NICE we set above */
                        assert_se(setpriority_closest(-10) > 0);
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && q == -10);

                        assert_se(setpriority_closest(-9) > 0);
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && q == -9);

                        /* This should succeed but should be clamped to the limit */
                        assert_se(setpriority_closest(-11) == 0);
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && q == -10);

                        assert_se(setpriority_closest(-8) > 0);
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && q == -8);

                        /* This should succeed but should be clamped to the limit */
                        assert_se(setpriority_closest(-12) == 0);
                        errno = 0;
                        q = getpriority(PRIO_PROCESS, 0);
                        assert_se(errno == 0 && q == -10);
                }

                _exit(EXIT_SUCCESS);
        }
}

TEST(get_process_ppid) {
        uint64_t limit;
        int r;

        assert_se(get_process_ppid(1, NULL) == -EADDRNOTAVAIL);

        /* the process with the PID above the global limit definitely doesn't exist. Verify that */
        assert_se(procfs_get_pid_max(&limit) >= 0);
        log_debug("kernel.pid_max = %"PRIu64, limit);

        if (limit < INT_MAX) {
                r = get_process_ppid(limit + 1, NULL);
                log_debug_errno(r, "get_process_limit(%"PRIu64") → %d/%m", limit + 1, r);
                assert(r == -ESRCH);
        }

        for (pid_t pid = 0;;) {
                _cleanup_free_ char *c1 = NULL, *c2 = NULL;
                pid_t ppid;

                r = get_process_ppid(pid, &ppid);
                if (r == -EADDRNOTAVAIL) {
                        log_info("No further parent PID");
                        break;
                }

                assert_se(r >= 0);

                assert_se(get_process_cmdline(pid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c1) >= 0);
                assert_se(get_process_cmdline(ppid, SIZE_MAX, PROCESS_CMDLINE_COMM_FALLBACK, &c2) >= 0);

                log_info("Parent of " PID_FMT " (%s) is " PID_FMT " (%s).", pid, c1, ppid, c2);

                pid = ppid;
        }
}

TEST(set_oom_score_adjust) {
        int a, b, r;

        assert_se(get_oom_score_adjust(&a) >= 0);

        r = set_oom_score_adjust(OOM_SCORE_ADJ_MIN);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r));

        if (r >= 0) {
                assert_se(get_oom_score_adjust(&b) >= 0);
                assert_se(b == OOM_SCORE_ADJ_MIN);
        }

        assert_se(set_oom_score_adjust(a) >= 0);
        assert_se(get_oom_score_adjust(&b) >= 0);
        assert_se(b == a);
}

DEFINE_CUSTOM_TEST_MAIN(LOG_INFO, log_show_color(true), /* no outro */);
