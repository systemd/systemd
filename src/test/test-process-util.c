/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "architecture.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "test-helper.h"
#include "util.h"
#include "virt.h"

static void test_get_process_comm(pid_t pid) {
        struct stat st;
        _cleanup_free_ char *a = NULL, *c = NULL, *d = NULL, *f = NULL, *i = NULL;
        _cleanup_free_ char *env = NULL;
        char path[strlen("/proc//comm") + DECIMAL_STR_MAX(pid_t)];
        pid_t e;
        uid_t u;
        gid_t g;
        dev_t h;
        int r;

        xsprintf(path, "/proc/"PID_FMT"/comm", pid);

        if (stat(path, &st) == 0) {
                assert_se(get_process_comm(pid, &a) >= 0);
                log_info("PID"PID_FMT" comm: '%s'", pid, a);
        } else
                log_warning("%s not exist.", path);

        assert_se(get_process_cmdline(pid, 0, true, &c) >= 0);
        log_info("PID"PID_FMT" cmdline: '%s'", pid, c);

        assert_se(get_process_cmdline(pid, 8, false, &d) >= 0);
        log_info("PID"PID_FMT" cmdline truncated to 8: '%s'", pid, d);

        free(d);
        assert_se(get_process_cmdline(pid, 1, false, &d) >= 0);
        log_info("PID"PID_FMT" cmdline truncated to 1: '%s'", pid, d);

        assert_se(get_process_ppid(pid, &e) >= 0);
        log_info("PID"PID_FMT" PPID: "PID_FMT, pid, e);
        assert_se(pid == 1 ? e == 0 : e > 0);

        assert_se(is_kernel_thread(pid) == 0 || pid != 1);

        r = get_process_exe(pid, &f);
        assert_se(r >= 0 || r == -EACCES);
        log_info("PID"PID_FMT" exe: '%s'", pid, strna(f));

        assert_se(get_process_uid(pid, &u) == 0);
        log_info("PID"PID_FMT" UID: "UID_FMT, pid, u);
        assert_se(u == 0 || pid != 1);

        assert_se(get_process_gid(pid, &g) == 0);
        log_info("PID"PID_FMT" GID: "GID_FMT, pid, g);
        assert_se(g == 0 || pid != 1);

        r = get_process_environ(pid, &env);
        assert_se(r >= 0 || r == -EACCES);
        log_info("PID"PID_FMT" strlen(environ): %zi", pid, env ? (ssize_t)strlen(env) : (ssize_t)-errno);

        if (!detect_container())
                assert_se(get_ctty_devnr(pid, &h) == -ENXIO || pid != 1);

        getenv_for_pid(pid, "PATH", &i);
        log_info("PID"PID_FMT" $PATH: '%s'", pid, strna(i));
}

static void test_pid_is_unwaited(void) {
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
        assert_se(pid_is_unwaited(getpid()));
        assert_se(!pid_is_unwaited(-1));
}

static void test_pid_is_alive(void) {
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
        assert_se(pid_is_alive(getpid()));
        assert_se(!pid_is_alive(-1));
}

static void test_personality(void) {

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

static void test_get_process_cmdline_harder(void) {
        char path[] = "/tmp/test-cmdlineXXXXXX";
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *line = NULL;
        pid_t pid;

        if (geteuid() != 0)
                return;

#ifdef HAVE_VALGRIND_VALGRIND_H
        /* valgrind patches open(/proc//cmdline)
         * so, test_get_process_cmdline_harder fails always
         * See https://github.com/systemd/systemd/pull/3555#issuecomment-226564908 */
        if (RUNNING_ON_VALGRIND)
                return;
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

        fd = mkostemp(path, O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(mount(path, "/proc/self/cmdline", "bind", MS_BIND, NULL) >= 0);
        assert_se(unlink(path) >= 0);

        assert_se(prctl(PR_SET_NAME, "testa") >= 0);

        assert_se(get_process_cmdline(getpid(), 0, false, &line) == -ENOENT);

        assert_se(get_process_cmdline(getpid(), 0, true, &line) >= 0);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 1, true, &line) >= 0);
        assert_se(streq(line, ""));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 2, true, &line) >= 0);
        assert_se(streq(line, "["));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 3, true, &line) >= 0);
        assert_se(streq(line, "[."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 4, true, &line) >= 0);
        assert_se(streq(line, "[.."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 5, true, &line) >= 0);
        assert_se(streq(line, "[..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 6, true, &line) >= 0);
        assert_se(streq(line, "[...]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 7, true, &line) >= 0);
        assert_se(streq(line, "[t...]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 8, true, &line) >= 0);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        assert_se(write(fd, "\0\0\0\0\0\0\0\0\0", 10) == 10);

        assert_se(get_process_cmdline(getpid(), 0, false, &line) == -ENOENT);

        assert_se(get_process_cmdline(getpid(), 0, true, &line) >= 0);
        assert_se(streq(line, "[testa]"));
        line = mfree(line);

        assert_se(write(fd, "foo\0bar\0\0\0\0\0", 10) == 10);

        assert_se(get_process_cmdline(getpid(), 0, false, &line) >= 0);
        assert_se(streq(line, "foo bar"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 0, true, &line) >= 0);
        assert_se(streq(line, "foo bar"));
        line = mfree(line);

        assert_se(write(fd, "quux", 4) == 4);
        assert_se(get_process_cmdline(getpid(), 0, false, &line) >= 0);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 0, true, &line) >= 0);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 1, true, &line) >= 0);
        assert_se(streq(line, ""));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 2, true, &line) >= 0);
        assert_se(streq(line, "."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 3, true, &line) >= 0);
        assert_se(streq(line, ".."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 4, true, &line) >= 0);
        assert_se(streq(line, "..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 5, true, &line) >= 0);
        assert_se(streq(line, "f..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 6, true, &line) >= 0);
        assert_se(streq(line, "fo..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 7, true, &line) >= 0);
        assert_se(streq(line, "foo..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 8, true, &line) >= 0);
        assert_se(streq(line, "foo..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 9, true, &line) >= 0);
        assert_se(streq(line, "foo b..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 10, true, &line) >= 0);
        assert_se(streq(line, "foo ba..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 11, true, &line) >= 0);
        assert_se(streq(line, "foo bar..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 12, true, &line) >= 0);
        assert_se(streq(line, "foo bar..."));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 13, true, &line) >= 0);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 14, true, &line) >= 0);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 1000, true, &line) >= 0);
        assert_se(streq(line, "foo bar quux"));
        line = mfree(line);

        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(prctl(PR_SET_NAME, "aaaa bbbb cccc") >= 0);

        assert_se(get_process_cmdline(getpid(), 0, false, &line) == -ENOENT);

        assert_se(get_process_cmdline(getpid(), 0, true, &line) >= 0);
        assert_se(streq(line, "[aaaa bbbb cccc]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 10, true, &line) >= 0);
        assert_se(streq(line, "[aaaa...]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 11, true, &line) >= 0);
        assert_se(streq(line, "[aaaa...]"));
        line = mfree(line);

        assert_se(get_process_cmdline(getpid(), 12, true, &line) >= 0);
        assert_se(streq(line, "[aaaa b...]"));
        line = mfree(line);

        safe_close(fd);
        _exit(0);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        if (argc > 1) {
                pid_t pid = 0;

                (void) parse_pid(argv[1], &pid);
                test_get_process_comm(pid);
        } else {
                TEST_REQ_RUNNING_SYSTEMD(test_get_process_comm(1));
                test_get_process_comm(getpid());
        }

        test_pid_is_unwaited();
        test_pid_is_alive();
        test_personality();
        test_get_process_cmdline_harder();

        return 0;
}
