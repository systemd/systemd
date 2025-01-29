/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <unistd.h>

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "argv-util.h"
#include "missing_sched.h"
#include "process-util.h"
#include "tests.h"
#include "virt.h"

static void test_rename_process_now(const char *p, int ret) {
        _cleanup_free_ char *comm = NULL, *cmdline = NULL;
        int r;

        log_info("/* %s(%s) */", __func__, p);

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

        assert_se(pid_get_comm(0, &comm) >= 0);
        log_debug("comm = <%s>", comm);
        assert_se(strneq(comm, p, TASK_COMM_LEN-1));
        /* We expect comm to be at most 16 bytes (TASK_COMM_LEN). The kernel may raise this limit in the
         * future. We'd only check the initial part, at least until we recompile, but this will still pass. */

        r = pid_get_cmdline(0, SIZE_MAX, 0, &cmdline);
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

        log_info("/* %s(%s) */", __func__, p);

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

TEST(rename_process_invalid) {
        assert_se(rename_process(NULL) == -EINVAL);
        assert_se(rename_process("") == -EINVAL);
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
        _exit(EXIT_SUCCESS);
}

TEST(rename_process) {
        test_rename_process_one("foo", 1); /* should always fit */
        test_rename_process_one("this is a really really long process name, followed by some more words", 0); /* unlikely to fit */
        test_rename_process_one("1234567", 1); /* should always fit */
}

TEST(argv_help) {
        assert_se(argv_looks_like_help(1, STRV_MAKE("program")));
        assert_se(argv_looks_like_help(2, STRV_MAKE("program", "help")));
        assert_se(argv_looks_like_help(3, STRV_MAKE("program", "arg1", "--help")));
        assert_se(argv_looks_like_help(4, STRV_MAKE("program", "arg1", "arg2", "-h")));
        assert_se(!argv_looks_like_help(2, STRV_MAKE("program", "arg1")));
        assert_se(!argv_looks_like_help(4, STRV_MAKE("program", "arg1", "arg2", "--h")));
        assert_se(!argv_looks_like_help(3, STRV_MAKE("program", "Help", "arg2")));
        assert_se(argv_looks_like_help(5, STRV_MAKE("program", "--help", "arg1", "-h", "--help")));
        assert_se(!argv_looks_like_help(4, STRV_MAKE("program","arg1", "arg2", "-H")));
        assert_se(!argv_looks_like_help(3, STRV_MAKE("program", "--Help", "arg2")));
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
