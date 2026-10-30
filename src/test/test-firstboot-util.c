/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "firstboot-util.h"
#include "io-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"

TEST(firstboot_mode_from_string) {
        ASSERT_EQ(firstboot_mode_from_string("yes"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("1"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("on"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("true"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("interactive"), FIRSTBOOT_INTERACTIVE);

        ASSERT_EQ(firstboot_mode_from_string("no"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("0"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("off"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("false"), FIRSTBOOT_NO);

        ASSERT_EQ(firstboot_mode_from_string("headless"), FIRSTBOOT_HEADLESS);

        ASSERT_EQ(firstboot_mode_from_string(""), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string(NULL), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string("Headless"), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string("maybe"), _FIRSTBOOT_MODE_INVALID);
}

static void read_until(int fd, const char *text) {
        const char *p = text;

        while (*p) {
                struct pollfd pfd = {
                        .fd = fd,
                        .events = POLLIN,
                };
                ASSERT_GT(ppoll_usec(&pfd, 1, 5 * USEC_PER_SEC), 0);

                char ch;
                ASSERT_OK_EQ_ERRNO(read(fd, &ch, 1), 1);
                p = ch == *p ? p + 1 : text;
        }
}

static void assert_termios_restored(int fd, const struct termios *saved) {
        struct termios termios;

        ASSERT_OK_ERRNO(tcgetattr(fd, &termios));
        ASSERT_EQ(termios.c_iflag, saved->c_iflag);
        ASSERT_EQ(termios.c_oflag, saved->c_oflag);
        ASSERT_EQ(termios.c_cflag, saved->c_cflag);
        ASSERT_EQ(termios.c_lflag, saved->c_lflag);
        ASSERT_EQ(memcmp(termios.c_cc, saved->c_cc, sizeof(termios.c_cc)), 0);
}

static void test_select_console(unsigned selected, bool hangup, int signal, bool prepare_failure) {
        _cleanup_free_ char *tty0 = NULL, *tty1 = NULL;
        _cleanup_close_pair_ int masters[2] = EBADF_PAIR, peers[2] = EBADF_PAIR;
        struct termios saved[2];

        masters[0] = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, &tty0));
        masters[1] = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, &tty1));
        FOREACH_ELEMENT(i, masters) {
                size_t k = i - masters;
                peers[k] = ASSERT_OK(pty_open_peer(*i, O_RDWR|O_NOCTTY|O_CLOEXEC));
                ASSERT_OK_ERRNO(tcgetattr(peers[k], &saved[k]));
                if (k == 0) {
                        saved[k].c_iflag |= IGNCR|INLCR;
                        saved[k].c_lflag &= ~ICANON;
                        saved[k].c_cc[VMIN] = 0;
                        saved[k].c_cc[VTIME] = 7;
                        ASSERT_OK_ERRNO(tcsetattr(peers[k], TCSANOW, &saved[k]));
                }
        }

        /* Stopping output makes the nonblocking prompt write fail with EAGAIN. */
        if (prepare_failure)
                ASSERT_OK_ERRNO(tcflow(peers[1 - selected], TCOOFF));

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r = pidref_safe_fork("select-console",
                                FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_CLOSE_ALL_FDS|FORK_LOG,
                                &child);
        ASSERT_OK(r);
        if (r == 0) {
                r = firstboot_select_console(STRV_MAKE("/dev/null", tty0, tty0, tty1));
                if (hangup && selected == UINT_MAX)
                        ASSERT_ERROR(r, ENXIO);
                else
                        ASSERT_OK_EQ(r, selected == 0 ? 1 : 3);
                _exit(EXIT_SUCCESS);
        }

        FOREACH_ELEMENT(i, masters)
                if (!prepare_failure || i - masters == selected)
                        read_until(*i, "Press Enter to begin initial setup on this console.");

        if (prepare_failure)
                ASSERT_ERROR(pidref_wait_for_terminate_full(&child, 100 * USEC_PER_MSEC, /* ret_si= */ NULL), ETIMEDOUT);

        if (signal > 0) {
                ASSERT_OK(pidref_kill(&child, signal));
                siginfo_t si;
                ASSERT_OK(pidref_wait_for_terminate(&child, &si));
                ASSERT_EQ(si.si_code, CLD_KILLED);
                ASSERT_EQ(si.si_status, signal);
        } else {
                if (hangup)
                        masters[selected == UINT_MAX ? 0 : 1 - selected] =
                                safe_close(masters[selected == UINT_MAX ? 0 : 1 - selected]);

                if (selected == UINT_MAX)
                        masters[1] = safe_close(masters[1]);
                else {
                        /* Other input must not claim the session, and must not leak into a later prompt. */
                        if (!hangup && !prepare_failure) {
                                ASSERT_OK(loop_write(masters[1 - selected], "ignored", SIZE_MAX));
                                ASSERT_OK(loop_write(masters[selected], "ignored\004", SIZE_MAX));
                                ASSERT_ERROR(pidref_wait_for_terminate_full(&child, 100 * USEC_PER_MSEC, /* ret_si= */ NULL), ETIMEDOUT);
                        }
                        ASSERT_OK(loop_write(masters[selected], selected == 0 ? "\r" : "\n", 1));

                        if (!hangup && !prepare_failure)
                                read_until(masters[1 - selected],
                                           strjoina("Initial setup is running on ", selected == 0 ? tty0 : tty1, "."));
                }
                ASSERT_OK_ZERO(pidref_wait_for_terminate_and_check("select-console", &child, WAIT_LOG));
        }

        if (prepare_failure)
                ASSERT_OK_ERRNO(tcflow(peers[1 - selected], TCOON));

        FOREACH_ELEMENT(i, masters)
                if (*i >= 0) {
                        size_t k = i - masters;
                        assert_termios_restored(peers[k], &saved[k]);
                        struct pollfd pfd = {
                                .fd = peers[k],
                                .events = POLLIN,
                        };
                        ASSERT_OK_ZERO(ppoll_usec(&pfd, 1, 0));
                }
}

TEST(firstboot_select_console) {
        test_select_console(0, /* hangup= */ false, /* signal= */ 0, /* prepare_failure= */ false);
        test_select_console(1, /* hangup= */ false, /* signal= */ 0, /* prepare_failure= */ false);
        test_select_console(0, /* hangup= */ true, /* signal= */ 0, /* prepare_failure= */ false);
        test_select_console(UINT_MAX, /* hangup= */ true, /* signal= */ 0, /* prepare_failure= */ false);
        test_select_console(0, /* hangup= */ false, SIGTERM, /* prepare_failure= */ false);
        test_select_console(0, /* hangup= */ false, SIGINT, /* prepare_failure= */ false);
        test_select_console(0, /* hangup= */ false, SIGHUP, /* prepare_failure= */ false);
        test_select_console(0, /* hangup= */ false, /* signal= */ 0, /* prepare_failure= */ true);
        test_select_console(1, /* hangup= */ false, /* signal= */ 0, /* prepare_failure= */ true);
}

TEST(firstboot_select_console_single) {
        _cleanup_free_ char *tty = NULL;
        _cleanup_close_ int master = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC, &tty));
        _cleanup_close_ int peer = ASSERT_OK(pty_open_peer(master, O_RDWR|O_NOCTTY|O_CLOEXEC));
        struct termios saved;
        ASSERT_OK_ERRNO(tcgetattr(peer, &saved));

        ASSERT_ERROR(firstboot_select_console(NULL), ENXIO);
        ASSERT_ERROR(firstboot_select_console(STRV_MAKE("/dev/null")), ENXIO);
        ASSERT_OK_ZERO(firstboot_select_console(STRV_MAKE(tty)));
        ASSERT_OK_EQ(firstboot_select_console(STRV_MAKE("/dev/null", tty, tty)), 1);
        assert_termios_restored(peer, &saved);
}

DEFINE_TEST_MAIN(LOG_INFO);
