/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "memory-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stat-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor " \
        "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation " \
        "ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit " \
        "in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat " \
        "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

TEST(colors_enabled) {
        log_info("colors_enabled: %s", yes_no(colors_enabled()));
}

TEST(read_one_char) {
        _cleanup_fclose_ FILE *file = NULL;
        char r;
        bool need_nl;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-read_one_char.XXXXXX";

        ASSERT_OK_ZERO(fmkostemp_safe(name, "r+", &file));

        ASSERT_OK_ERRNO(fputs("c\n", file));
        rewind(file);
        ASSERT_OK(read_one_char(file, &r, 1000000, /* echo= */ true, &need_nl));
        ASSERT_FALSE(need_nl);
        ASSERT_EQ(r, 'c');
        ASSERT_FAIL(read_one_char(file, &r, 1000000, /* echo= */ true, &need_nl));

        rewind(file);
        ASSERT_OK_ERRNO(fputs("foobar\n", file));
        rewind(file);
        ASSERT_FAIL(read_one_char(file, &r, 1000000, /* echo= */ true, &need_nl));

        rewind(file);
        ASSERT_OK_ERRNO(fputs("\n", file));
        rewind(file);
        ASSERT_FAIL(read_one_char(file, &r, 1000000, /* echo= */ true, &need_nl));
}

TEST(getttyname_malloc) {
        _cleanup_free_ char *ttyname = NULL;

        _cleanup_close_ int master = ASSERT_OK_ERRNO(posix_openpt(O_RDWR|O_NOCTTY));
        ASSERT_OK(getttyname_malloc(master, &ttyname));
        log_info("ttyname = %s", ttyname);

        ASSERT_TRUE(PATH_IN_SET(ttyname, "ptmx", "pts/ptmx"));
}

typedef struct {
        const char *name;
        const char* (*func)(void);
} Color;

static const Color colors[] = {
        { "normal", ansi_normal },
        { "highlight", ansi_highlight },
        { "black", ansi_black },
        { "red", ansi_red },
        { "green", ansi_green },
        { "yellow", ansi_yellow },
        { "blue", ansi_blue },
        { "magenta", ansi_magenta },
        { "cyan", ansi_cyan },
        { "white", ansi_white },
        { "grey", ansi_grey },

        { "bright-black", ansi_bright_black },
        { "bright-red", ansi_bright_red },
        { "bright-green", ansi_bright_green },
        { "bright-yellow", ansi_bright_yellow },
        { "bright-blue", ansi_bright_blue },
        { "bright-magenta", ansi_bright_magenta },
        { "bright-cyan", ansi_bright_cyan },
        { "bright-white", ansi_bright_white },

        { "highlight-black", ansi_highlight_black },
        { "highlight-red", ansi_highlight_red },
        { "highlight-green", ansi_highlight_green },
        { "highlight-yellow (original)", _ansi_highlight_yellow },
        { "highlight-yellow (replacement)", ansi_highlight_yellow },
        { "highlight-blue", ansi_highlight_blue },
        { "highlight-magenta", ansi_highlight_magenta },
        { "highlight-cyan", ansi_highlight_cyan },
        { "highlight-white", ansi_highlight_white },
        { "highlight-grey", ansi_highlight_grey },

        { "underline", ansi_underline },
        { "highlight-underline", ansi_highlight_underline },
        { "highlight-red-underline", ansi_highlight_red_underline },
        { "highlight-green-underline", ansi_highlight_green_underline },
        { "highlight-yellow-underline", ansi_highlight_yellow_underline },
        { "highlight-blue-underline", ansi_highlight_blue_underline },
        { "highlight-magenta-underline", ansi_highlight_magenta_underline },
        { "highlight-grey-underline", ansi_highlight_grey_underline },
};

TEST(colors) {
        FOREACH_ELEMENT(color, colors)
                printf("<%s%s%s>\n", colors->func(), color->name, ansi_normal());
}

TEST(text) {
        for (size_t i = 0; !streq(colors[i].name, "underline"); i++) {
                bool blwh = strstr(colors[i].name, "black")
                        || strstr(colors[i].name, "white");

                printf("\n"
                       "Testing color %s%s\n%s%s%s\n",
                       colors[i].name,
                       blwh ? "" : ", this text should be readable",
                       colors[i].func(),
                       LOREM_IPSUM,
                       ansi_normal());
        }
}

TEST(get_ctty) {
        _cleanup_free_ char *ctty = NULL;
        struct stat st;
        dev_t devnr;
        int r;

        r = get_ctty(0, &devnr, &ctty);
        if (r < 0) {
                log_notice_errno(r, "Apparently called without a controlling TTY, cutting get_ctty() test short: %m");
                return;
        }

        /* In almost all cases STDIN will match our controlling TTY. Let's verify that and then compare paths */
        ASSERT_OK_ERRNO(fstat(STDIN_FILENO, &st));
        if (S_ISCHR(st.st_mode) && st.st_rdev == devnr) {
                _cleanup_free_ char *stdin_name = NULL;

                ASSERT_OK(getttyname_malloc(STDIN_FILENO, &stdin_name));
                ASSERT_TRUE(path_equal(stdin_name, ctty));
        } else
                log_notice("Not invoked with stdin == ctty, cutting get_ctty() test short");
}

TEST(get_default_background_color) {
        double red, green, blue;
        int r;

        usec_t n = now(CLOCK_MONOTONIC);
        r = get_default_background_color(&red, &green, &blue);
        log_info("%s took %s", __func__+5,
                 FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), n), USEC_PER_MSEC));
        if (r < 0)
                log_notice_errno(r, "Can't get terminal default background color: %m");
        else
                log_notice("R=%g G=%g B=%g", red, green, blue);
}

TEST(terminal_get_size_csi18) {
        unsigned rows, columns;
        int r;

        usec_t n = now(CLOCK_MONOTONIC);
        r = terminal_get_size(STDIN_FILENO, STDOUT_FILENO, &rows, &columns, /* try_dsr= */ false, /* try_csi18= */ true);
        log_info("%s took %s", __func__+5,
                 FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), n), USEC_PER_MSEC));
        if (r < 0)
                return (void) log_notice_errno(r, "Can't get screen dimensions via CSI 18: %m");

        log_notice("terminal size via CSI 18: rows=%u columns=%u", rows, columns);

        struct winsize ws = {};

        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0)
                log_warning_errno(errno, "Can't get terminal size via ioctl, ignoring: %m");
        else
                log_notice("terminal size via ioctl: rows=%u columns=%u", ws.ws_row, ws.ws_col);
}

TEST(terminal_get_size_dsr) {
        unsigned rows, columns;
        int r;

        usec_t n = now(CLOCK_MONOTONIC);
        r = terminal_get_size(STDIN_FILENO, STDOUT_FILENO, &rows, &columns, /* try_dsr= */ true, /* try_csi18= */ false);
        log_info("%s took %s", __func__+5,
                 FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), n), USEC_PER_MSEC));
        if (r < 0)
                return (void) log_notice_errno(r, "Can't get screen dimensions via DSR: %m");

        log_notice("terminal size via DSR: rows=%u columns=%u", rows, columns);

        struct winsize ws = {};

        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0)
                log_warning_errno(errno, "Can't get terminal size via ioctl, ignoring: %m");
        else
                log_notice("terminal size via ioctl: rows=%u columns=%u", ws.ws_row, ws.ws_col);
}

TEST(terminal_fix_size) {
        int r;

        usec_t n = now(CLOCK_MONOTONIC);

        r = terminal_fix_size(STDIN_FILENO, STDOUT_FILENO);
        log_info("%s took %s", __func__+5,
                 FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), n), USEC_PER_MSEC));
        if (r < 0)
                log_warning_errno(r, "Failed to fix terminal size: %m");
        else if (r == 0)
                log_notice("Not fixing terminal size, nothing to do.");
        else
                log_notice("Fixed terminal size.");
}

TEST(terminal_get_terminfo_by_dcs) {
        _cleanup_free_ char *name = NULL;
        int r;

        /* We need a non-blocking read-write fd. */
        _cleanup_close_ int fd = fd_reopen(STDIN_FILENO, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return (void) log_info_errno(fd, "Cannot reopen stdin in read-write mode: %m");

        usec_t n = now(CLOCK_MONOTONIC);

        r = terminal_get_terminfo_by_dcs(fd, &name);
        log_info("%s took %s", __func__+5,
                 FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), n), USEC_PER_MSEC));
        if (r < 0)
                return (void) log_info_errno(r, "Can't get terminal terminfo via DCS: %m");
        log_info("terminal terminfo via DCS: %s, $TERM: %s", name, strnull(getenv("TERM")));
}

TEST(have_terminfo_file) {
        int r;

        FOREACH_STRING(s,
                       "linux",
                       "xterm",
                       "vt220",
                       "xterm-256color",
                       "nosuchfile") {
                r = have_terminfo_file(s);
                log_info("%s: %s → %s", __func__+5, s, r >= 0 ? yes_no(r) : STRERROR(r));
                ASSERT_OK(r);
        }
}

TEST(query_term_for_tty) {
        int r;

        FOREACH_STRING(s,
                       "/dev/console",
                       "/dev/stdin",
                       "/dev/stdout") {
                _cleanup_free_ char *term = NULL;

                r = query_term_for_tty(s, &term);
                log_info("%s: %s → %s/%s", __func__+5, s, STRERROR(r), strnull(term));
        }
}

TEST(terminal_is_pty_fd) {
        int r;

        _cleanup_close_ int fd1 = ASSERT_OK(openpt_allocate(O_RDWR, /* ret_peer_path= */ NULL));
        ASSERT_OK_POSITIVE(terminal_is_pty_fd(fd1));

        _cleanup_close_ int fd2 = ASSERT_OK(pty_open_peer(fd1, O_RDWR|O_CLOEXEC|O_NOCTTY));
        ASSERT_OK_POSITIVE(terminal_is_pty_fd(fd2));

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        fd1 = ASSERT_OK_ERRNO(open("/dev/null", O_RDONLY|O_CLOEXEC));
        ASSERT_OK_ZERO(terminal_is_pty_fd(fd1));

        /* In container managers real tty devices might be weird, avoid them. */
        r = path_is_read_only_fs("/sys");
        if (r != 0)
                return;

        FOREACH_STRING(p, "/dev/ttyS0", "/dev/tty1") {
                _cleanup_close_ int tfd = -EBADF;

                tfd = open_terminal(p, O_CLOEXEC|O_NOCTTY|O_RDONLY|O_NONBLOCK);
                if (tfd == -ENOENT)
                        continue;
                if (tfd < 0)  {
                        log_notice_errno(tfd, "Failed to open '%s', skipping: %m", p);
                        continue;
                }

                ASSERT_LE(terminal_is_pty_fd(tfd), 0);
        }
}

static void test_get_color_mode_with_env(const char *key, const char *val, ColorMode expected) {
        ASSERT_OK_ERRNO(setenv(key, val, true));
        reset_terminal_feature_caches();
        log_info("get_color_mode($%s=%s): %s", key, val, color_mode_to_string(get_color_mode()));
        ASSERT_EQ(get_color_mode(), expected);
}

TEST(get_color_mode) {
        log_info("get_color_mode(default): %s", color_mode_to_string(get_color_mode()));
        ASSERT_OK(get_color_mode());

        test_get_color_mode_with_env("SYSTEMD_COLORS", "0",     COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "no",    COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "16",    COLOR_16);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "256",   COLOR_256);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "24bit", COLOR_24BIT);

        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-16",    terminal_is_dumb() ? COLOR_OFF : COLOR_16);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-256",   terminal_is_dumb() ? COLOR_OFF : COLOR_256);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-24bit", terminal_is_dumb() ? COLOR_OFF : COLOR_24BIT);
        ASSERT_OK_ERRNO(setenv("COLORTERM", "truecolor", true));
        /* SYSTEMD_COLORS=1/yes/true all map to COLOR_TRUE and must force colors on
         * even when stdout is not a TTY (piped). With COLORTERM=truecolor, we get 24bit. */
        test_get_color_mode_with_env("SYSTEMD_COLORS", "1",          COLOR_24BIT);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "yes",        COLOR_24BIT);
        ASSERT_OK_ERRNO(unsetenv("COLORTERM"));
        /* Without COLORTERM, COLOR_TRUE still bypasses the TTY check but autodetects depth. */
        test_get_color_mode_with_env("SYSTEMD_COLORS", "true",       COLOR_256);

        ASSERT_OK_ERRNO(setenv("NO_COLOR", "1", true));
        /* COLOR_TRUE also bypasses NO_COLOR. */
        test_get_color_mode_with_env("SYSTEMD_COLORS", "true",       COLOR_256);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-16",    COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-256",   COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "auto-24bit", COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "42",         COLOR_OFF);
        test_get_color_mode_with_env("SYSTEMD_COLORS", "invalid",    COLOR_OFF);
        ASSERT_OK_ERRNO(unsetenv("NO_COLOR"));
        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_COLORS"));

        test_get_color_mode_with_env("COLORTERM", "truecolor", terminal_is_dumb() ? COLOR_OFF : COLOR_24BIT);
        test_get_color_mode_with_env("COLORTERM", "24bit",     terminal_is_dumb() ? COLOR_OFF : COLOR_24BIT);
        test_get_color_mode_with_env("COLORTERM", "invalid",   terminal_is_dumb() ? COLOR_OFF : COLOR_256);
        test_get_color_mode_with_env("COLORTERM", "42",        terminal_is_dumb() ? COLOR_OFF : COLOR_256);
        ASSERT_OK_ERRNO(unsetenv("COLORTERM"));
        reset_terminal_feature_caches();
}

TEST(terminal_reset_defensive) {
        int r;

        r = terminal_reset_defensive(STDOUT_FILENO, /* flags= */ 0);
        if (r < 0)
                log_notice_errno(r, "Failed to reset terminal: %m");
}

TEST(pty_open_peer) {
        _cleanup_free_ char *pty_path = NULL;

        _cleanup_close_ int pty_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, &pty_path));
        ASSERT_NOT_NULL(pty_path);

        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));

        static const char x[] = { 'x', '\n' };
        ASSERT_OK_EQ_ERRNO(write(pty_fd, x, sizeof(x)), (ssize_t) sizeof(x));

        char buf[3];
        ASSERT_OK_EQ_ERRNO(read(peer_fd, &buf, sizeof(buf)), (ssize_t) sizeof(x));
        ASSERT_EQ(buf[0], x[0]);
        ASSERT_EQ(buf[1], x[1]);
}

TEST(terminal_new_session) {
        int r;

        _cleanup_close_ int pty_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(pty_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));

        r = pidref_safe_fork_full(
                        "test-term-session",
                        (int[]) { peer_fd, peer_fd, peer_fd },
                        NULL, 0,
                        FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT|FORK_REARRANGE_STDIO,
                        NULL);
        ASSERT_OK(r);
        if (r == 0) {
                ASSERT_OK(terminal_new_session());
                ASSERT_OK(get_ctty_devnr(0, NULL));

                terminal_detach_session();
                ASSERT_ERROR(get_ctty_devnr(0, NULL), ENXIO);

                ASSERT_OK(terminal_new_session());
                ASSERT_OK(get_ctty_devnr(0, NULL));

                terminal_detach_session();
                ASSERT_OK(rearrange_stdio(-EBADF, STDOUT_FILENO, STDERR_FILENO));
                ASSERT_ERROR(get_ctty_devnr(0, NULL), ENXIO);
                ASSERT_ERROR(terminal_new_session(), ENXIO);

                _exit(EXIT_SUCCESS);
        }
}

/* Helper for PTY-based terminal_fix_size() tests. Forks a child with a PTY as stdio, simulates
 * a terminal by writing pre-canned responses on the master side, and verifies the result via ioctl.
 *
 * terminal_fix_size() always tries CSI 18 first and falls back to DSR on failure.
 *
 * responses/n_responses: what to write to the master after each query is read (NULL entries
 * mean "don't respond", causing the child to time out on that round). */
static void test_terminal_fix_size_pty(
                unsigned initial_rows,
                unsigned initial_columns,
                const char *const *responses,
                size_t n_responses,
                int expected_r,
                unsigned expected_rows,
                unsigned expected_columns) {

        _cleanup_close_ int master_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(master_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));

        /* Set the initial terminal size via ioctl */
        struct winsize ws = { .ws_row = initial_rows, .ws_col = initial_columns };
        ASSERT_OK_ERRNO(ioctl(master_fd, TIOCSWINSZ, &ws));

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r = pidref_safe_fork_full(
                        "(terminal-fix-size-test)",
                        (int[]) { peer_fd, peer_fd, peer_fd },
                        NULL, 0,
                        FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_REARRANGE_STDIO,
                        &child);
        ASSERT_OK(r);
        if (r == 0) {
                /* Child: call terminal_fix_size() and verify the result via ioctl */
                ASSERT_OK_ERRNO(setenv("TERM", "xterm", true));
                reset_terminal_feature_caches();

                r = terminal_fix_size(STDIN_FILENO, STDOUT_FILENO);
                ASSERT_EQ(r, expected_r);

                if (r >= 0) {
                        struct winsize wsc;
                        ASSERT_OK_ERRNO(ioctl(STDIN_FILENO, TIOCGWINSZ, &wsc));
                        ASSERT_EQ((unsigned) wsc.ws_row, expected_rows);
                        ASSERT_EQ((unsigned) wsc.ws_col, expected_columns);
                }

                _exit(EXIT_SUCCESS);
        }

        /* Parent: simulate terminal by reading queries and writing responses */
        peer_fd = safe_close(peer_fd);

        for (size_t i = 0; i < n_responses; i++) {
                /* Wait for the child to write a query */
                ASSERT_OK(fd_wait_for_event(master_fd, POLLIN, 5 * USEC_PER_SEC));

                /* Read and discard the query. The child writes the entire query via a single
                 * loop_write(), so all data is in the kernel buffer once POLLIN fires. */
                char buf[256];
                for (;;) {
                        ssize_t l = read(master_fd, buf, sizeof(buf));
                        if (l < 0) {
                                if (errno == EAGAIN)
                                        break;
                                ASSERT_OK_ERRNO(l);
                        }
                        if (l == 0)
                                break;
                }

                /* Write the simulated response */
                if (responses[i])
                        ASSERT_OK(loop_write(master_fd, responses[i], strlen(responses[i])));
        }

        /* Wait for child and check it exited successfully */
        ASSERT_OK(pidref_wait_for_terminate_and_check("(terminal-fix-size-test)", &child, WAIT_LOG));
}

/* CSI 18: valid response, size updated */
TEST(terminal_fix_size_csi18_pty) {
        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        STRV_MAKE_CONST("\x1B[8;24;80t"), 1,
                        /* expected_r= */ 1,
                        /* expected: */ 24, 80);
}

/* CSI 18: valid response, size already matches → no change */
TEST(terminal_fix_size_csi18_pty_unchanged) {
        test_terminal_fix_size_pty(
                        /* initial: */ 24, 80,
                        STRV_MAKE_CONST("\x1B[8;24;80t"), 1,
                        /* expected_r= */ 0,
                        /* expected: */ 24, 80);
}

/* CSI 18: valid response with large terminal size */
TEST(terminal_fix_size_csi18_pty_large) {
        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        STRV_MAKE_CONST("\x1B[8;200;300t"), 1,
                        /* expected_r= */ 1,
                        /* expected: */ 200, 300);
}

/* CSI 18 fails with -EINVAL, falls back to DSR which succeeds */
TEST(terminal_fix_size_csi18_fallback_to_dsr_pty) {
        const char *responses[] = {
                "\x1B[X;1;1t",   /* Invalid CSI 18 response → triggers DSR fallback */
                "\x1B[40;160R",  /* Valid DSR response */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 40, 160);
}

/* DSR: garbage bytes before valid CPR responses (state machine should handle this) */
TEST(terminal_fix_size_dsr_pty_garbage_prefix) {
        const char *responses[] = {
                NULL,                   /* No CSI 18 response → timeout */
                "garbage\x1B[50;132R",  /* DSR: garbage before valid CPR */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 50, 132);
}

/* DSR: bogus escape sequence before valid CPR responses */
TEST(terminal_fix_size_dsr_pty_bogus_escape) {
        const char *responses[] = {
                NULL,                    /* No CSI 18 response → timeout */
                "\x1B[?1X\x1B[80;120R",  /* DSR: bogus escape before valid CPR */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 80, 120);
}

/* DSR: row/column values too small (< 4) in size response → error */
TEST(terminal_fix_size_dsr_pty_too_small) {
        const char *responses[] = {
                NULL,         /* No CSI 18 response → timeout */
                "\x1B[2;2R",  /* DSR: too-small size */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ -ENODATA,
                        /* expected: */ 25, 80);
}

/* DSR: row/column values at boundary (>= 32766) → error */
TEST(terminal_fix_size_dsr_pty_too_large) {
        const char *responses[] = {
                NULL,                 /* No CSI 18 response → timeout */
                "\x1B[32766;32766R",  /* DSR: too-large size */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ -ENODATA,
                        /* expected: */ 25, 80);
}

/* No response at all (both CSI 18 and DSR time out) → error */
TEST(terminal_fix_size_pty_timeout) {
        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        NULL, 0,
                        /* expected_r= */ -EOPNOTSUPP,
                        /* expected: */ 25, 80);
}

/* Reproduces the core scenario from https://github.com/systemd/systemd/issues/35499:
 * CSI 18 times out (terminal doesn't respond), then DSR fallback succeeds. */
TEST(terminal_fix_size_csi18_timeout_fallback_to_dsr_pty) {
        const char *responses[] = {
                NULL,           /* No CSI 18 response → times out after 333ms */
                "\x1B[24;80R",  /* Valid DSR response */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 24, 80);
}

/* Simulates a late CSI 18 response arriving together with the DSR response.
 * This is the echo contamination scenario from https://github.com/systemd/systemd/issues/35499:
 * the CSI 18 query times out, the child sends DSR queries, but then a stale CSI 18 response
 * and the DSR responses arrive together. The DSR state machine must skip over the stale
 * CSI 18 bytes and parse the valid CPR responses. */
TEST(terminal_fix_size_csi18_late_response_with_dsr_pty) {
        const char *responses[] = {
                NULL,                           /* No CSI 18 response → timeout */
                "\x1B[8;30;90t" "\x1B[24;80R",  /* Late CSI 18 response + valid DSR response */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 24, 80);
}

/* CSI 18 response fills the buffer without a valid terminator → -EOPNOTSUPP → DSR fallback.
 * Simulates a terminal that sends an unrelated response instead of the CSI 18 answer. */
TEST(terminal_fix_size_csi18_buffer_full_fallback_to_dsr_pty) {
        const char *responses[] = {
                "\x1B[?62;4;6;22;99c",  /* Device Attributes response, fills CSI 18 buffer with no 't' terminator */
                "\x1B[24;80R",          /* Valid DSR response */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 24, 80);
}

/* DSR: unrelated escape sequence (Device Attributes) before valid CPR.
 * The state machine should skip non-CPR sequences and find the valid response. */
TEST(terminal_fix_size_dsr_pty_da_response_before_cpr) {
        const char *responses[] = {
                NULL,                               /* No CSI 18 response → timeout */
                "\x1B[?62;4;6;22c" "\x1B[50;132R",  /* DA response + valid CPR */
        };

        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        responses, ELEMENTSOF(responses),
                        /* expected_r= */ 1,
                        /* expected: */ 50, 132);
}

/* CSI 18: minimum valid terminal size (1x1) */
TEST(terminal_fix_size_csi18_pty_minimum) {
        test_terminal_fix_size_pty(
                        /* initial: */ 25, 80,
                        STRV_MAKE_CONST("\x1B[8;1;1t"), 1,
                        /* expected_r= */ 1,
                        /* expected: */ 1, 1);
}

/* Verifies that DECRC (\x1B8) is always sent as part of the DSR query, ensuring the cursor is
 * restored even when the DSR response times out. The old code only restored the cursor on success
 * (by querying the position first via a separate DSR, then moving back), leaving the cursor stuck
 * at the bottom-right corner on timeout — a visible artifact reported in #35499. */
TEST(terminal_fix_size_dsr_timeout_cursor_restore) {
        _cleanup_close_ int master_fd = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK, NULL));
        _cleanup_close_ int peer_fd = ASSERT_OK(pty_open_peer(master_fd, O_RDWR|O_NOCTTY|O_CLOEXEC));

        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r = pidref_safe_fork_full(
                        "(cursor-restore-test)",
                        (int[]) { peer_fd, peer_fd, peer_fd },
                        NULL, 0,
                        FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_REARRANGE_STDIO,
                        &child);
        ASSERT_OK(r);
        if (r == 0) {
                ASSERT_OK_ERRNO(setenv("TERM", "xterm", true));
                reset_terminal_feature_caches();

                /* Let both CSI 18 and DSR time out */
                (void) terminal_fix_size(STDIN_FILENO, STDOUT_FILENO);
                _exit(EXIT_SUCCESS);
        }

        peer_fd = safe_close(peer_fd);
        ASSERT_OK(pidref_wait_for_terminate_and_check("(cursor-restore-test)", &child, WAIT_LOG));

        /* Read all bytes the child wrote to the terminal. EIO is expected once the peer
         * side of the PTY is closed after the child exits. */
        char buf[512];
        size_t total = 0;
        for (;;) {
                ssize_t l = read(master_fd, buf + total, sizeof(buf) - total);
                if (l < 0) {
                        if (IN_SET(errno, EAGAIN, EIO))
                                break;
                        ASSERT_OK_ERRNO(l);
                }
                if (l == 0)
                        break;
                total += l;
        }

        /* The DSR query must include DECRC (\x1B8) to restore the cursor unconditionally.
         * The old code skipped cursor restore on timeout, leaving it at the bottom-right. */
        ASSERT_NOT_NULL(memmem_safe(buf, total, "\x1B" "8", 2));
}

DEFINE_TEST_MAIN(LOG_INFO);
