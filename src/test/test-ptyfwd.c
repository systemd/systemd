/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "sd-event.h"

#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "pidref.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"

/* Comfortably below the timeout terminal_query() applies if the terminal doesn't answer (333ms) */
#define ANSWER_TIMEOUT_USEC (300 * USEC_PER_MSEC)

static void read_reply(int fd, char final, char *buf, size_t size) {
        size_t n = 0;

        /* Reads a reply sequence from the terminal, up to and including the specified final character */

        usec_t end = usec_add(now(CLOCK_MONOTONIC), 5 * USEC_PER_SEC);
        for (;;) {
                ASSERT_LT(n, size - 1);

                usec_t t = now(CLOCK_MONOTONIC);
                ASSERT_LT(t, end);
                ASSERT_OK_POSITIVE(fd_wait_for_event(fd, POLLIN, usec_sub_unsigned(end, t)));

                ssize_t l = read(fd, buf + n, 1);
                if (l < 0 && errno == EAGAIN)
                        continue;
                ASSERT_OK_EQ_ERRNO(l, 1);

                if (buf[n++] == final)
                        break;
        }

        buf[n] = 0;
}

TEST(ptyfwd_answer_queries) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        int r;

        _cleanup_close_ int master = ASSERT_OK(openpt_allocate(O_RDWR|O_NOCTTY|O_NONBLOCK, /* ret_peer_path= */ NULL));
        _cleanup_close_ int peer = ASSERT_OK(pty_open_peer(master, O_RDWR|O_NOCTTY|O_NONBLOCK));
        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));

        /* Run a read-only forwarder whose output goes to a pipe, i.e. something that cannot answer any
         * queries, just like the journal when invoked as a service */
        r = ASSERT_OK(pidref_safe_fork_full(
                        "(ptyfwd)",
                        (int[]) { -EBADF, pipe_fds[1], STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_REARRANGE_STDIO,
                        &pidref));
        if (r == 0) {
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                _cleanup_(pty_forward_freep) PTYForward *f = NULL;

                peer = safe_close(peer);

                /* Without a tty on stdout the forwarder derives the dimensions from $COLUMNS/$LINES */
                ASSERT_OK_ERRNO(setenv("COLUMNS", "100", /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("LINES", "40", /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("TERM", "xterm-256color", /* overwrite= */ true));
                reset_terminal_feature_caches();

                ASSERT_OK(sd_event_new(&event));
                ASSERT_OK(pty_forward_new(event, master, PTY_FORWARD_READ_ONLY|PTY_FORWARD_ANSWER_QUERIES, &f));
                ASSERT_OK(sd_event_loop(event));

                _exit(EXIT_SUCCESS);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);
        master = safe_close(master);

        /* Wait until the forwarder is up, i.e. has set the dimensions of the pty */
        for (unsigned i = 0;; i++) {
                struct winsize ws = {};

                ASSERT_OK_ERRNO(ioctl(peer, TIOCGWINSZ, &ws));
                if (ws.ws_row == 40 && ws.ws_col == 100)
                        break;

                ASSERT_LT(i, 500U);
                ASSERT_OK(usleep_safe(10 * USEC_PER_MSEC));
        }

        /* Size queries are refused on dumb terminals, hence pretend we are not on one */
        ASSERT_OK_ERRNO(setenv("TERM", "xterm", /* overwrite= */ true));

        /* Size and terminfo name: must be answered without waiting for the timeout */
        unsigned rows = 0, columns = 0;
        _cleanup_free_ char *terminfo = NULL;
        usec_t n = now(CLOCK_MONOTONIC);
        ASSERT_OK(terminal_query(peer, peer, &rows, &columns, &terminfo));
        usec_t d = usec_sub_unsigned(now(CLOCK_MONOTONIC), n);
        log_info("terminal_query() for size and terminfo took %s", FORMAT_TIMESPAN(d, USEC_PER_MSEC));
        ASSERT_EQ(rows, 40U);
        ASSERT_EQ(columns, 100U);
        ASSERT_STREQ(terminfo, "xterm-256color");
        ASSERT_LT(d, ANSWER_TIMEOUT_USEC);

        /* Terminfo name only, i.e. DA1 as end marker */
        terminfo = mfree(terminfo);
        n = now(CLOCK_MONOTONIC);
        ASSERT_OK(terminal_query(peer, peer, /* ret_rows= */ NULL, /* ret_columns= */ NULL, &terminfo));
        d = usec_sub_unsigned(now(CLOCK_MONOTONIC), n);
        log_info("terminal_query() for terminfo took %s", FORMAT_TIMESPAN(d, USEC_PER_MSEC));
        ASSERT_STREQ(terminfo, "xterm-256color");
        ASSERT_LT(d, ANSWER_TIMEOUT_USEC);

        /* Now talk to the forwarder directly */
        struct termios t;
        ASSERT_OK_ERRNO(tcgetattr(peer, &t));
        cfmakeraw(&t);
        ASSERT_OK_ERRNO(tcsetattr(peer, TCSANOW, &t));

        char buf[64];

        /* The cursor position is reported directly after absolute positioning, clamped to the dimensions */
        ASSERT_OK(loop_write(peer, "\x1B[5;7H\x1B[6n", SIZE_MAX));
        read_reply(peer, 'R', buf, sizeof(buf));
        ASSERT_STREQ(buf, "\x1B[5;7R");

        ASSERT_OK(loop_write(peer, "\x1B[H\x1B[6n", SIZE_MAX));
        read_reply(peer, 'R', buf, sizeof(buf));
        ASSERT_STREQ(buf, "\x1B[1;1R");

        ASSERT_OK(loop_write(peer, "\x1B[999;999f\x1B[6n", SIZE_MAX));
        read_reply(peer, 'R', buf, sizeof(buf));
        ASSERT_STREQ(buf, "\x1B[40;100R");

        /* After regular output we don't know the cursor position anymore, hence DSR isn't answered, but the
         * DA1 after it is */
        ASSERT_OK(loop_write(peer, "\x1B[5;7Hx\x1B[6n\x1B[c", SIZE_MAX));
        read_reply(peer, 'c', buf, sizeof(buf));
        ASSERT_STREQ(buf, "\x1B[?62;22c");

        /* Other capabilities are reported as unsupported */
        ASSERT_OK(loop_write(peer, "\x1BP+q636F6C6F7273\x1B\\", SIZE_MAX));
        read_reply(peer, '\\', buf, sizeof(buf));
        ASSERT_STREQ(buf, "\x1BP0+r\x1B\\");

        /* Close the peer, which makes the forwarder exit, and check that none of the queries reached the
         * output, but everything else did */
        ASSERT_OK(loop_write(peer, "hello", SIZE_MAX));
        peer = safe_close(peer);

        _cleanup_fclose_ FILE *fp = ASSERT_NOT_NULL(take_fdopen(&pipe_fds[0], "r"));
        _cleanup_free_ char *output = NULL;
        ASSERT_OK(read_full_stream(fp, &output, /* ret_size= */ NULL));
        ASSERT_OK(pidref_wait_for_terminate_and_check("(ptyfwd)", &pidref, WAIT_LOG));
        pidref_done(&pidref);

        log_debug("Forwarded output: %s", output);
        ASSERT_NOT_NULL(strstr(output, "hello"));
        ASSERT_NOT_NULL(strstr(output, "\x1B[5;7H"));
        ASSERT_NULL(strstr(output, "\x1B[18t"));
        ASSERT_NULL(strstr(output, "\x1B[c"));
        ASSERT_NULL(strstr(output, "\x1BP"));

        /* Only the one DSR we didn't answer is forwarded */
        const char *p = ASSERT_NOT_NULL(strstr(output, "x\x1B[6n"));
        ASSERT_NULL(strstr(p + STRLEN("x\x1B[6n"), "\x1B[6n"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
