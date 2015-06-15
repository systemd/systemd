/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <errno.h>
#include <locale.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pty.h"
#include "util.h"
#include "signal-util.h"

static const char sndmsg[] = "message\n";
static const char rcvmsg[] = "message\r\n";
static char rcvbuf[128];
static size_t rcvsiz = 0;
static sd_event *event;

static void run_child(Pty *pty) {
        ssize_t r, l;
        char buf[512];

        r = read(0, buf, sizeof(buf));
        assert_se((size_t)r == strlen(sndmsg));
        assert_se(!strncmp(buf, sndmsg, r));

        l = write(1, buf, r);
        assert_se(l == r);
}

static int pty_fn(Pty *pty, void *userdata, unsigned int ev, const void *ptr, size_t size) {
        switch (ev) {
        case PTY_DATA:
                assert_se(rcvsiz < strlen(rcvmsg) * 2);
                assert_se(rcvsiz + size < sizeof(rcvbuf));

                memcpy(&rcvbuf[rcvsiz], ptr, size);
                rcvsiz += size;

                if (rcvsiz >= strlen(rcvmsg) * 2) {
                        assert_se(rcvsiz == strlen(rcvmsg) * 2);
                        assert_se(!memcmp(rcvbuf, rcvmsg, strlen(rcvmsg)));
                        assert_se(!memcmp(&rcvbuf[strlen(rcvmsg)], rcvmsg, strlen(rcvmsg)));
                }

                break;
        case PTY_HUP:
                /* This is guaranteed to appear _after_ the input queues are
                 * drained! */
                assert_se(rcvsiz == strlen(rcvmsg) * 2);
                break;
        case PTY_CHILD:
                /* this may appear at any time */
                break;
        default:
                assert_se(0);
                break;
        }

        /* if we got HUP _and_ CHILD, exit */
        if (pty_get_fd(pty) < 0 && pty_get_child(pty) < 0)
                sd_event_exit(event, 0);

        return 0;
}

static void run_parent(Pty *pty) {
        int r;

        /* write message to pty, ECHO mode guarantees that we get it back
         * twice: once via ECHO, once from the run_child() fn */
        assert_se(pty_write(pty, sndmsg, strlen(sndmsg)) >= 0);

        r = sd_event_loop(event);
        assert_se(r >= 0);
}

static void test_pty(void) {
        pid_t pid;
        Pty *pty = NULL;

        rcvsiz = 0;
        zero(rcvbuf);

        assert_se(sd_event_default(&event) >= 0);

        pid = pty_fork(&pty, event, pty_fn, NULL, 80, 25);
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */
                run_child(pty);
                exit(0);
        }

        /* parent */
        run_parent(pty);

        /* Make sure the PTY recycled the child; yeah, this is racy if the
         * PID was already reused; but that seems fine for a test. */
        assert_se(waitpid(pid, NULL, WNOHANG) < 0 && errno == ECHILD);

        pty_unref(pty);
        sd_event_unref(event);
}

int main(int argc, char *argv[]) {
        unsigned int i;

        log_parse_environment();
        log_open();

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, -1) >= 0);

        /* Oh, there're ugly races in the TTY layer regarding HUP vs IN. Turns
         * out they appear only 10% of the time. I fixed all of them and
         * don't see them, anymore. But lets be safe and run this 1000 times
         * so we catch any new ones, in case they appear again. */
        for (i = 0; i < 1000; ++i)
                test_pty();

        return 0;
}
