/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2013 Lennart Poettering

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

#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <termios.h>

#include "util.h"
#include "ptyfwd.h"

#define ESCAPE_USEC USEC_PER_SEC

static bool look_for_escape(usec_t *timestamp, unsigned *counter, const char *buffer, size_t n) {
        const char *p;

        assert(timestamp);
        assert(counter);
        assert(buffer);
        assert(n > 0);

        for (p = buffer; p < buffer + n; p++) {

                /* Check for ^] */
                if (*p == 0x1D) {
                        usec_t nw = now(CLOCK_MONOTONIC);

                        if (*counter == 0 || nw > *timestamp + USEC_PER_SEC)  {
                                *timestamp = nw;
                                *counter = 1;
                        } else {
                                (*counter)++;

                                if (*counter >= 3)
                                        return true;
                        }
                } else {
                        *timestamp = 0;
                        *counter = 0;
                }
        }

        return false;
}

static int process_pty_loop(int master, sigset_t *mask, pid_t kill_pid, int signo) {
        char in_buffer[LINE_MAX], out_buffer[LINE_MAX];
        size_t in_buffer_full = 0, out_buffer_full = 0;
        struct epoll_event stdin_ev, stdout_ev, master_ev, signal_ev;
        bool stdin_readable = false, stdout_writable = false, master_readable = false, master_writable = false;
        bool stdin_hangup = false, stdout_hangup = false, master_hangup = false;
        bool tried_orderly_shutdown = false, process_signalfd = false, quit = false;
        usec_t escape_timestamp = 0;
        unsigned escape_counter = 0;
        _cleanup_close_ int ep = -1, signal_fd = -1;

        assert(master >= 0);
        assert(mask);
        assert(kill_pid == 0 || kill_pid > 1);
        assert(signo >= 0 && signo < _NSIG);

        fd_nonblock(STDIN_FILENO, true);
        fd_nonblock(STDOUT_FILENO, true);
        fd_nonblock(master, true);

        signal_fd = signalfd(-1, mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0) {
                log_error("signalfd(): %m");
                return -errno;
        }

        ep = epoll_create1(EPOLL_CLOEXEC);
        if (ep < 0) {
                log_error("Failed to create epoll: %m");
                return -errno;
        }

        /* We read from STDIN only if this is actually a TTY,
         * otherwise we assume non-interactivity. */
        if (isatty(STDIN_FILENO)) {
                zero(stdin_ev);
                stdin_ev.events = EPOLLIN|EPOLLET;
                stdin_ev.data.fd = STDIN_FILENO;

                if (epoll_ctl(ep, EPOLL_CTL_ADD, STDIN_FILENO, &stdin_ev) < 0) {
                        log_error("Failed to register STDIN in epoll: %m");
                        return -errno;
                }
        }

        zero(stdout_ev);
        stdout_ev.events = EPOLLOUT|EPOLLET;
        stdout_ev.data.fd = STDOUT_FILENO;

        zero(master_ev);
        master_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
        master_ev.data.fd = master;

        zero(signal_ev);
        signal_ev.events = EPOLLIN;
        signal_ev.data.fd = signal_fd;

        if (epoll_ctl(ep, EPOLL_CTL_ADD, STDOUT_FILENO, &stdout_ev) < 0) {
                if (errno != EPERM) {
                        log_error("Failed to register stdout in epoll: %m");
                        return -errno;
                }

                /* stdout without epoll support. Likely redirected to regular file. */
                stdout_writable = true;
        }

        if (epoll_ctl(ep, EPOLL_CTL_ADD, master, &master_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, signal_fd, &signal_ev) < 0) {
                log_error("Failed to register fds in epoll: %m");
                return -errno;
        }

        for (;;) {
                struct epoll_event ev[16];
                ssize_t k;
                int i, nfds;

                nfds = epoll_wait(ep, ev, ELEMENTSOF(ev), quit ? 0 : -1);
                if (nfds < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll_wait(): %m");
                        return -errno;
                }

                if (nfds == 0)
                        return 0;

                for (i = 0; i < nfds; i++) {
                        if (ev[i].data.fd == STDIN_FILENO) {

                                if (ev[i].events & (EPOLLIN|EPOLLHUP))
                                        stdin_readable = true;

                        } else if (ev[i].data.fd == STDOUT_FILENO) {

                                if (ev[i].events & (EPOLLOUT|EPOLLHUP))
                                        stdout_writable = true;

                        } else if (ev[i].data.fd == master) {

                                if (ev[i].events & (EPOLLIN|EPOLLHUP))
                                        master_readable = true;

                                if (ev[i].events & (EPOLLOUT|EPOLLHUP))
                                        master_writable = true;

                        } else if (ev[i].data.fd == signal_fd)
                                process_signalfd = true;
                }

                while ((stdin_readable && in_buffer_full <= 0) ||
                       (master_writable && in_buffer_full > 0) ||
                       (master_readable && out_buffer_full <= 0) ||
                       (stdout_writable && out_buffer_full > 0)) {

                        if (stdin_readable && in_buffer_full < LINE_MAX) {

                                k = read(STDIN_FILENO, in_buffer + in_buffer_full, LINE_MAX - in_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN)
                                                stdin_readable = false;
                                        else if (errno == EIO || errno == EPIPE || errno == ECONNRESET) {
                                                stdin_readable = false;
                                                stdin_hangup = true;
                                                epoll_ctl(ep, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                                        } else {
                                                log_error("read(): %m");
                                                return -errno;
                                        }
                                } else {
                                        /* Check if ^] has been
                                         * pressed three times within
                                         * one second. If we get this
                                         * we quite immediately. */
                                        if (look_for_escape(&escape_timestamp, &escape_counter, in_buffer + in_buffer_full, k))
                                                return !quit;

                                        in_buffer_full += (size_t) k;
                                }
                        }

                        if (master_writable && in_buffer_full > 0) {

                                k = write(master, in_buffer, in_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN || errno == EIO)
                                                master_writable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET) {
                                                master_writable = master_readable = false;
                                                master_hangup = true;
                                                epoll_ctl(ep, EPOLL_CTL_DEL, master, NULL);
                                        } else {
                                                log_error("write(): %m");
                                                return -errno;
                                        }

                                } else {
                                        assert(in_buffer_full >= (size_t) k);
                                        memmove(in_buffer, in_buffer + k, in_buffer_full - k);
                                        in_buffer_full -= k;
                                }
                        }

                        if (master_readable && out_buffer_full < LINE_MAX) {

                                k = read(master, out_buffer + out_buffer_full, LINE_MAX - out_buffer_full);
                                if (k < 0) {

                                        /* Note that EIO on the master
                                         * device might be cause by
                                         * vhangup() or temporary
                                         * closing of everything on
                                         * the other side, we treat it
                                         * like EAGAIN here and try
                                         * again. */

                                        if (errno == EAGAIN || errno == EIO)
                                                master_readable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET) {
                                                master_readable = master_writable = false;
                                                master_hangup = true;
                                                epoll_ctl(ep, EPOLL_CTL_DEL, master, NULL);
                                        } else {
                                                log_error("read(): %m");
                                                return -errno;
                                        }
                                }  else
                                        out_buffer_full += (size_t) k;
                        }

                        if (stdout_writable && out_buffer_full > 0) {

                                k = write(STDOUT_FILENO, out_buffer, out_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN)
                                                stdout_writable = false;
                                        else if (errno == EIO || errno == EPIPE || errno == ECONNRESET) {
                                                stdout_writable = false;
                                                stdout_hangup = true;
                                                epoll_ctl(ep, EPOLL_CTL_DEL, STDOUT_FILENO, NULL);
                                        } else {
                                                log_error("write(): %m");
                                                return -errno;
                                        }

                                } else {
                                        assert(out_buffer_full >= (size_t) k);
                                        memmove(out_buffer, out_buffer + k, out_buffer_full - k);
                                        out_buffer_full -= k;
                                }
                        }

                }

                if (process_signalfd) {
                        struct signalfd_siginfo sfsi;
                        ssize_t n;

                        n = read(signal_fd, &sfsi, sizeof(sfsi));
                        if (n != sizeof(sfsi)) {

                                if (n >= 0) {
                                        log_error("Failed to read from signalfd: invalid block size");
                                        return -EIO;
                                }

                                if (errno != EINTR && errno != EAGAIN) {
                                        log_error("Failed to read from signalfd: %m");
                                        return -errno;
                                }
                        } else {

                                if (sfsi.ssi_signo == SIGWINCH) {
                                        struct winsize ws;

                                        /* The window size changed, let's forward that. */
                                        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
                                                ioctl(master, TIOCSWINSZ, &ws);

                                } else if (sfsi.ssi_signo == SIGTERM && kill_pid > 0 && signo > 0 && !tried_orderly_shutdown) {

                                        if (kill(kill_pid, signo) < 0)
                                                quit = true;
                                        else {
                                                log_info("Trying to halt container. Send SIGTERM again to trigger immediate termination.");

                                                /* This only works for systemd... */
                                                tried_orderly_shutdown = true;
                                        }

                                } else
                                        /* Signals that where
                                         * delivered via signalfd that
                                         * we didn't know are a reason
                                         * for us to quit */
                                        quit = true;
                        }
                }

                if (stdin_hangup || stdout_hangup || master_hangup) {
                        /* Exit the loop if any side hung up and if
                         * there's nothing more to write or nothing we
                         * could write. */

                        if ((out_buffer_full <= 0 || stdout_hangup) &&
                            (in_buffer_full <= 0 || master_hangup))
                                return !quit;
                }
        }
}

int process_pty(int master, sigset_t *mask, pid_t kill_pid, int signo) {
        struct termios saved_stdin_attr, raw_stdin_attr;
        struct termios saved_stdout_attr, raw_stdout_attr;
        bool saved_stdin = false;
        bool saved_stdout = false;
        struct winsize ws;
        int r;

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
                ioctl(master, TIOCSWINSZ, &ws);

        if (tcgetattr(STDIN_FILENO, &saved_stdin_attr) >= 0) {
                saved_stdin = true;

                raw_stdin_attr = saved_stdin_attr;
                cfmakeraw(&raw_stdin_attr);
                raw_stdin_attr.c_oflag = saved_stdin_attr.c_oflag;
                tcsetattr(STDIN_FILENO, TCSANOW, &raw_stdin_attr);
        }
        if (tcgetattr(STDOUT_FILENO, &saved_stdout_attr) >= 0) {
                saved_stdout = true;

                raw_stdout_attr = saved_stdout_attr;
                cfmakeraw(&raw_stdout_attr);
                raw_stdout_attr.c_iflag = saved_stdout_attr.c_iflag;
                raw_stdout_attr.c_lflag = saved_stdout_attr.c_lflag;
                tcsetattr(STDOUT_FILENO, TCSANOW, &raw_stdout_attr);
        }

        r = process_pty_loop(master, mask, kill_pid, signo);

        if (saved_stdout)
                tcsetattr(STDOUT_FILENO, TCSANOW, &saved_stdout_attr);
        if (saved_stdin)
                tcsetattr(STDIN_FILENO, TCSANOW, &saved_stdin_attr);

        /* STDIN/STDOUT should not be nonblocking normally, so let's
         * unconditionally reset it */
        fd_nonblock(STDIN_FILENO, false);
        fd_nonblock(STDOUT_FILENO, false);

        return r;

}
