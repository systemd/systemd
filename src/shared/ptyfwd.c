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

int process_pty(int master, sigset_t *mask, pid_t kill_pid, int signo) {
        char in_buffer[LINE_MAX], out_buffer[LINE_MAX];
        size_t in_buffer_full = 0, out_buffer_full = 0;
        struct epoll_event stdin_ev, stdout_ev, master_ev, signal_ev;
        bool stdin_readable = false, stdout_writable = false, master_readable = false, master_writable = false;
        bool tried_orderly_shutdown = false;
        _cleanup_close_ int ep = -1, signal_fd = -1;

        assert(master >= 0);
        assert(mask);
        assert(kill_pid == 0 || kill_pid > 1);
        assert(signo >= 0 && signo < _NSIG);

        fd_nonblock(STDIN_FILENO, 1);
        fd_nonblock(STDOUT_FILENO, 1);
        fd_nonblock(master, 1);

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

                nfds = epoll_wait(ep, ev, ELEMENTSOF(ev), -1);
                if (nfds < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll_wait(): %m");
                        return -errno;
                }

                assert(nfds >= 1);

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

                        } else if (ev[i].data.fd == signal_fd) {
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
                                                if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0)
                                                        ioctl(master, TIOCSWINSZ, &ws);

                                        } else if (sfsi.ssi_signo == SIGTERM && kill_pid > 0 && signo > 0 && !tried_orderly_shutdown) {

                                                if (kill(kill_pid, signo) < 0)
                                                        return 0;

                                                log_info("Trying to halt container. Send SIGTERM again to trigger immediate termination.");

                                                /* This only works for systemd... */
                                                tried_orderly_shutdown = true;

                                        } else
                                                return 0;
                                }
                        }
                }

                while ((stdin_readable && in_buffer_full <= 0) ||
                       (master_writable && in_buffer_full > 0) ||
                       (master_readable && out_buffer_full <= 0) ||
                       (stdout_writable && out_buffer_full > 0)) {

                        if (stdin_readable && in_buffer_full < LINE_MAX) {

                                k = read(STDIN_FILENO, in_buffer + in_buffer_full, LINE_MAX - in_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                stdin_readable = false;
                                        else {
                                                log_error("read(): %m");
                                                return -errno;
                                        }
                                } else
                                        in_buffer_full += (size_t) k;
                        }

                        if (master_writable && in_buffer_full > 0) {

                                k = write(master, in_buffer, in_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                master_writable = false;
                                        else {
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

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                master_readable = false;
                                        else {
                                                log_error("read(): %m");
                                                return -errno;
                                        }
                                }  else
                                        out_buffer_full += (size_t) k;
                        }

                        if (stdout_writable && out_buffer_full > 0) {

                                k = write(STDOUT_FILENO, out_buffer, out_buffer_full);
                                if (k < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                stdout_writable = false;
                                        else {
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
        }
}
