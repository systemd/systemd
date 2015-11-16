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

#include <limits.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "ptyfwd.h"
#include "util.h"

struct PTYForward {
        sd_event *event;

        int master;

        PTYForwardFlags flags;

        sd_event_source *stdin_event_source;
        sd_event_source *stdout_event_source;
        sd_event_source *master_event_source;

        sd_event_source *sigwinch_event_source;

        struct termios saved_stdin_attr;
        struct termios saved_stdout_attr;

        bool saved_stdin:1;
        bool saved_stdout:1;

        bool stdin_readable:1;
        bool stdin_hangup:1;
        bool stdout_writable:1;
        bool stdout_hangup:1;
        bool master_readable:1;
        bool master_writable:1;
        bool master_hangup:1;

        bool read_from_master:1;

        bool last_char_set:1;
        char last_char;

        char in_buffer[LINE_MAX], out_buffer[LINE_MAX];
        size_t in_buffer_full, out_buffer_full;

        usec_t escape_timestamp;
        unsigned escape_counter;
};

#define ESCAPE_USEC (1*USEC_PER_SEC)

static bool look_for_escape(PTYForward *f, const char *buffer, size_t n) {
        const char *p;

        assert(f);
        assert(buffer);
        assert(n > 0);

        for (p = buffer; p < buffer + n; p++) {

                /* Check for ^] */
                if (*p == 0x1D) {
                        usec_t nw = now(CLOCK_MONOTONIC);

                        if (f->escape_counter == 0 || nw > f->escape_timestamp + ESCAPE_USEC)  {
                                f->escape_timestamp = nw;
                                f->escape_counter = 1;
                        } else {
                                (f->escape_counter)++;

                                if (f->escape_counter >= 3)
                                        return true;
                        }
                } else {
                        f->escape_timestamp = 0;
                        f->escape_counter = 0;
                }
        }

        return false;
}

static bool ignore_vhangup(PTYForward *f) {
        assert(f);

        if (f->flags & PTY_FORWARD_IGNORE_VHANGUP)
                return true;

        if ((f->flags & PTY_FORWARD_IGNORE_INITIAL_VHANGUP) && !f->read_from_master)
                return true;

        return false;
}

static int shovel(PTYForward *f) {
        ssize_t k;

        assert(f);

        while ((f->stdin_readable && f->in_buffer_full <= 0) ||
               (f->master_writable && f->in_buffer_full > 0) ||
               (f->master_readable && f->out_buffer_full <= 0) ||
               (f->stdout_writable && f->out_buffer_full > 0)) {

                if (f->stdin_readable && f->in_buffer_full < LINE_MAX) {

                        k = read(STDIN_FILENO, f->in_buffer + f->in_buffer_full, LINE_MAX - f->in_buffer_full);
                        if (k < 0) {

                                if (errno == EAGAIN)
                                        f->stdin_readable = false;
                                else if (errno == EIO || errno == EPIPE || errno == ECONNRESET) {
                                        f->stdin_readable = false;
                                        f->stdin_hangup = true;

                                        f->stdin_event_source = sd_event_source_unref(f->stdin_event_source);
                                } else {
                                        log_error_errno(errno, "read(): %m");
                                        return sd_event_exit(f->event, EXIT_FAILURE);
                                }
                        } else if (k == 0) {
                                /* EOF on stdin */
                                f->stdin_readable = false;
                                f->stdin_hangup = true;

                                f->stdin_event_source = sd_event_source_unref(f->stdin_event_source);
                        } else  {
                                /* Check if ^] has been
                                 * pressed three times within
                                 * one second. If we get this
                                 * we quite immediately. */
                                if (look_for_escape(f, f->in_buffer + f->in_buffer_full, k))
                                        return sd_event_exit(f->event, EXIT_FAILURE);

                                f->in_buffer_full += (size_t) k;
                        }
                }

                if (f->master_writable && f->in_buffer_full > 0) {

                        k = write(f->master, f->in_buffer, f->in_buffer_full);
                        if (k < 0) {

                                if (errno == EAGAIN || errno == EIO)
                                        f->master_writable = false;
                                else if (errno == EPIPE || errno == ECONNRESET) {
                                        f->master_writable = f->master_readable = false;
                                        f->master_hangup = true;

                                        f->master_event_source = sd_event_source_unref(f->master_event_source);
                                } else {
                                        log_error_errno(errno, "write(): %m");
                                        return sd_event_exit(f->event, EXIT_FAILURE);
                                }
                        } else {
                                assert(f->in_buffer_full >= (size_t) k);
                                memmove(f->in_buffer, f->in_buffer + k, f->in_buffer_full - k);
                                f->in_buffer_full -= k;
                        }
                }

                if (f->master_readable && f->out_buffer_full < LINE_MAX) {

                        k = read(f->master, f->out_buffer + f->out_buffer_full, LINE_MAX - f->out_buffer_full);
                        if (k < 0) {

                                /* Note that EIO on the master device
                                 * might be caused by vhangup() or
                                 * temporary closing of everything on
                                 * the other side, we treat it like
                                 * EAGAIN here and try again, unless
                                 * ignore_vhangup is off. */

                                if (errno == EAGAIN || (errno == EIO && ignore_vhangup(f)))
                                        f->master_readable = false;
                                else if (errno == EPIPE || errno == ECONNRESET || errno == EIO) {
                                        f->master_readable = f->master_writable = false;
                                        f->master_hangup = true;

                                        f->master_event_source = sd_event_source_unref(f->master_event_source);
                                } else {
                                        log_error_errno(errno, "read(): %m");
                                        return sd_event_exit(f->event, EXIT_FAILURE);
                                }
                        }  else {
                                f->read_from_master = true;
                                f->out_buffer_full += (size_t) k;
                        }
                }

                if (f->stdout_writable && f->out_buffer_full > 0) {

                        k = write(STDOUT_FILENO, f->out_buffer, f->out_buffer_full);
                        if (k < 0) {

                                if (errno == EAGAIN)
                                        f->stdout_writable = false;
                                else if (errno == EIO || errno == EPIPE || errno == ECONNRESET) {
                                        f->stdout_writable = false;
                                        f->stdout_hangup = true;
                                        f->stdout_event_source = sd_event_source_unref(f->stdout_event_source);
                                } else {
                                        log_error_errno(errno, "write(): %m");
                                        return sd_event_exit(f->event, EXIT_FAILURE);
                                }

                        } else {

                                if (k > 0) {
                                        f->last_char = f->out_buffer[k-1];
                                        f->last_char_set = true;
                                }

                                assert(f->out_buffer_full >= (size_t) k);
                                memmove(f->out_buffer, f->out_buffer + k, f->out_buffer_full - k);
                                f->out_buffer_full -= k;
                        }
                }
        }

        if (f->stdin_hangup || f->stdout_hangup || f->master_hangup) {
                /* Exit the loop if any side hung up and if there's
                 * nothing more to write or nothing we could write. */

                if ((f->out_buffer_full <= 0 || f->stdout_hangup) &&
                    (f->in_buffer_full <= 0 || f->master_hangup))
                        return sd_event_exit(f->event, EXIT_SUCCESS);
        }

        return 0;
}

static int on_master_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = userdata;

        assert(f);
        assert(e);
        assert(e == f->master_event_source);
        assert(fd >= 0);
        assert(fd == f->master);

        if (revents & (EPOLLIN|EPOLLHUP))
                f->master_readable = true;

        if (revents & (EPOLLOUT|EPOLLHUP))
                f->master_writable = true;

        return shovel(f);
}

static int on_stdin_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = userdata;

        assert(f);
        assert(e);
        assert(e == f->stdin_event_source);
        assert(fd >= 0);
        assert(fd == STDIN_FILENO);

        if (revents & (EPOLLIN|EPOLLHUP))
                f->stdin_readable = true;

        return shovel(f);
}

static int on_stdout_event(sd_event_source *e, int fd, uint32_t revents, void *userdata) {
        PTYForward *f = userdata;

        assert(f);
        assert(e);
        assert(e == f->stdout_event_source);
        assert(fd >= 0);
        assert(fd == STDOUT_FILENO);

        if (revents & (EPOLLOUT|EPOLLHUP))
                f->stdout_writable = true;

        return shovel(f);
}

static int on_sigwinch_event(sd_event_source *e, const struct signalfd_siginfo *si, void *userdata) {
        PTYForward *f = userdata;
        struct winsize ws;

        assert(f);
        assert(e);
        assert(e == f->sigwinch_event_source);

        /* The window size changed, let's forward that. */
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
                (void) ioctl(f->master, TIOCSWINSZ, &ws);

        return 0;
}

int pty_forward_new(
                sd_event *event,
                int master,
                PTYForwardFlags flags,
                PTYForward **ret) {

        _cleanup_(pty_forward_freep) PTYForward *f = NULL;
        struct winsize ws;
        int r;

        f = new0(PTYForward, 1);
        if (!f)
                return -ENOMEM;

        f->flags = flags;

        if (event)
                f->event = sd_event_ref(event);
        else {
                r = sd_event_default(&f->event);
                if (r < 0)
                        return r;
        }

        if (!(flags & PTY_FORWARD_READ_ONLY)) {
                r = fd_nonblock(STDIN_FILENO, true);
                if (r < 0)
                        return r;

                r = fd_nonblock(STDOUT_FILENO, true);
                if (r < 0)
                        return r;
        }

        r = fd_nonblock(master, true);
        if (r < 0)
                return r;

        f->master = master;

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
                (void) ioctl(master, TIOCSWINSZ, &ws);

        if (!(flags & PTY_FORWARD_READ_ONLY)) {
                if (tcgetattr(STDIN_FILENO, &f->saved_stdin_attr) >= 0) {
                        struct termios raw_stdin_attr;

                        f->saved_stdin = true;

                        raw_stdin_attr = f->saved_stdin_attr;
                        cfmakeraw(&raw_stdin_attr);
                        raw_stdin_attr.c_oflag = f->saved_stdin_attr.c_oflag;
                        tcsetattr(STDIN_FILENO, TCSANOW, &raw_stdin_attr);
                }

                if (tcgetattr(STDOUT_FILENO, &f->saved_stdout_attr) >= 0) {
                        struct termios raw_stdout_attr;

                        f->saved_stdout = true;

                        raw_stdout_attr = f->saved_stdout_attr;
                        cfmakeraw(&raw_stdout_attr);
                        raw_stdout_attr.c_iflag = f->saved_stdout_attr.c_iflag;
                        raw_stdout_attr.c_lflag = f->saved_stdout_attr.c_lflag;
                        tcsetattr(STDOUT_FILENO, TCSANOW, &raw_stdout_attr);
                }

                r = sd_event_add_io(f->event, &f->stdin_event_source, STDIN_FILENO, EPOLLIN|EPOLLET, on_stdin_event, f);
                if (r < 0 && r != -EPERM)
                        return r;
        }

        r = sd_event_add_io(f->event, &f->stdout_event_source, STDOUT_FILENO, EPOLLOUT|EPOLLET, on_stdout_event, f);
        if (r == -EPERM)
                /* stdout without epoll support. Likely redirected to regular file. */
                f->stdout_writable = true;
        else if (r < 0)
                return r;

        r = sd_event_add_io(f->event, &f->master_event_source, master, EPOLLIN|EPOLLOUT|EPOLLET, on_master_event, f);
        if (r < 0)
                return r;

        r = sd_event_add_signal(f->event, &f->sigwinch_event_source, SIGWINCH, on_sigwinch_event, f);
        if (r < 0)
                return r;

        *ret = f;
        f = NULL;

        return 0;
}

PTYForward *pty_forward_free(PTYForward *f) {

        if (f) {
                sd_event_source_unref(f->stdin_event_source);
                sd_event_source_unref(f->stdout_event_source);
                sd_event_source_unref(f->master_event_source);
                sd_event_source_unref(f->sigwinch_event_source);
                sd_event_unref(f->event);

                if (f->saved_stdout)
                        tcsetattr(STDOUT_FILENO, TCSANOW, &f->saved_stdout_attr);
                if (f->saved_stdin)
                        tcsetattr(STDIN_FILENO, TCSANOW, &f->saved_stdin_attr);

                free(f);
        }

        /* STDIN/STDOUT should not be nonblocking normally, so let's
         * unconditionally reset it */
        fd_nonblock(STDIN_FILENO, false);
        fd_nonblock(STDOUT_FILENO, false);

        return NULL;
}

int pty_forward_get_last_char(PTYForward *f, char *ch) {
        assert(f);
        assert(ch);

        if (!f->last_char_set)
                return -ENXIO;

        *ch = f->last_char;
        return 0;
}

int pty_forward_set_ignore_vhangup(PTYForward *f, bool b) {
        int r;

        assert(f);

        if (!!(f->flags & PTY_FORWARD_IGNORE_VHANGUP) == b)
                return 0;

        if (b)
                f->flags |= PTY_FORWARD_IGNORE_VHANGUP;
        else
                f->flags &= ~PTY_FORWARD_IGNORE_VHANGUP;

        if (!ignore_vhangup(f)) {

                /* We shall now react to vhangup()s? Let's check
                 * immediately if we might be in one */

                f->master_readable = true;
                r = shovel(f);
                if (r < 0)
                        return r;
        }

        return 0;
}

int pty_forward_get_ignore_vhangup(PTYForward *f) {
        assert(f);

        return !!(f->flags & PTY_FORWARD_IGNORE_VHANGUP);
}
