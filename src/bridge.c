/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <stddef.h>

#include "log.h"
#include "util.h"
#include "socket-util.h"

#define BUFFER_SIZE (64*1024)
#define EXTRA_SIZE 16

static bool initial_nul = false;
static bool auth_over = false;

static void format_uid(char *buf, size_t l) {
        char text[20 + 1]; /* enough space for a 64bit integer plus NUL */
        unsigned j;

        assert(l > 0);

        snprintf(text, sizeof(text)-1, "%llu", (unsigned long long) geteuid());
        text[sizeof(text)-1] = 0;

        memset(buf, 0, l);

        for (j = 0; text[j] && j*2+2 < l; j++) {
                buf[j*2]   = hexchar(text[j] >> 4);
                buf[j*2+1] = hexchar(text[j] & 0xF);
        }

        buf[j*2] = 0;
}

static size_t patch_in_line(char *line, size_t l, size_t left) {
        size_t r;

        if (line[0] == 0 && !initial_nul) {
                initial_nul = true;
                line += 1;
                l -= 1;
                r = 1;
        } else
                r = 0;

        if (l == 5 && strncmp(line, "BEGIN", 5) == 0) {
                r += l;
                auth_over = true;

        } else if (l == 17 && strncmp(line, "NEGOTIATE_UNIX_FD", 17) == 0) {
                memmove(line + 13, line + 17, left);
                memcpy(line, "NEGOTIATE_NOP", 13);
                r += 13;

        } else if (l >= 14 && strncmp(line, "AUTH EXTERNAL ", 14) == 0) {
                char uid[20*2 + 1];
                size_t len;

                format_uid(uid, sizeof(uid));
                len = strlen(uid);
                assert(len <= EXTRA_SIZE);

                memmove(line + 14 + len, line + l, left);
                memcpy(line + 14, uid, len);

                r += 14 + len;
        } else
                r += l;

        return r;
}

static size_t patch_in_buffer(char* in_buffer, size_t *in_buffer_full) {
        size_t i, good = 0;

        if (*in_buffer_full <= 0)
                return *in_buffer_full;

        /* If authentication is done, we don't touch anything anymore */
        if (auth_over)
                return *in_buffer_full;

        if (*in_buffer_full < 2)
                return 0;

        for (i = 0; i <= *in_buffer_full - 2; i ++) {

                /* Fully lines can be send on */
                if (in_buffer[i] == '\r' && in_buffer[i+1] == '\n') {
                        if (i > good) {
                                size_t old_length, new_length;

                                old_length = i - good;
                                new_length = patch_in_line(in_buffer+good, old_length, *in_buffer_full - i);
                                *in_buffer_full = *in_buffer_full + new_length - old_length;

                                good += new_length + 2;

                        } else
                                good = i+2;
                }

                if (auth_over)
                        break;
        }

        return good;
}

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE, fd = -1, ep = -1;
        union sockaddr_union sa;
        char in_buffer[BUFFER_SIZE+EXTRA_SIZE], out_buffer[BUFFER_SIZE+EXTRA_SIZE];
        size_t in_buffer_full = 0, out_buffer_full = 0;
        struct epoll_event stdin_ev, stdout_ev, fd_ev;
        bool stdin_readable = false, stdout_writable = false, fd_readable = false, fd_writable = false;
        bool stdin_rhup = false, stdout_whup = false, fd_rhup = false, fd_whup = false;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        if ((fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)) < 0) {
                log_error("Failed to create socket: %s", strerror(errno));
                goto finish;
        }

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/run/dbus/system_bus_socket", sizeof(sa.un.sun_path));

        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1)) < 0) {
                log_error("Failed to connect: %m");
                goto finish;
        }

        fd_nonblock(STDIN_FILENO, 1);
        fd_nonblock(STDOUT_FILENO, 1);

        if ((ep = epoll_create1(EPOLL_CLOEXEC)) < 0) {
                log_error("Failed to create epoll: %m");
                goto finish;
        }

        zero(stdin_ev);
        stdin_ev.events = EPOLLIN|EPOLLET;
        stdin_ev.data.fd = STDIN_FILENO;

        zero(stdout_ev);
        stdout_ev.events = EPOLLOUT|EPOLLET;
        stdout_ev.data.fd = STDOUT_FILENO;

        zero(fd_ev);
        fd_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
        fd_ev.data.fd = fd;

        if (epoll_ctl(ep, EPOLL_CTL_ADD, STDIN_FILENO, &stdin_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, STDOUT_FILENO, &stdout_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, fd, &fd_ev) < 0) {
                log_error("Failed to regiser fds in epoll: %m");
                goto finish;
        }

        do {
                struct epoll_event ev[16];
                ssize_t k;
                int i, nfds;

                if ((nfds = epoll_wait(ep, ev, ELEMENTSOF(ev), -1)) < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll_wait(): %m");
                        goto finish;
                }

                assert(nfds >= 1);

                for (i = 0; i < nfds; i++) {
                        if (ev[i].data.fd == STDIN_FILENO) {

                                if (!stdin_rhup && (ev[i].events & (EPOLLHUP|EPOLLIN)))
                                        stdin_readable = true;

                        } else if (ev[i].data.fd == STDOUT_FILENO) {

                                if (ev[i].events & EPOLLHUP) {
                                        stdout_writable = false;
                                        stdout_whup = true;
                                }

                                if (!stdout_whup && (ev[i].events & EPOLLOUT))
                                        stdout_writable = true;

                        } else if (ev[i].data.fd == fd) {

                                if (ev[i].events & EPOLLHUP) {
                                        fd_writable = false;
                                        fd_whup = true;
                                }

                                if (!fd_rhup && (ev[i].events & (EPOLLHUP|EPOLLIN)))
                                        fd_readable = true;

                                if (!fd_whup && (ev[i].events & EPOLLOUT))
                                        fd_writable = true;
                        }
                }

                while ((stdin_readable && in_buffer_full <= 0) ||
                       (fd_writable && patch_in_buffer(in_buffer, &in_buffer_full) > 0) ||
                       (fd_readable && out_buffer_full <= 0) ||
                       (stdout_writable && out_buffer_full > 0)) {

                        size_t in_buffer_good = 0;

                        if (stdin_readable && in_buffer_full < BUFFER_SIZE) {

                                if ((k = read(STDIN_FILENO, in_buffer + in_buffer_full, BUFFER_SIZE - in_buffer_full)) < 0) {

                                        if (errno == EAGAIN)
                                                stdin_readable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET)
                                                k = 0;
                                        else {
                                                log_error("read(): %m");
                                                goto finish;
                                        }
                                } else
                                        in_buffer_full += (size_t) k;

                                if (k == 0) {
                                        stdin_rhup = true;
                                        stdin_readable = false;
                                        shutdown(STDIN_FILENO, SHUT_RD);
                                        close_nointr_nofail(STDIN_FILENO);
                                }
                        }

                        in_buffer_good = patch_in_buffer(in_buffer, &in_buffer_full);

                        if (fd_writable && in_buffer_good > 0) {

                                if ((k = write(fd, in_buffer, in_buffer_good)) < 0) {

                                        if (errno == EAGAIN)
                                                fd_writable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET) {
                                                fd_whup = true;
                                                fd_writable = false;
                                                shutdown(fd, SHUT_WR);
                                        } else {
                                                log_error("write(): %m");
                                                goto finish;
                                        }

                                } else {
                                        assert(in_buffer_full >= (size_t) k);
                                        memmove(in_buffer, in_buffer + k, in_buffer_full - k);
                                        in_buffer_full -= k;
                                }
                        }

                        if (fd_readable && out_buffer_full < BUFFER_SIZE) {

                                if ((k = read(fd, out_buffer + out_buffer_full, BUFFER_SIZE - out_buffer_full)) < 0) {

                                        if (errno == EAGAIN)
                                                fd_readable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET)
                                                k = 0;
                                        else {
                                                log_error("read(): %m");
                                                goto finish;
                                        }
                                }  else
                                        out_buffer_full += (size_t) k;

                                if (k == 0) {
                                        fd_rhup = true;
                                        fd_readable = false;
                                        shutdown(fd, SHUT_RD);
                                }
                        }

                        if (stdout_writable && out_buffer_full > 0) {

                                if ((k = write(STDOUT_FILENO, out_buffer, out_buffer_full)) < 0) {

                                        if (errno == EAGAIN)
                                                stdout_writable = false;
                                        else if (errno == EPIPE || errno == ECONNRESET) {
                                                stdout_whup = true;
                                                stdout_writable = false;
                                                shutdown(STDOUT_FILENO, SHUT_WR);
                                                close_nointr(STDOUT_FILENO);
                                        } else {
                                                log_error("write(): %m");
                                                goto finish;
                                        }

                                } else {
                                        assert(out_buffer_full >= (size_t) k);
                                        memmove(out_buffer, out_buffer + k, out_buffer_full - k);
                                        out_buffer_full -= k;
                                }
                        }
                }

                if (stdin_rhup && in_buffer_full <= 0 && !fd_whup) {
                        fd_whup = true;
                        fd_writable = false;
                        shutdown(fd, SHUT_WR);
                }

                if (fd_rhup && out_buffer_full <= 0 && !stdout_whup) {
                        stdout_whup = true;
                        stdout_writable = false;
                        shutdown(STDOUT_FILENO, SHUT_WR);
                        close_nointr(STDOUT_FILENO);
                }

        } while (!stdout_whup || !fd_whup);

        r = EXIT_SUCCESS;

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        if (ep >= 0)
                close_nointr_nofail(ep);

        return r;
}
