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
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "shutdownd.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "sd-daemon.h"

static int read_packet(int fd, struct shutdownd_command *_c) {
        struct msghdr msghdr;
        struct iovec iovec;
        struct ucred *ucred;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control;
        struct shutdownd_command c;
        ssize_t n;

        assert(fd >= 0);
        assert(_c);

        zero(iovec);
        iovec.iov_base = &c;
        iovec.iov_len = sizeof(c);

        zero(control);
        zero(msghdr);
        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = &control;
        msghdr.msg_controllen = sizeof(control);

        if ((n = recvmsg(fd, &msghdr, MSG_DONTWAIT)) <= 0) {
                if (n >= 0) {
                        log_error("Short read");
                        return -EIO;
                }

                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                log_error("recvmsg(): %m");
                return -errno;
        }

        if (msghdr.msg_controllen < CMSG_LEN(sizeof(struct ucred)) ||
            control.cmsghdr.cmsg_level != SOL_SOCKET ||
            control.cmsghdr.cmsg_type != SCM_CREDENTIALS ||
            control.cmsghdr.cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                log_warning("Received message without credentials. Ignoring.");
                return 0;
        }

        ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
        if (ucred->uid != 0) {
                log_warning("Got request from unprivileged user. Ignoring.");
                return 0;
        }

        if (n != sizeof(c)) {
                log_warning("Message has invaliud size. Ignoring");
                return 0;
        }

        *_c = c;
        return 1;
}

int main(int argc, char *argv[]) {
        enum {
                FD_SOCKET,
                FD_SHUTDOWN_TIMER,
                FD_NOLOGIN_TIMER,
                _FD_MAX
        };

        int r = 4, n;
        int one = 1;
        unsigned n_fds = 1;
        struct shutdownd_command c;
        struct pollfd pollfd[_FD_MAX];
        bool exec_shutdown = false, unlink_nologin = false;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return 1;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return 1;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();

        if ((n = sd_listen_fds(true)) < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-r));
                return 1;
        }

        if (n != 1) {
                log_error("Need exactly one file descriptor.");
                return 2;
        }

        if (setsockopt(SD_LISTEN_FDS_START, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
                log_error("SO_PASSCRED failed: %m");
                return 3;
        }

        zero(c);
        zero(pollfd);

        pollfd[FD_SOCKET].fd = SD_LISTEN_FDS_START;
        pollfd[FD_SOCKET].events = POLLIN;
        pollfd[FD_SHUTDOWN_TIMER].fd = -1;
        pollfd[FD_SHUTDOWN_TIMER].events = POLLIN;
        pollfd[FD_NOLOGIN_TIMER].fd = -1;
        pollfd[FD_NOLOGIN_TIMER].events = POLLIN;

        log_debug("systemd-shutdownd running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        do {
                int k;

                if (poll(pollfd, n_fds, -1) < 0) {

                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        log_error("poll(): %m");
                        goto finish;
                }

                if (pollfd[FD_SOCKET].revents) {

                        if ((k = read_packet(pollfd[FD_SOCKET].fd, &c)) < 0)
                                goto finish;
                        else if (k > 0 && c.elapse > 0) {
                                struct itimerspec its;
                                char buf[27];

                                if (pollfd[FD_SHUTDOWN_TIMER].fd < 0)
                                        if ((pollfd[FD_SHUTDOWN_TIMER].fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC)) < 0) {
                                                log_error("timerfd_create(): %m");
                                                goto finish;
                                        }

                                if (pollfd[FD_NOLOGIN_TIMER].fd < 0)
                                        if ((pollfd[FD_NOLOGIN_TIMER].fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC)) < 0) {
                                                log_error("timerfd_create(): %m");
                                                goto finish;
                                        }

                                /* Disallow logins 5 minutes prior to shutdown */
                                zero(its);
                                timespec_store(&its.it_value, c.elapse > 5*USEC_PER_MINUTE ? c.elapse - 5*USEC_PER_MINUTE : 0);
                                if (timerfd_settime(pollfd[FD_NOLOGIN_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                        log_error("timerfd_settime(): %m");
                                        goto finish;
                                }

                                /* Shutdown after the specified time is reached */
                                zero(its);
                                timespec_store(&its.it_value, c.elapse);
                                if (timerfd_settime(pollfd[FD_SHUTDOWN_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                        log_error("timerfd_settime(): %m");
                                        goto finish;
                                }

                                n_fds = 3;

                                ctime_r(&its.it_value.tv_sec, buf);

                                sd_notifyf(false,
                                           "STATUS=Shutting down at %s...",
                                           strstrip(buf));
                        }
                }

                if (pollfd[FD_NOLOGIN_TIMER].fd >= 0 &&
                    pollfd[FD_NOLOGIN_TIMER].revents) {
                        int e;

                        if ((e = touch("/etc/nologin")) < 0)
                                log_error("Failed to create /etc/nologin: %s", strerror(-e));
                        else
                                unlink_nologin = true;

                        /* Disarm nologin timer */
                        close_nointr_nofail(pollfd[FD_NOLOGIN_TIMER].fd);
                        pollfd[FD_NOLOGIN_TIMER].fd = -1;
                        n_fds = 2;

                }

                if (pollfd[FD_SHUTDOWN_TIMER].fd >= 0 &&
                    pollfd[FD_SHUTDOWN_TIMER].revents) {
                        exec_shutdown = true;
                        goto finish;
                }

        } while (c.elapse > 0);

        r = 0;

        log_debug("systemd-shutdownd stopped as pid %lu", (unsigned long) getpid());

finish:
        if (pollfd[FD_SOCKET].fd >= 0)
                close_nointr_nofail(pollfd[FD_SOCKET].fd);

        if (pollfd[FD_SHUTDOWN_TIMER].fd >= 0)
                close_nointr_nofail(pollfd[FD_SHUTDOWN_TIMER].fd);

        if (pollfd[FD_NOLOGIN_TIMER].fd >= 0)
                close_nointr_nofail(pollfd[FD_NOLOGIN_TIMER].fd);

        if (exec_shutdown) {
                char sw[3];

                sw[0] = '-';
                sw[1] = c.mode;
                sw[2] = 0;

                execl(SYSTEMCTL_BINARY_PATH, "shutdown", sw, "now", NULL);
                log_error("Failed to execute /sbin/shutdown: %m");
        }

        if (unlink_nologin)
                unlink("/etc/nologin");

        sd_notify(false,
                  "STATUS=Exiting...");

        return r;
}
