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
#include "utmp-wtmp.h"

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
                log_warning("Message has invalid size. Ignoring");
                return 0;
        }

        char_array_0(c.wall_message);

        *_c = c;
        return 1;
}

static void warn_wall(usec_t n, struct shutdownd_command *c) {

        assert(c);
        assert(c->warn_wall);

        if (n >= c->elapse)
                return;

        if (c->wall_message[0])
                utmp_wall(c->wall_message);
        else {
                char date[FORMAT_TIMESTAMP_MAX];
                const char* prefix;
                char *l = NULL;

                if (c->mode == 'H')
                        prefix = "The system is going down for system halt at ";
                else if (c->mode == 'P')
                        prefix = "The system is going down for power-off at ";
                else if (c->mode == 'r')
                        prefix = "The system is going down for reboot at ";
                else
                        assert_not_reached("Unknown mode!");

                if (asprintf(&l, "%s%s!", prefix, format_timestamp(date, sizeof(date), c->elapse)) < 0)
                        log_error("Failed to allocate wall message");
                else {
                        utmp_wall(l);
                        free(l);
                }
        }
}

static usec_t when_wall(usec_t n, usec_t elapse) {

        static const struct {
                usec_t delay;
                usec_t interval;
        } table[] = {
                { 10 * USEC_PER_MINUTE, USEC_PER_MINUTE      },
                { USEC_PER_HOUR,        15 * USEC_PER_MINUTE },
                { 3 * USEC_PER_HOUR,    30 * USEC_PER_MINUTE }
        };

        usec_t left, sub;
        unsigned i;

        /* If the time is already passed, then don't announce */
        if (n >= elapse)
                return 0;

        left = elapse - n;
        for (i = 0; i < ELEMENTSOF(table); i++)
                if (n + table[i].delay >= elapse) {
                        sub = ((left / table[i].interval) * table[i].interval);
                        break;
                }

        if (i >= ELEMENTSOF(table))
                sub = ((left / USEC_PER_HOUR) * USEC_PER_HOUR);

        return elapse > sub ? elapse - sub : 1;
}

static usec_t when_nologin(usec_t elapse) {
        return elapse > 5*USEC_PER_MINUTE ? elapse - 5*USEC_PER_MINUTE : 1;
}

int main(int argc, char *argv[]) {
        enum {
                FD_SOCKET,
                FD_WALL_TIMER,
                FD_NOLOGIN_TIMER,
                FD_SHUTDOWN_TIMER,
                _FD_MAX
        };

        int r = 4, n_fds;
        int one = 1;
        struct shutdownd_command c;
        struct pollfd pollfd[_FD_MAX];
        bool exec_shutdown = false, unlink_nologin = false, failed = false;
        unsigned i;

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
        log_open();

        if ((n_fds = sd_listen_fds(true)) < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-r));
                return 1;
        }

        if (n_fds != 1) {
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

        for (i = 0; i < _FD_MAX; i++) {

                if (i == FD_SOCKET)
                        continue;

                pollfd[i].events = POLLIN;

                if ((pollfd[i].fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC)) < 0) {
                        log_error("timerfd_create(): %m");
                        failed = false;
                }
        }

        if (failed)
                goto finish;

        log_debug("systemd-shutdownd running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        do {
                int k;
                usec_t n;

                if (poll(pollfd, _FD_MAX, -1) < 0) {

                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        log_error("poll(): %m");
                        goto finish;
                }

                n = now(CLOCK_REALTIME);

                if (pollfd[FD_SOCKET].revents) {

                        if ((k = read_packet(pollfd[FD_SOCKET].fd, &c)) < 0)
                                goto finish;
                        else if (k > 0 && c.elapse > 0) {
                                struct itimerspec its;
                                char date[FORMAT_TIMESTAMP_MAX];

                                if (c.warn_wall) {
                                        /* Send wall messages every so often */
                                        zero(its);
                                        timespec_store(&its.it_value, when_wall(n, c.elapse));
                                        if (timerfd_settime(pollfd[FD_WALL_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                                log_error("timerfd_settime(): %m");
                                                goto finish;
                                        }

                                        /* Warn immediately if less than 15 minutes are left */
                                        if (n < c.elapse &&
                                            n + 15*USEC_PER_MINUTE >= c.elapse)
                                                warn_wall(n, &c);
                                }

                                /* Disallow logins 5 minutes prior to shutdown */
                                zero(its);
                                timespec_store(&its.it_value, when_nologin(c.elapse));
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

                                sd_notifyf(false,
                                           "STATUS=Shutting down at %s...",
                                           format_timestamp(date, sizeof(date), c.elapse));
                        }
                }

                if (pollfd[FD_WALL_TIMER].revents) {
                        struct itimerspec its;

                        warn_wall(n, &c);
                        flush_fd(pollfd[FD_WALL_TIMER].fd);

                        /* Restart timer */
                        zero(its);
                        timespec_store(&its.it_value, when_wall(n, c.elapse));
                        if (timerfd_settime(pollfd[FD_WALL_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                log_error("timerfd_settime(): %m");
                                goto finish;
                        }
                }

                if (pollfd[FD_NOLOGIN_TIMER].revents) {
                        int e;

                        log_info("Creating /etc/nologin, blocking further logins...");

                        if ((e = touch("/etc/nologin")) < 0)
                                log_error("Failed to create /etc/nologin: %s", strerror(-e));
                        else
                                unlink_nologin = true;

                        flush_fd(pollfd[FD_NOLOGIN_TIMER].fd);
                }

                if (pollfd[FD_SHUTDOWN_TIMER].revents) {
                        exec_shutdown = true;
                        goto finish;
                }

        } while (c.elapse > 0);

        r = 0;

        log_debug("systemd-shutdownd stopped as pid %lu", (unsigned long) getpid());

finish:

        for (i = 0; i < _FD_MAX; i++)
                if (pollfd[i].fd >= 0)
                        close_nointr_nofail(pollfd[i].fd);

        if (unlink_nologin)
                unlink("/etc/nologin");

        if (exec_shutdown) {
                char sw[3];

                sw[0] = '-';
                sw[1] = c.mode;
                sw[2] = 0;

                execl(SYSTEMCTL_BINARY_PATH,
                      "shutdown",
                      sw,
                      "now",
                      (c.warn_wall && c.wall_message[0]) ? c.wall_message :
                      (c.warn_wall ? NULL : "--no-wall"),
                      NULL);

                log_error("Failed to execute /sbin/shutdown: %m");
        }

        sd_notify(false,
                  "STATUS=Exiting...");

        return r;
}
