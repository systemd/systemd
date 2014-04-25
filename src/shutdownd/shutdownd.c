/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-shutdown.h>

#include "log.h"
#include "macro.h"
#include "util.h"
#include "utmp-wtmp.h"
#include "mkdir.h"
#include "fileio.h"

union shutdown_buffer {
        struct sd_shutdown_command command;
        char space[offsetof(struct sd_shutdown_command, wall_message) + LINE_MAX];
};

static int read_packet(int fd, union shutdown_buffer *_b) {
        struct ucred *ucred;
        ssize_t n;

        union shutdown_buffer b; /* We maintain our own copy here, in
                                  * order not to corrupt the last message */
        struct iovec iovec = {
                iovec.iov_base = &b,
                iovec.iov_len = sizeof(b) - 1,
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control = {};
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        assert(fd >= 0);
        assert(_b);

        n = recvmsg(fd, &msghdr, MSG_DONTWAIT);
        if (n <= 0) {
                if (n == 0) {
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

        if ((size_t) n < offsetof(struct sd_shutdown_command, wall_message)) {
                log_warning("Message has invalid size. Ignoring.");
                return 0;
        }

        if (b.command.mode != SD_SHUTDOWN_NONE &&
            b.command.mode != SD_SHUTDOWN_REBOOT &&
            b.command.mode != SD_SHUTDOWN_POWEROFF &&
            b.command.mode != SD_SHUTDOWN_HALT &&
            b.command.mode != SD_SHUTDOWN_KEXEC) {
                log_warning("Message has invalid mode. Ignoring.");
                return 0;
        }

        b.space[n] = 0;

        *_b = b;
        return 1;
}

static void warn_wall(usec_t n, struct sd_shutdown_command *c) {
        char date[FORMAT_TIMESTAMP_MAX];
        const char *prefix;
        _cleanup_free_ char *l = NULL;

        assert(c);
        assert(c->warn_wall);

        if (n >= c->usec)
                return;

        if (c->mode == SD_SHUTDOWN_HALT)
                prefix = "The system is going down for system halt at ";
        else if (c->mode == SD_SHUTDOWN_POWEROFF)
                prefix = "The system is going down for power-off at ";
        else if (c->mode == SD_SHUTDOWN_REBOOT)
                prefix = "The system is going down for reboot at ";
        else if (c->mode == SD_SHUTDOWN_KEXEC)
                prefix = "The system is going down for kexec reboot at ";
        else if (c->mode == SD_SHUTDOWN_NONE)
                prefix = "The system shutdown has been cancelled at ";
        else
                assert_not_reached("Unknown mode!");

        if (asprintf(&l, "%s%s%s%s!", c->wall_message, c->wall_message[0] ? "\n" : "",
                     prefix, format_timestamp(date, sizeof(date), c->usec)) >= 0)
                utmp_wall(l, NULL, NULL);
        else
                log_error("Failed to allocate wall message");
}

_const_ static usec_t when_wall(usec_t n, usec_t elapse) {

        static const struct {
                usec_t delay;
                usec_t interval;
        } table[] = {
                { 0,                    USEC_PER_MINUTE      },
                { 10 * USEC_PER_MINUTE, 15 * USEC_PER_MINUTE },
                { USEC_PER_HOUR,        30 * USEC_PER_MINUTE },
                { 3 * USEC_PER_HOUR,    USEC_PER_HOUR        },
        };

        usec_t left, sub;
        unsigned i = ELEMENTSOF(table) - 1;

        /* If the time is already passed, then don't announce */
        if (n >= elapse)
                return 0;

        left = elapse - n;
        while (left < table[i].delay)
                i--;
        sub = (left / table[i].interval) * table[i].interval;

        assert(sub < elapse);
        return elapse - sub;
}

static usec_t when_nologin(usec_t elapse) {
        return elapse > 5*USEC_PER_MINUTE ? elapse - 5*USEC_PER_MINUTE : 1;
}

static const char *mode_to_string(enum sd_shutdown_mode m) {
        switch (m) {
        case SD_SHUTDOWN_REBOOT:
                return "reboot";
        case SD_SHUTDOWN_POWEROFF:
                return "poweroff";
        case SD_SHUTDOWN_HALT:
                return "halt";
        case SD_SHUTDOWN_KEXEC:
                return "kexec";
        default:
                return NULL;
        }
}

static int update_schedule_file(struct sd_shutdown_command *c) {
        int r;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *t = NULL, *temp_path = NULL;

        assert(c);

        r = mkdir_safe_label("/run/systemd/shutdown", 0755, 0, 0);
        if (r < 0) {
                log_error("Failed to create shutdown subdirectory: %s", strerror(-r));
                return r;
        }

        t = cescape(c->wall_message);
        if (!t)
                return log_oom();

        r = fopen_temporary("/run/systemd/shutdown/scheduled", &f, &temp_path);
        if (r < 0) {
                log_error("Failed to save information about scheduled shutdowns: %s", strerror(-r));
                return r;
        }

        fchmod(fileno(f), 0644);

        fprintf(f,
                "USEC="USEC_FMT"\n"
                "WARN_WALL=%i\n"
                "MODE=%s\n",
                c->usec,
                c->warn_wall,
                mode_to_string(c->mode));

        if (c->dry_run)
                fputs("DRY_RUN=1\n", f);

        if (!isempty(t))
                fprintf(f, "WALL_MESSAGE=%s\n", t);

        fflush(f);

        if (ferror(f) || rename(temp_path, "/run/systemd/shutdown/scheduled") < 0) {
                log_error("Failed to write information about scheduled shutdowns: %m");
                r = -errno;

                unlink(temp_path);
                unlink("/run/systemd/shutdown/scheduled");
        }

        return r;
}

static bool scheduled(struct sd_shutdown_command *c) {
        return c->usec > 0 && c->mode != SD_SHUTDOWN_NONE;
}

int main(int argc, char *argv[]) {
        enum {
                FD_SOCKET,
                FD_WALL_TIMER,
                FD_NOLOGIN_TIMER,
                FD_SHUTDOWN_TIMER,
                _FD_MAX
        };

        int r = EXIT_FAILURE, n_fds;
        union shutdown_buffer b = {};
        struct pollfd pollfd[_FD_MAX] = {};
        bool exec_shutdown = false, unlink_nologin = false;
        unsigned i;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        n_fds = sd_listen_fds(true);
        if (n_fds < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        if (n_fds != 1) {
                log_error("Need exactly one file descriptor.");
                return EXIT_FAILURE;
        }

        pollfd[FD_SOCKET].fd = SD_LISTEN_FDS_START;
        pollfd[FD_SOCKET].events = POLLIN;

        for (i = FD_WALL_TIMER; i < _FD_MAX; i++) {
                pollfd[i].events = POLLIN;
                pollfd[i].fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC);
                if (pollfd[i].fd < 0) {
                        log_error("timerfd_create(): %m");
                        goto finish;
                }
        }

        log_debug("systemd-shutdownd running as pid "PID_FMT, getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        for (;;) {
                int k;
                usec_t n;

                k = poll(pollfd, _FD_MAX, scheduled(&b.command) ? -1 : 0);
                if (k < 0) {

                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        log_error("poll(): %m");
                        goto finish;
                }

                /* Exit on idle */
                if (k == 0)
                        break;

                n = now(CLOCK_REALTIME);

                if (pollfd[FD_SOCKET].revents) {

                        k = read_packet(pollfd[FD_SOCKET].fd, &b);
                        if (k < 0)
                                goto finish;
                        else if (k > 0) {
                                struct itimerspec its;
                                char date[FORMAT_TIMESTAMP_MAX];

                                if (!scheduled(&b.command)) {
                                        log_info("Shutdown canceled.");
                                        if (b.command.warn_wall)
                                                warn_wall(0, &b.command);
                                        break;
                                }

                                zero(its);
                                if (b.command.warn_wall) {
                                        /* Send wall messages every so often */
                                        timespec_store(&its.it_value, when_wall(n, b.command.usec));

                                        /* Warn immediately if less than 15 minutes are left */
                                        if (n < b.command.usec &&
                                            n + 15*USEC_PER_MINUTE >= b.command.usec)
                                                warn_wall(n, &b.command);
                                }
                                if (timerfd_settime(pollfd[FD_WALL_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                        log_error("timerfd_settime(): %m");
                                        goto finish;
                                }

                                /* Disallow logins 5 minutes prior to shutdown */
                                zero(its);
                                timespec_store(&its.it_value, when_nologin(b.command.usec));
                                if (timerfd_settime(pollfd[FD_NOLOGIN_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                        log_error("timerfd_settime(): %m");
                                        goto finish;
                                }

                                /* Shutdown after the specified time is reached */
                                zero(its);
                                timespec_store(&its.it_value, b.command.usec);
                                if (timerfd_settime(pollfd[FD_SHUTDOWN_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                        log_error("timerfd_settime(): %m");
                                        goto finish;
                                }

                                update_schedule_file(&b.command);

                                sd_notifyf(false,
                                           "STATUS=Shutting down at %s (%s)...",
                                           format_timestamp(date, sizeof(date), b.command.usec),
                                           mode_to_string(b.command.mode));

                                log_info("Shutting down at %s (%s)...", date, mode_to_string(b.command.mode));
                        }
                }

                if (pollfd[FD_WALL_TIMER].revents) {
                        struct itimerspec its = {};

                        warn_wall(n, &b.command);
                        flush_fd(pollfd[FD_WALL_TIMER].fd);

                        /* Restart timer */
                        timespec_store(&its.it_value, when_wall(n, b.command.usec));
                        if (timerfd_settime(pollfd[FD_WALL_TIMER].fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                                log_error("timerfd_settime(): %m");
                                goto finish;
                        }
                }

                if (pollfd[FD_NOLOGIN_TIMER].revents) {
                        int e;

                        log_info("Creating /run/nologin, blocking further logins...");

                        e = write_string_file_atomic("/run/nologin", "System is going down.");
                        if (e < 0)
                                log_error("Failed to create /run/nologin: %s", strerror(-e));
                        else
                                unlink_nologin = true;

                        flush_fd(pollfd[FD_NOLOGIN_TIMER].fd);
                }

                if (pollfd[FD_SHUTDOWN_TIMER].revents) {
                        exec_shutdown = true;
                        goto finish;
                }
        }

        r = EXIT_SUCCESS;

        log_debug("systemd-shutdownd stopped as pid "PID_FMT, getpid());

finish:

        for (i = 0; i < _FD_MAX; i++)
                safe_close(pollfd[i].fd);

        if (unlink_nologin)
                unlink("/run/nologin");

        unlink("/run/systemd/shutdown/scheduled");

        if (exec_shutdown && !b.command.dry_run) {
                char sw[3];

                sw[0] = '-';
                sw[1] = b.command.mode;
                sw[2] = 0;

                execl(SYSTEMCTL_BINARY_PATH,
                      "shutdown",
                      sw,
                      "now",
                      (b.command.warn_wall && b.command.wall_message[0]) ? b.command.wall_message :
                      (b.command.warn_wall ? NULL : "--no-wall"),
                      NULL);

                log_error("Failed to execute /sbin/shutdown: %m");
        }

        sd_notify(false,
                  "STATUS=Exiting...");

        return r;
}
