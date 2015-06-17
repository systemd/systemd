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

#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/timerfd.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "sd-daemon.h"
#include "sd-messages.h"

#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "ratelimit.h"
#include "locale-setup.h"
#include "unit-name.h"
#include "missing.h"
#include "rm-rf.h"
#include "path-lookup.h"
#include "special.h"
#include "exit-status.h"
#include "virt.h"
#include "watchdog.h"
#include "path-util.h"
#include "audit-fd.h"
#include "boot-timestamps.h"
#include "env-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-util.h"
#include "bus-kernel.h"
#include "time-util.h"
#include "process-util.h"
#include "terminal-util.h"
#include "signal-util.h"
#include "dbus.h"
#include "dbus-unit.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "manager.h"
#include "transaction.h"

/* Initial delay and the interval for printing status messages about running jobs */
#define JOBS_IN_PROGRESS_WAIT_USEC (5*USEC_PER_SEC)
#define JOBS_IN_PROGRESS_PERIOD_USEC (USEC_PER_SEC / 3)
#define JOBS_IN_PROGRESS_PERIOD_DIVISOR 3

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata);
static int manager_dispatch_run_queue(sd_event_source *source, void *userdata);
static int manager_run_generators(Manager *m);
static void manager_undo_generators(Manager *m);

static void manager_watch_jobs_in_progress(Manager *m) {
        usec_t next;
        int r;

        assert(m);

        if (m->jobs_in_progress_event_source)
                return;

        next = now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_WAIT_USEC;
        r = sd_event_add_time(
                        m->event,
                        &m->jobs_in_progress_event_source,
                        CLOCK_MONOTONIC,
                        next, 0,
                        manager_dispatch_jobs_in_progress, m);
        if (r < 0)
                return;

        (void) sd_event_source_set_description(m->jobs_in_progress_event_source, "manager-jobs-in-progress");
}

#define CYLON_BUFFER_EXTRA (2*(sizeof(ANSI_RED_ON)-1) + sizeof(ANSI_HIGHLIGHT_RED_ON)-1 + 2*(sizeof(ANSI_HIGHLIGHT_OFF)-1))

static void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos) {
        char *p = buffer;

        assert(buflen >= CYLON_BUFFER_EXTRA + width + 1);
        assert(pos <= width+1); /* 0 or width+1 mean that the center light is behind the corner */

        if (pos > 1) {
                if (pos > 2)
                        p = mempset(p, ' ', pos-2);
                p = stpcpy(p, ANSI_RED_ON);
                *p++ = '*';
        }

        if (pos > 0 && pos <= width) {
                p = stpcpy(p, ANSI_HIGHLIGHT_RED_ON);
                *p++ = '*';
        }

        p = stpcpy(p, ANSI_HIGHLIGHT_OFF);

        if (pos < width) {
                p = stpcpy(p, ANSI_RED_ON);
                *p++ = '*';
                if (pos < width-1)
                        p = mempset(p, ' ', width-1-pos);
                strcpy(p, ANSI_HIGHLIGHT_OFF);
        }
}

void manager_flip_auto_status(Manager *m, bool enable) {
        assert(m);

        if (enable) {
                if (m->show_status == SHOW_STATUS_AUTO)
                        manager_set_show_status(m, SHOW_STATUS_TEMPORARY);
        } else {
                if (m->show_status == SHOW_STATUS_TEMPORARY)
                        manager_set_show_status(m, SHOW_STATUS_AUTO);
        }
}

static void manager_print_jobs_in_progress(Manager *m) {
        _cleanup_free_ char *job_of_n = NULL;
        Iterator i;
        Job *j;
        unsigned counter = 0, print_nr;
        char cylon[6 + CYLON_BUFFER_EXTRA + 1];
        unsigned cylon_pos;
        char time[FORMAT_TIMESPAN_MAX], limit[FORMAT_TIMESPAN_MAX] = "no limit";
        uint64_t x;

        assert(m);
        assert(m->n_running_jobs > 0);

        manager_flip_auto_status(m, true);

        print_nr = (m->jobs_in_progress_iteration / JOBS_IN_PROGRESS_PERIOD_DIVISOR) % m->n_running_jobs;

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->state == JOB_RUNNING && counter++ == print_nr)
                        break;

        /* m->n_running_jobs must be consistent with the contents of m->jobs,
         * so the above loop must have succeeded in finding j. */
        assert(counter == print_nr + 1);
        assert(j);

        cylon_pos = m->jobs_in_progress_iteration % 14;
        if (cylon_pos >= 8)
                cylon_pos = 14 - cylon_pos;
        draw_cylon(cylon, sizeof(cylon), 6, cylon_pos);

        m->jobs_in_progress_iteration++;

        if (m->n_running_jobs > 1) {
                if (asprintf(&job_of_n, "(%u of %u) ", counter, m->n_running_jobs) < 0)
                        job_of_n = NULL;
        }

        format_timespan(time, sizeof(time), now(CLOCK_MONOTONIC) - j->begin_usec, 1*USEC_PER_SEC);
        if (job_get_timeout(j, &x) > 0)
                format_timespan(limit, sizeof(limit), x - j->begin_usec, 1*USEC_PER_SEC);

        manager_status_printf(m, STATUS_TYPE_EPHEMERAL, cylon,
                              "%sA %s job is running for %s (%s / %s)",
                              strempty(job_of_n),
                              job_type_to_string(j->type),
                              unit_description(j->unit),
                              time, limit);
}

static int have_ask_password(void) {
        _cleanup_closedir_ DIR *dir;

        dir = opendir("/run/systemd/ask-password");
        if (!dir) {
                if (errno == ENOENT)
                        return false;
                else
                        return -errno;
        }

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(dir);
                if (!de && errno != 0)
                        return -errno;
                if (!de)
                        return false;

                if (startswith(de->d_name, "ask."))
                        return true;
        }
}

static int manager_dispatch_ask_password_fd(sd_event_source *source,
                                            int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);

        flush_fd(fd);

        m->have_ask_password = have_ask_password();
        if (m->have_ask_password < 0)
                /* Log error but continue. Negative have_ask_password
                 * is treated as unknown status. */
                log_error_errno(m->have_ask_password, "Failed to list /run/systemd/ask-password: %m");

        return 0;
}

static void manager_close_ask_password(Manager *m) {
        assert(m);

        m->ask_password_inotify_fd = safe_close(m->ask_password_inotify_fd);
        m->ask_password_event_source = sd_event_source_unref(m->ask_password_event_source);
        m->have_ask_password = -EINVAL;
}

static int manager_check_ask_password(Manager *m) {
        int r;

        assert(m);

        if (!m->ask_password_event_source) {
                assert(m->ask_password_inotify_fd < 0);

                mkdir_p_label("/run/systemd/ask-password", 0755);

                m->ask_password_inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (m->ask_password_inotify_fd < 0)
                        return log_error_errno(errno, "inotify_init1() failed: %m");

                if (inotify_add_watch(m->ask_password_inotify_fd, "/run/systemd/ask-password", IN_CREATE|IN_DELETE|IN_MOVE) < 0) {
                        log_error_errno(errno, "Failed to add watch on /run/systemd/ask-password: %m");
                        manager_close_ask_password(m);
                        return -errno;
                }

                r = sd_event_add_io(m->event, &m->ask_password_event_source,
                                    m->ask_password_inotify_fd, EPOLLIN,
                                    manager_dispatch_ask_password_fd, m);
                if (r < 0) {
                        log_error_errno(errno, "Failed to add event source for /run/systemd/ask-password: %m");
                        manager_close_ask_password(m);
                        return -errno;
                }

                (void) sd_event_source_set_description(m->ask_password_event_source, "manager-ask-password");

                /* Queries might have been added meanwhile... */
                manager_dispatch_ask_password_fd(m->ask_password_event_source,
                                                 m->ask_password_inotify_fd, EPOLLIN, m);
        }

        return m->have_ask_password;
}

static int manager_watch_idle_pipe(Manager *m) {
        int r;

        assert(m);

        if (m->idle_pipe_event_source)
                return 0;

        if (m->idle_pipe[2] < 0)
                return 0;

        r = sd_event_add_io(m->event, &m->idle_pipe_event_source, m->idle_pipe[2], EPOLLIN, manager_dispatch_idle_pipe_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch idle pipe: %m");

        (void) sd_event_source_set_description(m->idle_pipe_event_source, "manager-idle-pipe");

        return 0;
}

static void manager_close_idle_pipe(Manager *m) {
        assert(m);

        safe_close_pair(m->idle_pipe);
        safe_close_pair(m->idle_pipe + 2);
}

static int manager_setup_time_change(Manager *m) {
        int r;

        /* We only care for the cancellation event, hence we set the
         * timeout to the latest possible value. */
        struct itimerspec its = {
                .it_value.tv_sec = TIME_T_MAX,
        };

        assert(m);
        assert_cc(sizeof(time_t) == sizeof(TIME_T_MAX));

        if (m->test_run)
                return 0;

        /* Uses TFD_TIMER_CANCEL_ON_SET to get notifications whenever
         * CLOCK_REALTIME makes a jump relative to CLOCK_MONOTONIC */

        m->time_change_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC);
        if (m->time_change_fd < 0)
                return log_error_errno(errno, "Failed to create timerfd: %m");

        if (timerfd_settime(m->time_change_fd, TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET, &its, NULL) < 0) {
                log_debug_errno(errno, "Failed to set up TFD_TIMER_CANCEL_ON_SET, ignoring: %m");
                m->time_change_fd = safe_close(m->time_change_fd);
                return 0;
        }

        r = sd_event_add_io(m->event, &m->time_change_event_source, m->time_change_fd, EPOLLIN, manager_dispatch_time_change_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create time change event source: %m");

        (void) sd_event_source_set_description(m->time_change_event_source, "manager-time-change");

        log_debug("Set up TFD_TIMER_CANCEL_ON_SET timerfd.");

        return 0;
}

static int enable_special_signals(Manager *m) {
        _cleanup_close_ int fd = -1;

        assert(m);

        /* Enable that we get SIGINT on control-alt-del. In containers
         * this will fail with EPERM (older) or EINVAL (newer), so
         * ignore that. */
        if (reboot(RB_DISABLE_CAD) < 0 && errno != EPERM && errno != EINVAL)
                log_warning_errno(errno, "Failed to enable ctrl-alt-del handling: %m");

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                /* Support systems without virtual console */
                if (fd != -ENOENT)
                        log_warning_errno(errno, "Failed to open /dev/tty0: %m");
        } else {
                /* Enable that we get SIGWINCH on kbrequest */
                if (ioctl(fd, KDSIGACCEPT, SIGWINCH) < 0)
                        log_warning_errno(errno, "Failed to enable kbrequest handling: %m");
        }

        return 0;
}

static int manager_setup_signals(Manager *m) {
        struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_NOCLDSTOP|SA_RESTART,
        };
        sigset_t mask;
        int r;

        assert(m);

        assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

        /* We make liberal use of realtime signals here. On
         * Linux/glibc we have 30 of them (with the exception of Linux
         * on hppa, see below), between SIGRTMIN+0 ... SIGRTMIN+30
         * (aka SIGRTMAX). */

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask,
                        SIGCHLD,     /* Child died */
                        SIGTERM,     /* Reexecute daemon */
                        SIGHUP,      /* Reload configuration */
                        SIGUSR1,     /* systemd/upstart: reconnect to D-Bus */
                        SIGUSR2,     /* systemd: dump status */
                        SIGINT,      /* Kernel sends us this on control-alt-del */
                        SIGWINCH,    /* Kernel sends us this on kbrequest (alt-arrowup) */
                        SIGPWR,      /* Some kernel drivers and upsd send us this on power failure */

                        SIGRTMIN+0,  /* systemd: start default.target */
                        SIGRTMIN+1,  /* systemd: isolate rescue.target */
                        SIGRTMIN+2,  /* systemd: isolate emergency.target */
                        SIGRTMIN+3,  /* systemd: start halt.target */
                        SIGRTMIN+4,  /* systemd: start poweroff.target */
                        SIGRTMIN+5,  /* systemd: start reboot.target */
                        SIGRTMIN+6,  /* systemd: start kexec.target */

                        /* ... space for more special targets ... */

                        SIGRTMIN+13, /* systemd: Immediate halt */
                        SIGRTMIN+14, /* systemd: Immediate poweroff */
                        SIGRTMIN+15, /* systemd: Immediate reboot */
                        SIGRTMIN+16, /* systemd: Immediate kexec */

                        /* ... space for more immediate system state changes ... */

                        SIGRTMIN+20, /* systemd: enable status messages */
                        SIGRTMIN+21, /* systemd: disable status messages */
                        SIGRTMIN+22, /* systemd: set log level to LOG_DEBUG */
                        SIGRTMIN+23, /* systemd: set log level to LOG_INFO */
                        SIGRTMIN+24, /* systemd: Immediate exit (--user only) */

                        /* .. one free signal here ... */

#if !defined(__hppa64__) && !defined(__hppa__)
                        /* Apparently Linux on hppa has fewer RT
                         * signals (SIGRTMAX is SIGRTMIN+25 there),
                         * hence let's not try to make use of them
                         * here. Since these commands are accessible
                         * by different means and only really a safety
                         * net, the missing functionality on hppa
                         * shouldn't matter. */

                        SIGRTMIN+26, /* systemd: set log target to journal-or-kmsg */
                        SIGRTMIN+27, /* systemd: set log target to console */
                        SIGRTMIN+28, /* systemd: set log target to kmsg */
                        SIGRTMIN+29, /* systemd: set log target to syslog-or-kmsg (obsolete) */

                        /* ... one free signal here SIGRTMIN+30 ... */
#endif
                        -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (m->signal_fd < 0)
                return -errno;

        r = sd_event_add_io(m->event, &m->signal_event_source, m->signal_fd, EPOLLIN, manager_dispatch_signal_fd, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->signal_event_source, "manager-signal");

        /* Process signals a bit earlier than the rest of things, but
         * later than notify_fd processing, so that the notify
         * processing can still figure out to which process/service a
         * message belongs, before we reap the process. */
        r = sd_event_source_set_priority(m->signal_event_source, -5);
        if (r < 0)
                return r;

        if (m->running_as == MANAGER_SYSTEM)
                return enable_special_signals(m);

        return 0;
}

static void manager_clean_environment(Manager *m) {
        assert(m);

        /* Let's remove some environment variables that we
         * need ourselves to communicate with our clients */
        strv_env_unset_many(
                        m->environment,
                        "NOTIFY_SOCKET",
                        "MAINPID",
                        "MANAGERPID",
                        "LISTEN_PID",
                        "LISTEN_FDS",
                        "WATCHDOG_PID",
                        "WATCHDOG_USEC",
                        NULL);
}

static int manager_default_environment(Manager *m) {
        assert(m);

        if (m->running_as == MANAGER_SYSTEM) {
                /* The system manager always starts with a clean
                 * environment for its children. It does not import
                 * the kernel or the parents exported variables.
                 *
                 * The initial passed environ is untouched to keep
                 * /proc/self/environ valid; it is used for tagging
                 * the init process inside containers. */
                m->environment = strv_new("PATH=" DEFAULT_PATH,
                                          NULL);

                /* Import locale variables LC_*= from configuration */
                locale_setup(&m->environment);
        } else {
                /* The user manager passes its own environment
                 * along to its children. */
                m->environment = strv_copy(environ);
        }

        if (!m->environment)
                return -ENOMEM;

        manager_clean_environment(m);
        strv_sort(m->environment);

        return 0;
}


int manager_new(ManagerRunningAs running_as, bool test_run, Manager **_m) {

        static const char * const unit_log_fields[_MANAGER_RUNNING_AS_MAX] = {
                [MANAGER_SYSTEM] = "UNIT=",
                [MANAGER_USER] = "USER_UNIT=",
        };

        static const char * const unit_log_format_strings[_MANAGER_RUNNING_AS_MAX] = {
                [MANAGER_SYSTEM] = "UNIT=%s",
                [MANAGER_USER] = "USER_UNIT=%s",
        };

        Manager *m;
        int r;

        assert(_m);
        assert(running_as >= 0);
        assert(running_as < _MANAGER_RUNNING_AS_MAX);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

#ifdef ENABLE_EFI
        if (running_as == MANAGER_SYSTEM && detect_container(NULL) <= 0)
                boot_timestamps(&m->userspace_timestamp, &m->firmware_timestamp, &m->loader_timestamp);
#endif

        m->running_as = running_as;
        m->exit_code = _MANAGER_EXIT_CODE_INVALID;
        m->default_timer_accuracy_usec = USEC_PER_MINUTE;

        /* Prepare log fields we can use for structured logging */
        m->unit_log_field = unit_log_fields[running_as];
        m->unit_log_format_string = unit_log_format_strings[running_as];

        m->idle_pipe[0] = m->idle_pipe[1] = m->idle_pipe[2] = m->idle_pipe[3] = -1;

        m->pin_cgroupfs_fd = m->notify_fd = m->signal_fd = m->time_change_fd = m->dev_autofs_fd = m->private_listen_fd = m->kdbus_fd = m->utab_inotify_fd = -1;
        m->current_job_id = 1; /* start as id #1, so that we can leave #0 around as "null-like" value */

        m->ask_password_inotify_fd = -1;
        m->have_ask_password = -EINVAL; /* we don't know */

        m->test_run = test_run;

        /* Reboot immediately if the user hits C-A-D more often than 7x per 2s */
        RATELIMIT_INIT(m->ctrl_alt_del_ratelimit, 2 * USEC_PER_SEC, 7);

        r = manager_default_environment(m);
        if (r < 0)
                goto fail;

        r = hashmap_ensure_allocated(&m->units, &string_hash_ops);
        if (r < 0)
                goto fail;

        r = hashmap_ensure_allocated(&m->jobs, NULL);
        if (r < 0)
                goto fail;

        r = hashmap_ensure_allocated(&m->cgroup_unit, &string_hash_ops);
        if (r < 0)
                goto fail;

        r = hashmap_ensure_allocated(&m->watch_bus, &string_hash_ops);
        if (r < 0)
                goto fail;

        r = set_ensure_allocated(&m->startup_units, NULL);
        if (r < 0)
                goto fail;

        r = set_ensure_allocated(&m->failed_units, NULL);
        if (r < 0)
                goto fail;

        r = sd_event_default(&m->event);
        if (r < 0)
                goto fail;

        r = sd_event_add_defer(m->event, &m->run_queue_event_source, manager_dispatch_run_queue, m);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(m->run_queue_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_enabled(m->run_queue_event_source, SD_EVENT_OFF);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(m->run_queue_event_source, "manager-run-queue");

        r = manager_setup_signals(m);
        if (r < 0)
                goto fail;

        r = manager_setup_cgroup(m);
        if (r < 0)
                goto fail;

        r = manager_setup_time_change(m);
        if (r < 0)
                goto fail;

        m->udev = udev_new();
        if (!m->udev) {
                r = -ENOMEM;
                goto fail;
        }

        /* Note that we set up neither kdbus, nor the notify fd
         * here. We do that after deserialization, since they might
         * have gotten serialized across the reexec. */

        m->taint_usr = dir_is_empty("/usr") > 0;

        *_m = m;
        return 0;

fail:
        manager_free(m);
        return r;
}

static int manager_setup_notify(Manager *m) {
        int r;

        if (m->test_run)
                return 0;

        if (m->notify_fd < 0) {
                _cleanup_close_ int fd = -1;
                union sockaddr_union sa = {
                        .sa.sa_family = AF_UNIX,
                };
                static const int one = 1;

                /* First free all secondary fields */
                free(m->notify_socket);
                m->notify_socket = NULL;
                m->notify_event_source = sd_event_source_unref(m->notify_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate notification socket: %m");

                if (m->running_as == MANAGER_SYSTEM)
                        m->notify_socket = strdup("/run/systemd/notify");
                else {
                        const char *e;

                        e = getenv("XDG_RUNTIME_DIR");
                        if (!e) {
                                log_error_errno(errno, "XDG_RUNTIME_DIR is not set: %m");
                                return -EINVAL;
                        }

                        m->notify_socket = strappend(e, "/systemd/notify");
                }
                if (!m->notify_socket)
                        return log_oom();

                (void) mkdir_parents_label(m->notify_socket, 0755);
                (void) unlink(m->notify_socket);

                strncpy(sa.un.sun_path, m->notify_socket, sizeof(sa.un.sun_path)-1);
                r = bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                r = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
                if (r < 0)
                        return log_error_errno(errno, "SO_PASSCRED failed: %m");

                m->notify_fd = fd;
                fd = -1;

                log_debug("Using notification socket %s", m->notify_socket);
        }

        if (!m->notify_event_source) {
                r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOLLIN, manager_dispatch_notify_fd, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate notify event source: %m");

                /* Process signals a bit earlier than SIGCHLD, so that we can
                 * still identify to which service an exit message belongs */
                r = sd_event_source_set_priority(m->notify_event_source, -7);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of notify event source: %m");

                (void) sd_event_source_set_description(m->notify_event_source, "manager-notify");
        }

        return 0;
}

static int manager_setup_kdbus(Manager *m) {
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (m->test_run || m->kdbus_fd >= 0)
                return 0;
        if (!is_kdbus_available())
                return -ESOCKTNOSUPPORT;

        m->kdbus_fd = bus_kernel_create_bus(
                        m->running_as == MANAGER_SYSTEM ? "system" : "user",
                        m->running_as == MANAGER_SYSTEM, &p);

        if (m->kdbus_fd < 0)
                return log_debug_errno(m->kdbus_fd, "Failed to set up kdbus: %m");

        log_debug("Successfully set up kdbus on %s", p);

        return 0;
}

static int manager_connect_bus(Manager *m, bool reexecuting) {
        bool try_bus_connect;

        assert(m);

        if (m->test_run)
                return 0;

        try_bus_connect =
                m->kdbus_fd >= 0 ||
                reexecuting ||
                (m->running_as == MANAGER_USER && getenv("DBUS_SESSION_BUS_ADDRESS"));

        /* Try to connect to the buses, if possible. */
        return bus_init(m, try_bus_connect);
}

static unsigned manager_dispatch_cleanup_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        while ((u = m->cleanup_queue)) {
                assert(u->in_cleanup_queue);

                unit_free(u);
                n++;
        }

        return n;
}

enum {
        GC_OFFSET_IN_PATH,  /* This one is on the path we were traveling */
        GC_OFFSET_UNSURE,   /* No clue */
        GC_OFFSET_GOOD,     /* We still need this unit */
        GC_OFFSET_BAD,      /* We don't need this unit anymore */
        _GC_OFFSET_MAX
};

static void unit_gc_sweep(Unit *u, unsigned gc_marker) {
        Iterator i;
        Unit *other;
        bool is_bad;

        assert(u);

        if (u->gc_marker == gc_marker + GC_OFFSET_GOOD ||
            u->gc_marker == gc_marker + GC_OFFSET_BAD ||
            u->gc_marker == gc_marker + GC_OFFSET_IN_PATH)
                return;

        if (u->in_cleanup_queue)
                goto bad;

        if (unit_check_gc(u))
                goto good;

        u->gc_marker = gc_marker + GC_OFFSET_IN_PATH;

        is_bad = true;

        SET_FOREACH(other, u->dependencies[UNIT_REFERENCED_BY], i) {
                unit_gc_sweep(other, gc_marker);

                if (other->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        if (is_bad)
                goto bad;

        /* We were unable to find anything out about this entry, so
         * let's investigate it later */
        u->gc_marker = gc_marker + GC_OFFSET_UNSURE;
        unit_add_to_gc_queue(u);
        return;

bad:
        /* We definitely know that this one is not useful anymore, so
         * let's mark it for deletion */
        u->gc_marker = gc_marker + GC_OFFSET_BAD;
        unit_add_to_cleanup_queue(u);
        return;

good:
        u->gc_marker = gc_marker + GC_OFFSET_GOOD;
}

static unsigned manager_dispatch_gc_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;
        unsigned gc_marker;

        assert(m);

        /* log_debug("Running GC..."); */

        m->gc_marker += _GC_OFFSET_MAX;
        if (m->gc_marker + _GC_OFFSET_MAX <= _GC_OFFSET_MAX)
                m->gc_marker = 1;

        gc_marker = m->gc_marker;

        while ((u = m->gc_queue)) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

                LIST_REMOVE(gc_queue, m->gc_queue, u);
                u->in_gc_queue = false;

                n++;

                if (u->gc_marker == gc_marker + GC_OFFSET_BAD ||
                    u->gc_marker == gc_marker + GC_OFFSET_UNSURE) {
                        if (u->id)
                                log_unit_debug(u, "Collecting.");
                        u->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(u);
                }
        }

        m->n_in_gc_queue = 0;

        return n;
}

static void manager_clear_jobs_and_units(Manager *m) {
        Unit *u;

        assert(m);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        manager_dispatch_cleanup_queue(m);

        assert(!m->load_queue);
        assert(!m->run_queue);
        assert(!m->dbus_unit_queue);
        assert(!m->dbus_job_queue);
        assert(!m->cleanup_queue);
        assert(!m->gc_queue);

        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));

        m->n_on_console = 0;
        m->n_running_jobs = 0;
}

Manager* manager_free(Manager *m) {
        UnitType c;
        int i;

        if (!m)
                return NULL;

        manager_clear_jobs_and_units(m);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        /* If we reexecute ourselves, we keep the root cgroup
         * around */
        manager_shutdown_cgroup(m, m->exit_code != MANAGER_REEXECUTE);

        manager_undo_generators(m);

        bus_done(m);

        hashmap_free(m->units);
        hashmap_free(m->jobs);
        hashmap_free(m->watch_pids1);
        hashmap_free(m->watch_pids2);
        hashmap_free(m->watch_bus);

        set_free(m->startup_units);
        set_free(m->failed_units);

        sd_event_source_unref(m->signal_event_source);
        sd_event_source_unref(m->notify_event_source);
        sd_event_source_unref(m->time_change_event_source);
        sd_event_source_unref(m->jobs_in_progress_event_source);
        sd_event_source_unref(m->idle_pipe_event_source);
        sd_event_source_unref(m->run_queue_event_source);

        safe_close(m->signal_fd);
        safe_close(m->notify_fd);
        safe_close(m->time_change_fd);
        safe_close(m->kdbus_fd);

        manager_close_ask_password(m);

        manager_close_idle_pipe(m);

        udev_unref(m->udev);
        sd_event_unref(m->event);

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->environment);

        hashmap_free(m->cgroup_unit);
        set_free_free(m->unit_path_cache);

        free(m->switch_root);
        free(m->switch_root_init);

        for (i = 0; i < _RLIMIT_MAX; i++)
                free(m->rlimit[i]);

        assert(hashmap_isempty(m->units_requiring_mounts_for));
        hashmap_free(m->units_requiring_mounts_for);

        free(m);
        return NULL;
}

int manager_enumerate(Manager *m) {
        int r = 0;
        UnitType c;

        assert(m);

        /* Let's ask every type to load all units from disk/kernel
         * that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++) {
                int q;

                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (!unit_vtable[c]->enumerate)
                        continue;

                q = unit_vtable[c]->enumerate(m);
                if (q < 0)
                        r = q;
        }

        manager_dispatch_load_queue(m);
        return r;
}

static void manager_coldplug(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;
        int r;

        assert(m);

        /* Then, let's set up their initial state. */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                r = unit_coldplug(u);
                if (r < 0)
                        log_warning_errno(r, "We couldn't coldplug %s, proceeding anyway: %m", u->id);
        }
}

static void manager_build_unit_path_cache(Manager *m) {
        char **i;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        set_free_free(m->unit_path_cache);

        m->unit_path_cache = set_new(&string_hash_ops);
        if (!m->unit_path_cache) {
                log_error("Failed to allocate unit path cache.");
                return;
        }

        /* This simply builds a list of files we know exist, so that
         * we don't always have to go to disk */

        STRV_FOREACH(i, m->lookup_paths.unit_path) {
                struct dirent *de;

                d = opendir(*i);
                if (!d) {
                        if (errno != ENOENT)
                                log_error_errno(errno, "Failed to open directory %s: %m", *i);
                        continue;
                }

                while ((de = readdir(d))) {
                        char *p;

                        if (hidden_file(de->d_name))
                                continue;

                        p = strjoin(streq(*i, "/") ? "" : *i, "/", de->d_name, NULL);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        r = set_consume(m->unit_path_cache, p);
                        if (r < 0)
                                goto fail;
                }

                closedir(d);
                d = NULL;
        }

        return;

fail:
        log_error_errno(r, "Failed to build unit path cache: %m");

        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;
}


static int manager_distribute_fds(Manager *m, FDSet *fds) {
        Unit *u;
        Iterator i;
        int r;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i) {

                if (fdset_size(fds) <= 0)
                        break;

                if (UNIT_VTABLE(u)->distribute_fds) {
                        r = UNIT_VTABLE(u)->distribute_fds(u, fds);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r, q;

        assert(m);

        dual_timestamp_get(&m->generators_start_timestamp);
        r = manager_run_generators(m);
        dual_timestamp_get(&m->generators_finish_timestamp);
        if (r < 0)
                return r;

        r = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
                        NULL,
                        m->generator_unit_path,
                        m->generator_unit_path_early,
                        m->generator_unit_path_late);
        if (r < 0)
                return r;

        manager_build_unit_path_cache(m);

        /* If we will deserialize make sure that during enumeration
         * this is already known, so we increase the counter here
         * already */
        if (serialization)
                m->n_reloading ++;

        /* First, enumerate what we can from all config files */
        dual_timestamp_get(&m->units_load_start_timestamp);
        r = manager_enumerate(m);
        dual_timestamp_get(&m->units_load_finish_timestamp);

        /* Second, deserialize if there is something to deserialize */
        if (serialization)
                r = manager_deserialize(m, serialization, fds);

        /* Any fds left? Find some unit which wants them. This is
         * useful to allow container managers to pass some file
         * descriptors to us pre-initialized. This enables
         * socket-based activation of entire containers. */
        if (fdset_size(fds) > 0) {
                q = manager_distribute_fds(m, fds);
                if (q < 0 && r == 0)
                        r = q;
        }

        /* We might have deserialized the notify fd, but if we didn't
         * then let's create the bus now */
        q = manager_setup_notify(m);
        if (q < 0 && r == 0)
                r = q;

        /* We might have deserialized the kdbus control fd, but if we
         * didn't, then let's create the bus now. */
        manager_setup_kdbus(m);
        manager_connect_bus(m, !!serialization);
        bus_track_coldplug(m, &m->subscribed, &m->deserialized_subscribed);

        /* Third, fire things up! */
        manager_coldplug(m);

        if (serialization) {
                assert(m->n_reloading > 0);
                m->n_reloading --;

                /* Let's wait for the UnitNew/JobNew messages being
                 * sent, before we notify that the reload is
                 * finished */
                m->send_reloading_done = true;
        }

        return r;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool override, sd_bus_error *e, Job **_ret) {
        int r;
        Transaction *tr;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START)
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Isolate is only valid for start.");

        if (mode == JOB_ISOLATE && !unit->allow_isolate)
                return sd_bus_error_setf(e, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");

        log_unit_debug(unit, "Trying to enqueue job %s/%s/%s", unit->id, job_type_to_string(type), job_mode_to_string(mode));

        type = job_type_collapse(type, unit);

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        r = transaction_add_job_and_dependencies(tr, type, unit, NULL, true, override, false,
                                                 mode == JOB_IGNORE_DEPENDENCIES || mode == JOB_IGNORE_REQUIREMENTS,
                                                 mode == JOB_IGNORE_DEPENDENCIES, e);
        if (r < 0)
                goto tr_abort;

        if (mode == JOB_ISOLATE) {
                r = transaction_add_isolate_jobs(tr, m);
                if (r < 0)
                        goto tr_abort;
        }

        r = transaction_activate(tr, m, mode, e);
        if (r < 0)
                goto tr_abort;

        log_unit_debug(unit,
                       "Enqueued job %s/%s as %u", unit->id,
                       job_type_to_string(type), (unsigned) tr->anchor_job->id);

        if (_ret)
                *_ret = tr->anchor_job;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool override, sd_bus_error *e, Job **_ret) {
        Unit *unit;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_load_unit(m, name, NULL, NULL, &unit);
        if (r < 0)
                return r;

        return manager_add_job(m, type, unit, mode, override, e, _ret);
}

Job *manager_get_job(Manager *m, uint32_t id) {
        assert(m);

        return hashmap_get(m->jobs, UINT32_TO_PTR(id));
}

Unit *manager_get_unit(Manager *m, const char *name) {
        assert(m);
        assert(name);

        return hashmap_get(m->units, name);
}

unsigned manager_dispatch_load_queue(Manager *m) {
        Unit *u;
        unsigned n = 0;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a unit from the queue and
         * tries to load its data until the queue is empty */

        while ((u = m->load_queue)) {
                assert(u->in_load_queue);

                unit_load(u);
                n++;
        }

        m->dispatching_load_queue = false;
        return n;
}

int manager_load_unit_prepare(
                Manager *m,
                const char *name,
                const char *path,
                sd_bus_error *e,
                Unit **_ret) {

        Unit *ret;
        UnitType t;
        int r;

        assert(m);
        assert(name || path);

        /* This will prepare the unit for loading, but not actually
         * load anything from disk. */

        if (path && !is_path(path))
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not absolute.", path);

        if (!name)
                name = basename(path);

        t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is not valid.", name);

        ret = manager_get_unit(m, name);
        if (ret) {
                *_ret = ret;
                return 1;
        }

        ret = unit_new(m, unit_vtable[t]->object_size);
        if (!ret)
                return -ENOMEM;

        if (path) {
                ret->fragment_path = strdup(path);
                if (!ret->fragment_path) {
                        unit_free(ret);
                        return -ENOMEM;
                }
        }

        r = unit_add_name(ret, name);
        if (r < 0) {
                unit_free(ret);
                return r;
        }

        unit_add_to_load_queue(ret);
        unit_add_to_dbus_queue(ret);
        unit_add_to_gc_queue(ret);

        if (_ret)
                *_ret = ret;

        return 0;
}

int manager_load_unit(
                Manager *m,
                const char *name,
                const char *path,
                sd_bus_error *e,
                Unit **_ret) {

        int r;

        assert(m);

        /* This will load the service information files, but not actually
         * start any services or anything. */

        r = manager_load_unit_prepare(m, name, path, e, _ret);
        if (r != 0)
                return r;

        manager_dispatch_load_queue(m);

        if (_ret)
                *_ret = unit_follow_merge(*_ret);

        return 0;
}

void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Job *j;

        assert(s);
        assert(f);

        HASHMAP_FOREACH(j, s->jobs, i)
                job_dump(j, f, prefix);
}

void manager_dump_units(Manager *s, FILE *f, const char *prefix) {
        Iterator i;
        Unit *u;
        const char *t;

        assert(s);
        assert(f);

        HASHMAP_FOREACH_KEY(u, t, s->units, i)
                if (u->id == t)
                        unit_dump(u, f, prefix);
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->jobs)))
                /* No need to recurse. We're cancelling all jobs. */
                job_finish_and_invalidate(j, JOB_CANCELED, false);
}

static int manager_dispatch_run_queue(sd_event_source *source, void *userdata) {
        Manager *m = userdata;
        Job *j;

        assert(source);
        assert(m);

        while ((j = m->run_queue)) {
                assert(j->installed);
                assert(j->in_run_queue);

                job_run_and_invalidate(j);
        }

        if (m->n_running_jobs > 0)
                manager_watch_jobs_in_progress(m);

        if (m->n_on_console > 0)
                manager_watch_idle_pipe(m);

        return 1;
}

static unsigned manager_dispatch_dbus_queue(Manager *m) {
        Job *j;
        Unit *u;
        unsigned n = 0;

        assert(m);

        if (m->dispatching_dbus_queue)
                return 0;

        m->dispatching_dbus_queue = true;

        while ((u = m->dbus_unit_queue)) {
                assert(u->in_dbus_queue);

                bus_unit_send_change_signal(u);
                n++;
        }

        while ((j = m->dbus_job_queue)) {
                assert(j->in_dbus_queue);

                bus_job_send_change_signal(j);
                n++;
        }

        m->dispatching_dbus_queue = false;

        if (m->send_reloading_done) {
                m->send_reloading_done = false;

                bus_manager_send_reloading(m, false);
        }

        if (m->queued_message)
                bus_send_queued_message(m);

        return n;
}

static void manager_invoke_notify_message(Manager *m, Unit *u, pid_t pid, char *buf, size_t n, FDSet *fds) {
        _cleanup_strv_free_ char **tags = NULL;

        assert(m);
        assert(u);
        assert(buf);
        assert(n > 0);

        tags = strv_split(buf, "\n\r");
        if (!tags) {
                log_oom();
                return;
        }

        if (UNIT_VTABLE(u)->notify_message)
                UNIT_VTABLE(u)->notify_message(u, pid, tags, fds);
        else
                log_unit_debug(u, "Got notification message for unit. Ignoring.");
}

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        ssize_t n;
        int r;

        assert(m);
        assert(m->notify_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        for (;;) {
                _cleanup_fdset_free_ FDSet *fds = NULL;
                char buf[NOTIFY_BUFFER_MAX+1];
                struct iovec iovec = {
                        .iov_base = buf,
                        .iov_len = sizeof(buf)-1,
                };
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                                    CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)];
                } control = {};
                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };
                struct cmsghdr *cmsg;
                struct ucred *ucred = NULL;
                bool found = false;
                Unit *u1, *u2, *u3;
                int *fd_array = NULL;
                unsigned n_fds = 0;

                n = recvmsg(m->notify_fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
                if (n < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                break;

                        return -errno;
                }

                CMSG_FOREACH(cmsg, &msghdr) {
                        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {

                                fd_array = (int*) CMSG_DATA(cmsg);
                                n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                        } else if (cmsg->cmsg_level == SOL_SOCKET &&
                                   cmsg->cmsg_type == SCM_CREDENTIALS &&
                                   cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                                ucred = (struct ucred*) CMSG_DATA(cmsg);
                        }
                }

                if (n_fds > 0) {
                        assert(fd_array);

                        r = fdset_new_array(&fds, fd_array, n_fds);
                        if (r < 0) {
                                close_many(fd_array, n_fds);
                                return log_oom();
                        }
                }

                if (!ucred || ucred->pid <= 0) {
                        log_warning("Received notify message without valid credentials. Ignoring.");
                        continue;
                }

                if ((size_t) n >= sizeof(buf)) {
                        log_warning("Received notify message exceeded maximum size. Ignoring.");
                        continue;
                }

                buf[n] = 0;

                /* Notify every unit that might be interested, but try
                 * to avoid notifying the same one multiple times. */
                u1 = manager_get_unit_by_pid(m, ucred->pid);
                if (u1) {
                        manager_invoke_notify_message(m, u1, ucred->pid, buf, n, fds);
                        found = true;
                }

                u2 = hashmap_get(m->watch_pids1, LONG_TO_PTR(ucred->pid));
                if (u2 && u2 != u1) {
                        manager_invoke_notify_message(m, u2, ucred->pid, buf, n, fds);
                        found = true;
                }

                u3 = hashmap_get(m->watch_pids2, LONG_TO_PTR(ucred->pid));
                if (u3 && u3 != u2 && u3 != u1) {
                        manager_invoke_notify_message(m, u3, ucred->pid, buf, n, fds);
                        found = true;
                }

                if (!found)
                        log_warning("Cannot find unit for notify message of PID "PID_FMT".", ucred->pid);

                if (fdset_size(fds) > 0)
                        log_warning("Got auxiliary fds with notification message, closing all.");
        }

        return 0;
}

static void invoke_sigchld_event(Manager *m, Unit *u, siginfo_t *si) {
        assert(m);
        assert(u);
        assert(si);

        log_unit_debug(u, "Child "PID_FMT" belongs to %s", si->si_pid, u->id);

        unit_unwatch_pid(u, si->si_pid);
        UNIT_VTABLE(u)->sigchld_event(u, si->si_pid, si->si_code, si->si_status);
}

static int manager_dispatch_sigchld(Manager *m) {
        assert(m);

        for (;;) {
                siginfo_t si = {};

                /* First we call waitd() for a PID and do not reap the
                 * zombie. That way we can still access /proc/$PID for
                 * it while it is a zombie. */
                if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG|WNOWAIT) < 0) {

                        if (errno == ECHILD)
                                break;

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (si.si_pid <= 0)
                        break;

                if (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED) {
                        _cleanup_free_ char *name = NULL;
                        Unit *u1, *u2, *u3;

                        get_process_comm(si.si_pid, &name);

                        log_debug("Child "PID_FMT" (%s) died (code=%s, status=%i/%s)",
                                  si.si_pid, strna(name),
                                  sigchld_code_to_string(si.si_code),
                                  si.si_status,
                                  strna(si.si_code == CLD_EXITED
                                        ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)
                                        : signal_to_string(si.si_status)));

                        /* And now figure out the unit this belongs
                         * to, it might be multiple... */
                        u1 = manager_get_unit_by_pid(m, si.si_pid);
                        if (u1)
                                invoke_sigchld_event(m, u1, &si);
                        u2 = hashmap_get(m->watch_pids1, LONG_TO_PTR(si.si_pid));
                        if (u2 && u2 != u1)
                                invoke_sigchld_event(m, u2, &si);
                        u3 = hashmap_get(m->watch_pids2, LONG_TO_PTR(si.si_pid));
                        if (u3 && u3 != u2 && u3 != u1)
                                invoke_sigchld_event(m, u3, &si);
                }

                /* And now, we actually reap the zombie. */
                if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }
        }

        return 0;
}

static int manager_start_target(Manager *m, const char *name, JobMode mode) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        log_debug("Activating special unit %s", name);

        r = manager_add_job_by_name(m, JOB_START, name, mode, true, &error, NULL);
        if (r < 0)
                log_error("Failed to enqueue %s job: %s", name, bus_error_message(&error, r));

        return r;
}

static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        ssize_t n;
        struct signalfd_siginfo sfsi;
        bool sigchld = false;

        assert(m);
        assert(m->signal_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected events from signal file descriptor.");
                return 0;
        }

        for (;;) {
                n = read(m->signal_fd, &sfsi, sizeof(sfsi));
                if (n != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                break;

                        return -errno;
                }

                log_received_signal(sfsi.ssi_signo == SIGCHLD ||
                                    (sfsi.ssi_signo == SIGTERM && m->running_as == MANAGER_USER)
                                    ? LOG_DEBUG : LOG_INFO,
                                    &sfsi);

                switch (sfsi.ssi_signo) {

                case SIGCHLD:
                        sigchld = true;
                        break;

                case SIGTERM:
                        if (m->running_as == MANAGER_SYSTEM) {
                                /* This is for compatibility with the
                                 * original sysvinit */
                                m->exit_code = MANAGER_REEXECUTE;
                                break;
                        }

                        /* Fall through */

                case SIGINT:
                        if (m->running_as == MANAGER_SYSTEM) {

                                /* If the user presses C-A-D more than
                                 * 7 times within 2s, we reboot
                                 * immediately. */

                                if (ratelimit_test(&m->ctrl_alt_del_ratelimit))
                                        manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE_IRREVERSIBLY);
                                else {
                                        log_notice("Ctrl-Alt-Del was pressed more than 7 times within 2s, rebooting immediately.");
                                        status_printf(NULL, true, false, "Ctrl-Alt-Del was pressed more than 7 times within 2s, rebooting immediately.");
                                        m->exit_code = MANAGER_REBOOT;
                                }

                                break;
                        }

                        /* Run the exit target if there is one, if not, just exit. */
                        if (manager_start_target(m, SPECIAL_EXIT_TARGET, JOB_REPLACE) < 0) {
                                m->exit_code = MANAGER_EXIT;
                                return 0;
                        }

                        break;

                case SIGWINCH:
                        if (m->running_as == MANAGER_SYSTEM)
                                manager_start_target(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                        /* This is a nop on non-init */
                        break;

                case SIGPWR:
                        if (m->running_as == MANAGER_SYSTEM)
                                manager_start_target(m, SPECIAL_SIGPWR_TARGET, JOB_REPLACE);

                        /* This is a nop on non-init */
                        break;

                case SIGUSR1: {
                        Unit *u;

                        u = manager_get_unit(m, SPECIAL_DBUS_SERVICE);

                        if (!u || UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u))) {
                                log_info("Trying to reconnect to bus...");
                                bus_init(m, true);
                        }

                        if (!u || !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u))) {
                                log_info("Loading D-Bus service...");
                                manager_start_target(m, SPECIAL_DBUS_SERVICE, JOB_REPLACE);
                        }

                        break;
                }

                case SIGUSR2: {
                        _cleanup_free_ char *dump = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size;

                        f = open_memstream(&dump, &size);
                        if (!f) {
                                log_warning("Failed to allocate memory stream.");
                                break;
                        }

                        manager_dump_units(m, f, "\t");
                        manager_dump_jobs(m, f, "\t");

                        if (ferror(f)) {
                                log_warning("Failed to write status stream");
                                break;
                        }

                        if (fflush(f)) {
                                log_warning("Failed to flush status stream");
                                break;
                        }

                        log_dump(LOG_INFO, dump);
                        break;
                }

                case SIGHUP:
                        m->exit_code = MANAGER_RELOAD;
                        break;

                default: {

                        /* Starting SIGRTMIN+0 */
                        static const char * const target_table[] = {
                                [0] = SPECIAL_DEFAULT_TARGET,
                                [1] = SPECIAL_RESCUE_TARGET,
                                [2] = SPECIAL_EMERGENCY_TARGET,
                                [3] = SPECIAL_HALT_TARGET,
                                [4] = SPECIAL_POWEROFF_TARGET,
                                [5] = SPECIAL_REBOOT_TARGET,
                                [6] = SPECIAL_KEXEC_TARGET
                        };

                        /* Starting SIGRTMIN+13, so that target halt and system halt are 10 apart */
                        static const ManagerExitCode code_table[] = {
                                [0] = MANAGER_HALT,
                                [1] = MANAGER_POWEROFF,
                                [2] = MANAGER_REBOOT,
                                [3] = MANAGER_KEXEC
                        };

                        if ((int) sfsi.ssi_signo >= SIGRTMIN+0 &&
                            (int) sfsi.ssi_signo < SIGRTMIN+(int) ELEMENTSOF(target_table)) {
                                int idx = (int) sfsi.ssi_signo - SIGRTMIN;
                                manager_start_target(m, target_table[idx],
                                                     (idx == 1 || idx == 2) ? JOB_ISOLATE : JOB_REPLACE);
                                break;
                        }

                        if ((int) sfsi.ssi_signo >= SIGRTMIN+13 &&
                            (int) sfsi.ssi_signo < SIGRTMIN+13+(int) ELEMENTSOF(code_table)) {
                                m->exit_code = code_table[sfsi.ssi_signo - SIGRTMIN - 13];
                                break;
                        }

                        switch (sfsi.ssi_signo - SIGRTMIN) {

                        case 20:
                                log_debug("Enabling showing of status.");
                                manager_set_show_status(m, SHOW_STATUS_YES);
                                break;

                        case 21:
                                log_debug("Disabling showing of status.");
                                manager_set_show_status(m, SHOW_STATUS_NO);
                                break;

                        case 22:
                                log_set_max_level(LOG_DEBUG);
                                log_notice("Setting log level to debug.");
                                break;

                        case 23:
                                log_set_max_level(LOG_INFO);
                                log_notice("Setting log level to info.");
                                break;

                        case 24:
                                if (m->running_as == MANAGER_USER) {
                                        m->exit_code = MANAGER_EXIT;
                                        return 0;
                                }

                                /* This is a nop on init */
                                break;

                        case 26:
                        case 29: /* compatibility: used to be mapped to LOG_TARGET_SYSLOG_OR_KMSG */
                                log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
                                log_notice("Setting log target to journal-or-kmsg.");
                                break;

                        case 27:
                                log_set_target(LOG_TARGET_CONSOLE);
                                log_notice("Setting log target to console.");
                                break;

                        case 28:
                                log_set_target(LOG_TARGET_KMSG);
                                log_notice("Setting log target to kmsg.");
                                break;

                        default:
                                log_warning("Got unhandled signal <%s>.", signal_to_string(sfsi.ssi_signo));
                        }
                }
                }
        }

        if (sigchld)
                manager_dispatch_sigchld(m);

        return 0;
}

static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Iterator i;
        Unit *u;

        assert(m);
        assert(m->time_change_fd == fd);

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_TIME_CHANGE),
                   LOG_MESSAGE("Time has been changed"),
                   NULL);

        /* Restart the watch */
        m->time_change_event_source = sd_event_source_unref(m->time_change_event_source);
        m->time_change_fd = safe_close(m->time_change_fd);

        manager_setup_time_change(m);

        HASHMAP_FOREACH(u, m->units, i)
                if (UNIT_VTABLE(u)->time_change)
                        UNIT_VTABLE(u)->time_change(u);

        return 0;
}

static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);
        assert(m->idle_pipe[2] == fd);

        m->no_console_output = m->n_on_console > 0;

        m->idle_pipe_event_source = sd_event_source_unref(m->idle_pipe_event_source);
        manager_close_idle_pipe(m);

        return 0;
}

static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = userdata;
        int r;
        uint64_t next;

        assert(m);
        assert(source);

        manager_print_jobs_in_progress(m);

        next = now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_PERIOD_USEC;
        r = sd_event_source_set_time(source, next);
        if (r < 0)
                return r;

        return sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
}

int manager_loop(Manager *m) {
        int r;

        RATELIMIT_DEFINE(rl, 1*USEC_PER_SEC, 50000);

        assert(m);
        m->exit_code = MANAGER_OK;

        /* Release the path cache */
        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;

        manager_check_finished(m);

        /* There might still be some zombies hanging around from
         * before we were exec()'ed. Let's reap them. */
        r = manager_dispatch_sigchld(m);
        if (r < 0)
                return r;

        while (m->exit_code == MANAGER_OK) {
                usec_t wait_usec;

                if (m->runtime_watchdog > 0 && m->running_as == MANAGER_SYSTEM)
                        watchdog_ping();

                if (!ratelimit_test(&rl)) {
                        /* Yay, something is going seriously wrong, pause a little */
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
                        continue;
                }

                if (manager_dispatch_load_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_queue(m) > 0)
                        continue;

                if (manager_dispatch_cleanup_queue(m) > 0)
                        continue;

                if (manager_dispatch_cgroup_queue(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

                /* Sleep for half the watchdog time */
                if (m->runtime_watchdog > 0 && m->running_as == MANAGER_SYSTEM) {
                        wait_usec = m->runtime_watchdog / 2;
                        if (wait_usec <= 0)
                                wait_usec = 1;
                } else
                        wait_usec = USEC_INFINITY;

                r = sd_event_run(m->event, wait_usec);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
        }

        return m->exit_code;
}

int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u) {
        _cleanup_free_ char *n = NULL;
        Unit *u;
        int r;

        assert(m);
        assert(s);
        assert(_u);

        r = unit_name_from_dbus_path(s, &n);
        if (r < 0)
                return r;

        r = manager_load_unit(m, n, NULL, e, &u);
        if (r < 0)
                return r;

        *_u = u;

        return 0;
}

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j) {
        const char *p;
        unsigned id;
        Job *j;
        int r;

        assert(m);
        assert(s);
        assert(_j);

        p = startswith(s, "/org/freedesktop/systemd1/job/");
        if (!p)
                return -EINVAL;

        r = safe_atou(p, &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return -ENOENT;

        *_j = j;

        return 0;
}

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success) {

#ifdef HAVE_AUDIT
        _cleanup_free_ char *p = NULL;
        const char *msg;
        int audit_fd, r;

        audit_fd = get_audit_fd();
        if (audit_fd < 0)
                return;

        /* Don't generate audit events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != MANAGER_SYSTEM)
                return;

        if (u->type != UNIT_SERVICE)
                return;

        r = unit_name_to_prefix_and_instance(u->id, &p);
        if (r < 0) {
                log_error_errno(r, "Failed to extract prefix and instance of unit name: %m");
                return;
        }

        msg = strjoina("unit=", p);
        if (audit_log_user_comm_message(audit_fd, type, msg, "systemd", NULL, NULL, NULL, success) < 0) {
                if (errno == EPERM)
                        /* We aren't allowed to send audit messages?
                         * Then let's not retry again. */
                        close_audit_fd();
                else
                        log_warning_errno(errno, "Failed to send audit message: %m");
        }
#endif

}

void manager_send_unit_plymouth(Manager *m, Unit *u) {
        union sockaddr_union sa = PLYMOUTH_SOCKET;

        int n = 0;
        _cleanup_free_ char *message = NULL;
        _cleanup_close_ int fd = -1;

        /* Don't generate plymouth events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != MANAGER_SYSTEM)
                return;

        if (detect_container(NULL) > 0)
                return;

        if (u->type != UNIT_SERVICE &&
            u->type != UNIT_MOUNT &&
            u->type != UNIT_SWAP)
                return;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message then wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error_errno(errno, "socket() failed: %m");
                return;
        }

        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1)) < 0) {

                if (!IN_SET(errno, EPIPE, EAGAIN, ENOENT, ECONNREFUSED, ECONNRESET, ECONNABORTED))
                        log_error_errno(errno, "connect() failed: %m");
                return;
        }

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->id) + 1), u->id, &n) < 0) {
                log_oom();
                return;
        }

        errno = 0;
        if (write(fd, message, n + 1) != n + 1)
                if (!IN_SET(errno, EPIPE, EAGAIN, ENOENT, ECONNREFUSED, ECONNRESET, ECONNABORTED))
                        log_error_errno(errno, "Failed to write Plymouth message: %m");
}

void manager_dispatch_bus_name_owner_changed(
                Manager *m,
                const char *name,
                const char* old_owner,
                const char *new_owner) {

        Unit *u;

        assert(m);
        assert(name);

        u = hashmap_get(m->watch_bus, name);
        if (!u)
                return;

        UNIT_VTABLE(u)->bus_name_owner_change(u, name, old_owner, new_owner);
}

int manager_open_serialization(Manager *m, FILE **_f) {
        const char *path;
        int fd = -1;
        FILE *f;

        assert(_f);

        path = m->running_as == MANAGER_SYSTEM ? "/run/systemd" : "/tmp";
        fd = open_tmpfile(path, O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        log_debug("Serializing state to %s", path);

        f = fdopen(fd, "w+");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        *_f = f;

        return 0;
}

int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root) {
        Iterator i;
        Unit *u;
        const char *t;
        char **e;
        int r;

        assert(m);
        assert(f);
        assert(fds);

        m->n_reloading ++;

        fprintf(f, "current-job-id=%"PRIu32"\n", m->current_job_id);
        fprintf(f, "taint-usr=%s\n", yes_no(m->taint_usr));
        fprintf(f, "n-installed-jobs=%u\n", m->n_installed_jobs);
        fprintf(f, "n-failed-jobs=%u\n", m->n_failed_jobs);

        dual_timestamp_serialize(f, "firmware-timestamp", &m->firmware_timestamp);
        dual_timestamp_serialize(f, "loader-timestamp", &m->loader_timestamp);
        dual_timestamp_serialize(f, "kernel-timestamp", &m->kernel_timestamp);
        dual_timestamp_serialize(f, "initrd-timestamp", &m->initrd_timestamp);

        if (!in_initrd()) {
                dual_timestamp_serialize(f, "userspace-timestamp", &m->userspace_timestamp);
                dual_timestamp_serialize(f, "finish-timestamp", &m->finish_timestamp);
                dual_timestamp_serialize(f, "security-start-timestamp", &m->security_start_timestamp);
                dual_timestamp_serialize(f, "security-finish-timestamp", &m->security_finish_timestamp);
                dual_timestamp_serialize(f, "generators-start-timestamp", &m->generators_start_timestamp);
                dual_timestamp_serialize(f, "generators-finish-timestamp", &m->generators_finish_timestamp);
                dual_timestamp_serialize(f, "units-load-start-timestamp", &m->units_load_start_timestamp);
                dual_timestamp_serialize(f, "units-load-finish-timestamp", &m->units_load_finish_timestamp);
        }

        if (!switching_root) {
                STRV_FOREACH(e, m->environment) {
                        _cleanup_free_ char *ce;

                        ce = cescape(*e);
                        if (!ce)
                                return -ENOMEM;

                        fprintf(f, "env=%s\n", *e);
                }
        }

        if (m->notify_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, m->notify_fd);
                if (copy < 0)
                        return copy;

                fprintf(f, "notify-fd=%i\n", copy);
                fprintf(f, "notify-socket=%s\n", m->notify_socket);
        }

        if (m->kdbus_fd >= 0) {
                int copy;

                copy = fdset_put_dup(fds, m->kdbus_fd);
                if (copy < 0)
                        return copy;

                fprintf(f, "kdbus-fd=%i\n", copy);
        }

        bus_track_serialize(m->subscribed, f);

        fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->id != t)
                        continue;

                /* Start marker */
                fputs(u->id, f);
                fputc('\n', f);

                r = unit_serialize(u, f, fds, !switching_root);
                if (r < 0) {
                        m->n_reloading --;
                        return r;
                }
        }

        assert(m->n_reloading > 0);
        m->n_reloading --;

        if (ferror(f))
                return -EIO;

        r = bus_fdset_add_all(m, fds);
        if (r < 0)
                return r;

        return 0;
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r = 0;

        assert(m);
        assert(f);

        log_debug("Deserializing state...");

        m->n_reloading ++;

        for (;;) {
                char line[LINE_MAX], *l;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                r = 0;
                        else
                                r = -errno;

                        goto finish;
                }

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0)
                        break;

                if (startswith(l, "current-job-id=")) {
                        uint32_t id;

                        if (safe_atou32(l+15, &id) < 0)
                                log_debug("Failed to parse current job id value %s", l+15);
                        else
                                m->current_job_id = MAX(m->current_job_id, id);

                } else if (startswith(l, "n-installed-jobs=")) {
                        uint32_t n;

                        if (safe_atou32(l+17, &n) < 0)
                                log_debug("Failed to parse installed jobs counter %s", l+17);
                        else
                                m->n_installed_jobs += n;

                } else if (startswith(l, "n-failed-jobs=")) {
                        uint32_t n;

                        if (safe_atou32(l+14, &n) < 0)
                                log_debug("Failed to parse failed jobs counter %s", l+14);
                        else
                                m->n_failed_jobs += n;

                } else if (startswith(l, "taint-usr=")) {
                        int b;

                        b = parse_boolean(l+10);
                        if (b < 0)
                                log_debug("Failed to parse taint /usr flag %s", l+10);
                        else
                                m->taint_usr = m->taint_usr || b;

                } else if (startswith(l, "firmware-timestamp="))
                        dual_timestamp_deserialize(l+19, &m->firmware_timestamp);
                else if (startswith(l, "loader-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->loader_timestamp);
                else if (startswith(l, "kernel-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->kernel_timestamp);
                else if (startswith(l, "initrd-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->initrd_timestamp);
                else if (startswith(l, "userspace-timestamp="))
                        dual_timestamp_deserialize(l+20, &m->userspace_timestamp);
                else if (startswith(l, "finish-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->finish_timestamp);
                else if (startswith(l, "security-start-timestamp="))
                        dual_timestamp_deserialize(l+25, &m->security_start_timestamp);
                else if (startswith(l, "security-finish-timestamp="))
                        dual_timestamp_deserialize(l+26, &m->security_finish_timestamp);
                else if (startswith(l, "generators-start-timestamp="))
                        dual_timestamp_deserialize(l+27, &m->generators_start_timestamp);
                else if (startswith(l, "generators-finish-timestamp="))
                        dual_timestamp_deserialize(l+28, &m->generators_finish_timestamp);
                else if (startswith(l, "units-load-start-timestamp="))
                        dual_timestamp_deserialize(l+27, &m->units_load_start_timestamp);
                else if (startswith(l, "units-load-finish-timestamp="))
                        dual_timestamp_deserialize(l+28, &m->units_load_finish_timestamp);
                else if (startswith(l, "env=")) {
                        _cleanup_free_ char *uce = NULL;
                        char **e;

                        r = cunescape(l + 4, UNESCAPE_RELAX, &uce);
                        if (r < 0)
                                goto finish;

                        e = strv_env_set(m->environment, uce);
                        if (!e) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        strv_free(m->environment);
                        m->environment = e;

                } else if (startswith(l, "notify-fd=")) {
                        int fd;

                        if (safe_atoi(l + 10, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_debug("Failed to parse notify fd: %s", l + 10);
                        else {
                                m->notify_event_source = sd_event_source_unref(m->notify_event_source);
                                safe_close(m->notify_fd);
                                m->notify_fd = fdset_remove(fds, fd);
                        }

                } else if (startswith(l, "notify-socket=")) {
                        char *n;

                        n = strdup(l+14);
                        if (!n) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        free(m->notify_socket);
                        m->notify_socket = n;

                } else if (startswith(l, "kdbus-fd=")) {
                        int fd;

                        if (safe_atoi(l + 9, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_debug("Failed to parse kdbus fd: %s", l + 9);
                        else {
                                safe_close(m->kdbus_fd);
                                m->kdbus_fd = fdset_remove(fds, fd);
                        }

                } else {
                        int k;

                        k = bus_track_deserialize_item(&m->deserialized_subscribed, l);
                        if (k < 0)
                                log_debug_errno(k, "Failed to deserialize bus tracker object: %m");
                        else if (k == 0)
                                log_debug("Unknown serialization item '%s'", l);
                }
        }

        for (;;) {
                Unit *u;
                char name[UNIT_NAME_MAX+2];

                /* Start marker */
                if (!fgets(name, sizeof(name), f)) {
                        if (feof(f))
                                r = 0;
                        else
                                r = -errno;

                        goto finish;
                }

                char_array_0(name);

                r = manager_load_unit(m, strstrip(name), NULL, NULL, &u);
                if (r < 0)
                        goto finish;

                r = unit_deserialize(u, f, fds);
                if (r < 0)
                        goto finish;
        }

finish:
        if (ferror(f))
                r = -EIO;

        assert(m->n_reloading > 0);
        m->n_reloading --;

        return r;
}

int manager_reload(Manager *m) {
        int r, q;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;

        assert(m);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return r;

        m->n_reloading ++;
        bus_manager_send_reloading(m, true);

        fds = fdset_new();
        if (!fds) {
                m->n_reloading --;
                return -ENOMEM;
        }

        r = manager_serialize(m, f, fds, false);
        if (r < 0) {
                m->n_reloading --;
                return r;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                m->n_reloading --;
                return -errno;
        }

        /* From here on there is no way back. */
        manager_clear_jobs_and_units(m);
        manager_undo_generators(m);
        lookup_paths_free(&m->lookup_paths);

        /* Find new unit paths */
        q = manager_run_generators(m);
        if (q < 0 && r >= 0)
                r = q;

        q = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
                        NULL,
                        m->generator_unit_path,
                        m->generator_unit_path_early,
                        m->generator_unit_path_late);
        if (q < 0 && r >= 0)
                r = q;

        manager_build_unit_path_cache(m);

        /* First, enumerate what we can from all config files */
        q = manager_enumerate(m);
        if (q < 0 && r >= 0)
                r = q;

        /* Second, deserialize our stored data */
        q = manager_deserialize(m, f, fds);
        if (q < 0 && r >= 0)
                r = q;

        fclose(f);
        f = NULL;

        /* Re-register notify_fd as event source */
        q = manager_setup_notify(m);
        if (q < 0 && r >= 0)
                r = q;

        /* Third, fire things up! */
        manager_coldplug(m);

        assert(m->n_reloading > 0);
        m->n_reloading--;

        m->send_reloading_done = true;

        return r;
}

bool manager_is_reloading_or_reexecuting(Manager *m) {
        assert(m);

        return m->n_reloading != 0;
}

void manager_reset_failed(Manager *m) {
        Unit *u;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i)
                unit_reset_failed(u);
}

bool manager_unit_inactive_or_pending(Manager *m, const char *name) {
        Unit *u;

        assert(m);
        assert(name);

        /* Returns true if the unit is inactive or going down */
        u = manager_get_unit(m, name);
        if (!u)
                return true;

        return unit_inactive_or_pending(u);
}

static void manager_notify_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        if (m->test_run)
                return;

        if (m->running_as == MANAGER_SYSTEM && detect_container(NULL) <= 0) {

                /* Note that m->kernel_usec.monotonic is always at 0,
                 * and m->firmware_usec.monotonic and
                 * m->loader_usec.monotonic should be considered
                 * negative values. */

                firmware_usec = m->firmware_timestamp.monotonic - m->loader_timestamp.monotonic;
                loader_usec = m->loader_timestamp.monotonic - m->kernel_timestamp.monotonic;
                userspace_usec = m->finish_timestamp.monotonic - m->userspace_timestamp.monotonic;
                total_usec = m->firmware_timestamp.monotonic + m->finish_timestamp.monotonic;

                if (dual_timestamp_is_set(&m->initrd_timestamp)) {

                        kernel_usec = m->initrd_timestamp.monotonic - m->kernel_timestamp.monotonic;
                        initrd_usec = m->userspace_timestamp.monotonic - m->initrd_timestamp.monotonic;

                        log_struct(LOG_INFO,
                                   LOG_MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "INITRD_USEC="USEC_FMT, initrd_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                               format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                               format_timespan(initrd, sizeof(initrd), initrd_usec, USEC_PER_MSEC),
                                               format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                               format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)),
                                   NULL);
                } else {
                        kernel_usec = m->userspace_timestamp.monotonic - m->kernel_timestamp.monotonic;
                        initrd_usec = 0;

                        log_struct(LOG_INFO,
                                   LOG_MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s (kernel) + %s (userspace) = %s.",
                                               format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                               format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                               format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)),
                                   NULL);
                }
        } else {
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->finish_timestamp.monotonic - m->userspace_timestamp.monotonic;

                log_struct(LOG_INFO,
                           LOG_MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                           "USERSPACE_USEC="USEC_FMT, userspace_usec,
                           LOG_MESSAGE("Startup finished in %s.",
                                       format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)),
                           NULL);
        }

        bus_manager_send_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false,
                   "READY=1\n"
                   "STATUS=Startup finished in %s.",
                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC));
}

void manager_check_finished(Manager *m) {
        Unit *u = NULL;
        Iterator i;

        assert(m);

        if (m->n_reloading > 0)
                return;

        /* Verify that we are actually running currently. Initially
         * the exit code is set to invalid, and during operation it is
         * then set to MANAGER_OK */
        if (m->exit_code != MANAGER_OK)
                return;

        if (hashmap_size(m->jobs) > 0) {

                if (m->jobs_in_progress_event_source)
                        /* Ignore any failure, this is only for feedback */
                        (void) sd_event_source_set_time(m->jobs_in_progress_event_source,
                                                        now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_WAIT_USEC);

                return;
        }

        manager_flip_auto_status(m, false);

        /* Notify Type=idle units that we are done now */
        m->idle_pipe_event_source = sd_event_source_unref(m->idle_pipe_event_source);
        manager_close_idle_pipe(m);

        /* Turn off confirm spawn now */
        m->confirm_spawn = false;

        /* No need to update ask password status when we're going non-interactive */
        manager_close_ask_password(m);

        /* This is no longer the first boot */
        manager_set_first_boot(m, false);

        if (dual_timestamp_is_set(&m->finish_timestamp))
                return;

        dual_timestamp_get(&m->finish_timestamp);

        manager_notify_finished(m);

        SET_FOREACH(u, m->startup_units, i)
                if (u->cgroup_path)
                        cgroup_context_apply(unit_get_cgroup_context(u), unit_get_cgroup_mask(u), u->cgroup_path, manager_state(m));
}

static int create_generator_dir(Manager *m, char **generator, const char *name) {
        char *p;
        int r;

        assert(m);
        assert(generator);
        assert(name);

        if (*generator)
                return 0;

        if (m->running_as == MANAGER_SYSTEM && getpid() == 1) {
                /* systemd --system, not running --test */

                p = strappend("/run/systemd/", name);
                if (!p)
                        return log_oom();

                r = mkdir_p_label(p, 0755);
                if (r < 0) {
                        log_error_errno(r, "Failed to create generator directory %s: %m", p);
                        free(p);
                        return r;
                }
        } else if (m->running_as == MANAGER_USER) {
                const char *s = NULL;

                s = getenv("XDG_RUNTIME_DIR");
                if (!s)
                        return -EINVAL;
                p = strjoin(s, "/systemd/", name, NULL);
                if (!p)
                        return log_oom();

                r = mkdir_p_label(p, 0755);
                if (r < 0) {
                        log_error_errno(r, "Failed to create generator directory %s: %m", p);
                        free(p);
                        return r;
                }
        } else {
                /* systemd --system --test */

                p = strjoin("/tmp/systemd-", name, ".XXXXXX", NULL);
                if (!p)
                        return log_oom();

                if (!mkdtemp(p)) {
                        log_error_errno(errno, "Failed to create generator directory %s: %m",
                                  p);
                        free(p);
                        return -errno;
                }
        }

        *generator = p;
        return 0;
}

static void trim_generator_dir(Manager *m, char **generator) {
        assert(m);
        assert(generator);

        if (!*generator)
                return;

        if (rmdir(*generator) >= 0) {
                free(*generator);
                *generator = NULL;
        }

        return;
}

static int manager_run_generators(Manager *m) {
        _cleanup_strv_free_ char **paths = NULL;
        const char *argv[5];
        char **path;
        int r;

        assert(m);

        if (m->test_run)
                return 0;

        paths = generator_paths(m->running_as);
        if (!paths)
                return log_oom();

        /* Optimize by skipping the whole process by not creating output directories
         * if no generators are found. */
        STRV_FOREACH(path, paths) {
                r = access(*path, F_OK);
                if (r == 0)
                        goto found;
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open generator directory %s: %m", *path);
        }
        return 0;

 found:
        r = create_generator_dir(m, &m->generator_unit_path, "generator");
        if (r < 0)
                goto finish;

        r = create_generator_dir(m, &m->generator_unit_path_early, "generator.early");
        if (r < 0)
                goto finish;

        r = create_generator_dir(m, &m->generator_unit_path_late, "generator.late");
        if (r < 0)
                goto finish;

        argv[0] = NULL; /* Leave this empty, execute_directory() will fill something in */
        argv[1] = m->generator_unit_path;
        argv[2] = m->generator_unit_path_early;
        argv[3] = m->generator_unit_path_late;
        argv[4] = NULL;

        RUN_WITH_UMASK(0022)
                execute_directories((const char* const*) paths, DEFAULT_TIMEOUT_USEC, (char**) argv);

finish:
        trim_generator_dir(m, &m->generator_unit_path);
        trim_generator_dir(m, &m->generator_unit_path_early);
        trim_generator_dir(m, &m->generator_unit_path_late);
        return r;
}

static void remove_generator_dir(Manager *m, char **generator) {
        assert(m);
        assert(generator);

        if (!*generator)
                return;

        strv_remove(m->lookup_paths.unit_path, *generator);
        (void) rm_rf(*generator, REMOVE_ROOT);

        free(*generator);
        *generator = NULL;
}

static void manager_undo_generators(Manager *m) {
        assert(m);

        remove_generator_dir(m, &m->generator_unit_path);
        remove_generator_dir(m, &m->generator_unit_path_early);
        remove_generator_dir(m, &m->generator_unit_path_late);
}

int manager_environment_add(Manager *m, char **minus, char **plus) {
        char **a = NULL, **b = NULL, **l;
        assert(m);

        l = m->environment;

        if (!strv_isempty(minus)) {
                a = strv_env_delete(l, 1, minus);
                if (!a)
                        return -ENOMEM;

                l = a;
        }

        if (!strv_isempty(plus)) {
                b = strv_env_merge(2, l, plus);
                if (!b) {
                        strv_free(a);
                        return -ENOMEM;
                }

                l = b;
        }

        if (m->environment != l)
                strv_free(m->environment);
        if (a != l)
                strv_free(a);
        if (b != l)
                strv_free(b);

        m->environment = l;
        manager_clean_environment(m);
        strv_sort(m->environment);

        return 0;
}

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit) {
        int i;

        assert(m);

        for (i = 0; i < _RLIMIT_MAX; i++) {
                if (!default_rlimit[i])
                        continue;

                m->rlimit[i] = newdup(struct rlimit, default_rlimit[i], 1);
                if (!m->rlimit[i])
                        return -ENOMEM;
        }

        return 0;
}

void manager_recheck_journal(Manager *m) {
        Unit *u;

        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return;

        u = manager_get_unit(m, SPECIAL_JOURNALD_SOCKET);
        if (u && SOCKET(u)->state != SOCKET_RUNNING) {
                log_close_journal();
                return;
        }

        u = manager_get_unit(m, SPECIAL_JOURNALD_SERVICE);
        if (u && SERVICE(u)->state != SERVICE_RUNNING) {
                log_close_journal();
                return;
        }

        /* Hmm, OK, so the socket is fully up and the service is up
         * too, then let's make use of the thing. */
        log_open();
}

void manager_set_show_status(Manager *m, ShowStatus mode) {
        assert(m);
        assert(IN_SET(mode, SHOW_STATUS_AUTO, SHOW_STATUS_NO, SHOW_STATUS_YES, SHOW_STATUS_TEMPORARY));

        if (m->running_as != MANAGER_SYSTEM)
                return;

        m->show_status = mode;

        if (mode > 0)
                touch("/run/systemd/show-status");
        else
                unlink("/run/systemd/show-status");
}

static bool manager_get_show_status(Manager *m, StatusType type) {
        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return false;

        if (m->no_console_output)
                return false;

        if (!IN_SET(manager_state(m), MANAGER_INITIALIZING, MANAGER_STARTING, MANAGER_STOPPING))
                return false;

        /* If we cannot find out the status properly, just proceed. */
        if (type != STATUS_TYPE_EMERGENCY && manager_check_ask_password(m) > 0)
                return false;

        if (m->show_status > 0)
                return true;

        return false;
}

void manager_set_first_boot(Manager *m, bool b) {
        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return;

        m->first_boot = b;

        if (m->first_boot)
                touch("/run/systemd/first-boot");
        else
                unlink("/run/systemd/first-boot");
}

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) {
        va_list ap;

        /* If m is NULL, assume we're after shutdown and let the messages through. */

        if (m && !manager_get_show_status(m, type))
                return;

        /* XXX We should totally drop the check for ephemeral here
         * and thus effectively make 'Type=idle' pointless. */
        if (type == STATUS_TYPE_EPHEMERAL && m && m->n_on_console > 0)
                return;

        va_start(ap, format);
        status_vprintf(status, true, type == STATUS_TYPE_EPHEMERAL, format, ap);
        va_end(ap);
}

int manager_get_unit_by_path(Manager *m, const char *path, const char *suffix, Unit **_found) {
        _cleanup_free_ char *p = NULL;
        Unit *found;
        int r;

        assert(m);
        assert(path);
        assert(suffix);
        assert(_found);

        r = unit_name_from_path(path, suffix, &p);
        if (r < 0)
                return r;

        found = manager_get_unit(m, p);
        if (!found) {
                *_found = NULL;
                return 0;
        }

        *_found = found;
        return 1;
}

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path) {
        char p[strlen(path)+1];

        assert(m);
        assert(path);

        strcpy(p, path);
        path_kill_slashes(p);

        return hashmap_get(m->units_requiring_mounts_for, streq(p, "/") ? "" : p);
}

const char *manager_get_runtime_prefix(Manager *m) {
        assert(m);

        return m->running_as == MANAGER_SYSTEM ?
               "/run" :
               getenv("XDG_RUNTIME_DIR");
}

void manager_update_failed_units(Manager *m, Unit *u, bool failed) {
        unsigned size;

        assert(m);
        assert(u->manager == m);

        size = set_size(m->failed_units);

        if (failed) {
                if (set_put(m->failed_units, u) < 0)
                        log_oom();
        } else
                set_remove(m->failed_units, u);

        if (set_size(m->failed_units) != size)
                bus_manager_send_change_signal(m);
}

ManagerState manager_state(Manager *m) {
        Unit *u;

        assert(m);

        /* Did we ever finish booting? If not then we are still starting up */
        if (!dual_timestamp_is_set(&m->finish_timestamp)) {

                u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
                if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                        return MANAGER_INITIALIZING;

                return MANAGER_STARTING;
        }

        /* Is the special shutdown target queued? If so, we are in shutdown state */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u && u->job && IN_SET(u->job->type, JOB_START, JOB_RESTART, JOB_TRY_RESTART, JOB_RELOAD_OR_START))
                return MANAGER_STOPPING;

        /* Are the rescue or emergency targets active or queued? If so we are in maintenance state */
        u = manager_get_unit(m, SPECIAL_RESCUE_TARGET);
        if (u && (UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)) ||
                  (u->job && IN_SET(u->job->type, JOB_START, JOB_RESTART, JOB_TRY_RESTART, JOB_RELOAD_OR_START))))
                return MANAGER_MAINTENANCE;

        u = manager_get_unit(m, SPECIAL_EMERGENCY_TARGET);
        if (u && (UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u)) ||
                  (u->job && IN_SET(u->job->type, JOB_START, JOB_RESTART, JOB_TRY_RESTART, JOB_RELOAD_OR_START))))
                return MANAGER_MAINTENANCE;

        /* Are there any failed units? If so, we are in degraded mode */
        if (set_size(m->failed_units) > 0)
                return MANAGER_DEGRADED;

        return MANAGER_RUNNING;
}

static const char *const manager_state_table[_MANAGER_STATE_MAX] = {
        [MANAGER_INITIALIZING] = "initializing",
        [MANAGER_STARTING] = "starting",
        [MANAGER_RUNNING] = "running",
        [MANAGER_DEGRADED] = "degraded",
        [MANAGER_MAINTENANCE] = "maintenance",
        [MANAGER_STOPPING] = "stopping",
};

DEFINE_STRING_TABLE_LOOKUP(manager_state, ManagerState);
