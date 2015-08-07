/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#include "sd-daemon.h"
#include "sd-messages.h"
#include "sd-path.h"

#include "all-units.h"
#include "alloc-util.h"
#include "audit-fd.h"
#include "boot-timestamps.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-kernel.h"
#include "bus-util.h"
#include "clean-ipc.h"
#include "clock-util.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "dirent-util.h"
#include "env-util.h"
#include "escape.h"
#include "exec-util.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "install.h"
#include "label.h"
#include "locale-setup.h"
#include "log.h"
#include "macro.h"
#include "manager.h"
#include "memory-util.h"
#include "missing.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "plymouth-util.h"
#include "process-util.h"
#include "ratelimit.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "transaction.h"
#include "umask-util.h"
#include "unit-name.h"
#include "user-util.h"
#include "virt.h"
#include "watchdog.h"

#define NOTIFY_RCVBUF_SIZE (8*1024*1024)
#define CGROUPS_AGENT_RCVBUF_SIZE (8*1024*1024)

/* Initial delay and the interval for printing status messages about running jobs */
#define JOBS_IN_PROGRESS_WAIT_USEC (5*USEC_PER_SEC)
#define JOBS_IN_PROGRESS_PERIOD_USEC (USEC_PER_SEC / 3)
#define JOBS_IN_PROGRESS_PERIOD_DIVISOR 3

/* If there are more than 1K bus messages queue across our API and direct buses, then let's not add more on top until
 * the queue gets more empty. */
#define MANAGER_BUS_BUSY_THRESHOLD 1024LU

/* How many units and jobs to process of the bus queue before returning to the event loop. */
#define MANAGER_BUS_MESSAGE_BUDGET 100U

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_cgroups_agent_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_user_lookup_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata);
static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata);
static int manager_dispatch_run_queue(sd_event_source *source, void *userdata);
static int manager_dispatch_sigchld(sd_event_source *source, void *userdata);
static int manager_dispatch_timezone_change(sd_event_source *source, const struct inotify_event *event, void *userdata);
static int manager_run_environment_generators(Manager *m);
static int manager_run_generators(Manager *m);

static void manager_watch_jobs_in_progress(Manager *m) {
        usec_t next;
        int r;

        assert(m);

        /* We do not want to show the cylon animation if the user
         * needs to confirm service executions otherwise confirmation
         * messages will be screwed by the cylon animation. */
        if (!manager_is_confirm_spawn_disabled(m))
                return;

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

#define CYLON_BUFFER_EXTRA (2*STRLEN(ANSI_RED) + STRLEN(ANSI_HIGHLIGHT_RED) + 2*STRLEN(ANSI_NORMAL))

static void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos) {
        char *p = buffer;

        assert(buflen >= CYLON_BUFFER_EXTRA + width + 1);
        assert(pos <= width+1); /* 0 or width+1 mean that the center light is behind the corner */

        if (pos > 1) {
                if (pos > 2)
                        p = mempset(p, ' ', pos-2);
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
        }

        if (pos > 0 && pos <= width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_HIGHLIGHT_RED);
                *p++ = '*';
        }

        if (log_get_show_color())
                p = stpcpy(p, ANSI_NORMAL);

        if (pos < width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
                if (pos < width-1)
                        p = mempset(p, ' ', width-1-pos);
                if (log_get_show_color())
                        strcpy(p, ANSI_NORMAL);
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
                              unit_status_string(j->unit),
                              time, limit);
}

static int have_ask_password(void) {
        _cleanup_closedir_ DIR *dir;
        struct dirent *de;

        dir = opendir("/run/systemd/ask-password");
        if (!dir) {
                if (errno == ENOENT)
                        return false;
                else
                        return -errno;
        }

        FOREACH_DIRENT_ALL(de, dir, return -errno) {
                if (startswith(de->d_name, "ask."))
                        return true;
        }
        return false;
}

static int manager_dispatch_ask_password_fd(sd_event_source *source,
                                            int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);

        (void) flush_fd(fd);

        m->have_ask_password = have_ask_password();
        if (m->have_ask_password < 0)
                /* Log error but continue. Negative have_ask_password
                 * is treated as unknown status. */
                log_error_errno(m->have_ask_password, "Failed to list /run/systemd/ask-password: %m");

        return 0;
}

static void manager_close_ask_password(Manager *m) {
        assert(m);

        m->ask_password_event_source = sd_event_source_unref(m->ask_password_event_source);
        m->ask_password_inotify_fd = safe_close(m->ask_password_inotify_fd);
        m->have_ask_password = -EINVAL;
}

static int manager_check_ask_password(Manager *m) {
        int r;

        assert(m);

        if (!m->ask_password_event_source) {
                assert(m->ask_password_inotify_fd < 0);

                (void) mkdir_p_label("/run/systemd/ask-password", 0755);

                m->ask_password_inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (m->ask_password_inotify_fd < 0)
                        return log_error_errno(errno, "Failed to create inotify object: %m");

                if (inotify_add_watch(m->ask_password_inotify_fd, "/run/systemd/ask-password", IN_CREATE|IN_DELETE|IN_MOVE) < 0) {
                        log_error_errno(errno, "Failed to watch \"/run/systemd/ask-password\": %m");
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

        m->idle_pipe_event_source = sd_event_source_unref(m->idle_pipe_event_source);

        safe_close_pair(m->idle_pipe);
        safe_close_pair(m->idle_pipe + 2);
}

static int manager_setup_time_change(Manager *m) {
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        m->time_change_event_source = sd_event_source_unref(m->time_change_event_source);
        m->time_change_fd = safe_close(m->time_change_fd);

        m->time_change_fd = time_change_fd();
        if (m->time_change_fd < 0)
                return log_error_errno(m->time_change_fd, "Failed to create timer change timer fd: %m");

        r = sd_event_add_io(m->event, &m->time_change_event_source, m->time_change_fd, EPOLLIN, manager_dispatch_time_change_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create time change event source: %m");

        /* Schedule this slightly earlier than the .timer event sources */
        r = sd_event_source_set_priority(m->time_change_event_source, SD_EVENT_PRIORITY_NORMAL-1);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of time change event sources: %m");

        (void) sd_event_source_set_description(m->time_change_event_source, "manager-time-change");

        log_debug("Set up TFD_TIMER_CANCEL_ON_SET timerfd.");

        return 0;
}

static int manager_read_timezone_stat(Manager *m) {
        struct stat st;
        bool changed;

        assert(m);

        /* Read the current stat() data of /etc/localtime so that we detect changes */
        if (lstat("/etc/localtime", &st) < 0) {
                log_debug_errno(errno, "Failed to stat /etc/localtime, ignoring: %m");
                changed = m->etc_localtime_accessible;
                m->etc_localtime_accessible = false;
        } else {
                usec_t k;

                k = timespec_load(&st.st_mtim);
                changed = !m->etc_localtime_accessible || k != m->etc_localtime_mtime;

                m->etc_localtime_mtime = k;
                m->etc_localtime_accessible = true;
        }

        return changed;
}

static int manager_setup_timezone_change(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *new_event = NULL;
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        /* We watch /etc/localtime for three events: change of the link count (which might mean removal from /etc even
         * though another link might be kept), renames, and file close operations after writing. Note we don't bother
         * with IN_DELETE_SELF, as that would just report when the inode is removed entirely, i.e. after the link count
         * went to zero and all fds to it are closed.
         *
         * Note that we never follow symlinks here. This is a simplification, but should cover almost all cases
         * correctly.
         *
         * Note that we create the new event source first here, before releasing the old one. This should optimize
         * behaviour as this way sd-event can reuse the old watch in case the inode didn't change. */

        r = sd_event_add_inotify(m->event, &new_event, "/etc/localtime",
                                 IN_ATTRIB|IN_MOVE_SELF|IN_CLOSE_WRITE|IN_DONT_FOLLOW, manager_dispatch_timezone_change, m);
        if (r == -ENOENT) {
                /* If the file doesn't exist yet, subscribe to /etc instead, and wait until it is created either by
                 * O_CREATE or by rename() */

                log_debug_errno(r, "/etc/localtime doesn't exist yet, watching /etc instead.");
                r = sd_event_add_inotify(m->event, &new_event, "/etc",
                                         IN_CREATE|IN_MOVED_TO|IN_ONLYDIR, manager_dispatch_timezone_change, m);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to create timezone change event source: %m");

        /* Schedule this slightly earlier than the .timer event sources */
        r = sd_event_source_set_priority(new_event, SD_EVENT_PRIORITY_NORMAL-1);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of timezone change event sources: %m");

        sd_event_source_unref(m->timezone_change_event_source);
        m->timezone_change_event_source = TAKE_PTR(new_event);

        return 0;
}

static int enable_special_signals(Manager *m) {
        _cleanup_close_ int fd = -1;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        /* Enable that we get SIGINT on control-alt-del. In containers
         * this will fail with EPERM (older) or EINVAL (newer), so
         * ignore that. */
        if (reboot(RB_DISABLE_CAD) < 0 && !IN_SET(errno, EPERM, EINVAL))
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

#define RTSIG_IF_AVAILABLE(signum) (signum <= SIGRTMAX ? signum : -1)

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

                        /* Apparently Linux on hppa had fewer RT signals until v3.18,
                         * SIGRTMAX was SIGRTMIN+25, and then SIGRTMIN was lowered,
                         * see commit v3.17-7614-g1f25df2eff.
                         *
                         * We cannot unconditionally make use of those signals here,
                         * so let's use a runtime check. Since these commands are
                         * accessible by different means and only really a safety
                         * net, the missing functionality on hppa shouldn't matter.
                         */

                        RTSIG_IF_AVAILABLE(SIGRTMIN+26), /* systemd: set log target to journal-or-kmsg */
                        RTSIG_IF_AVAILABLE(SIGRTMIN+27), /* systemd: set log target to console */
                        RTSIG_IF_AVAILABLE(SIGRTMIN+28), /* systemd: set log target to kmsg */
                        RTSIG_IF_AVAILABLE(SIGRTMIN+29), /* systemd: set log target to syslog-or-kmsg (obsolete) */

                        /* ... one free signal here SIGRTMIN+30 ... */
                        -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (m->signal_fd < 0)
                return -errno;

        r = sd_event_add_io(m->event, &m->signal_event_source, m->signal_fd, EPOLLIN, manager_dispatch_signal_fd, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->signal_event_source, "manager-signal");

        /* Process signals a bit earlier than the rest of things, but later than notify_fd processing, so that the
         * notify processing can still figure out to which process/service a message belongs, before we reap the
         * process. Also, process this before handling cgroup notifications, so that we always collect child exit
         * status information before detecting that there's no process in a cgroup. */
        r = sd_event_source_set_priority(m->signal_event_source, SD_EVENT_PRIORITY_NORMAL-6);
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(m))
                return enable_special_signals(m);

        return 0;
}

static char** sanitize_environment(char **l) {

        /* Let's remove some environment variables that we need ourselves to communicate with our clients */
        strv_env_unset_many(
                        l,
                        "EXIT_CODE",
                        "EXIT_STATUS",
                        "INVOCATION_ID",
                        "JOURNAL_STREAM",
                        "LISTEN_FDNAMES",
                        "LISTEN_FDS",
                        "LISTEN_PID",
                        "MAINPID",
                        "MANAGERPID",
                        "NOTIFY_SOCKET",
                        "PIDFILE",
                        "REMOTE_ADDR",
                        "REMOTE_PORT",
                        "SERVICE_RESULT",
                        "WATCHDOG_PID",
                        "WATCHDOG_USEC",
                        NULL);

        /* Let's order the environment alphabetically, just to make it pretty */
        strv_sort(l);

        return l;
}

int manager_default_environment(Manager *m) {
        int r;

        assert(m);

        m->transient_environment = strv_free(m->transient_environment);

        if (MANAGER_IS_SYSTEM(m)) {
                /* The system manager always starts with a clean
                 * environment for its children. It does not import
                 * the kernel's or the parents' exported variables.
                 *
                 * The initial passed environment is untouched to keep
                 * /proc/self/environ valid; it is used for tagging
                 * the init process inside containers. */
                m->transient_environment = strv_new("PATH=" DEFAULT_PATH);
                if (!m->transient_environment)
                        return log_oom();

                /* Import locale variables LC_*= from configuration */
                (void) locale_setup(&m->transient_environment);
        } else {
                _cleanup_free_ char *k = NULL;

                /* The user manager passes its own environment
                 * along to its children, except for $PATH. */
                m->transient_environment = strv_copy(environ);
                if (!m->transient_environment)
                        return log_oom();

                k = strdup("PATH=" DEFAULT_USER_PATH);
                if (!k)
                        return log_oom();

                r = strv_env_replace(&m->transient_environment, k);
                if (r < 0)
                        return log_oom();
                TAKE_PTR(k);
        }

        sanitize_environment(m->transient_environment);

        return 0;
}

static int manager_setup_prefix(Manager *m) {
        struct table_entry {
                uint64_t type;
                const char *suffix;
        };

        static const struct table_entry paths_system[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] = { SD_PATH_SYSTEM_RUNTIME, NULL },
                [EXEC_DIRECTORY_STATE] = { SD_PATH_SYSTEM_STATE_PRIVATE, NULL },
                [EXEC_DIRECTORY_CACHE] = { SD_PATH_SYSTEM_STATE_CACHE, NULL },
                [EXEC_DIRECTORY_LOGS] = { SD_PATH_SYSTEM_STATE_LOGS, NULL },
                [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_SYSTEM_CONFIGURATION, NULL },
        };

        static const struct table_entry paths_user[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] = { SD_PATH_USER_RUNTIME, NULL },
                [EXEC_DIRECTORY_STATE] = { SD_PATH_USER_CONFIGURATION, NULL },
                [EXEC_DIRECTORY_CACHE] = { SD_PATH_USER_STATE_CACHE, NULL },
                [EXEC_DIRECTORY_LOGS] = { SD_PATH_USER_CONFIGURATION, "log" },
                [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_USER_CONFIGURATION, NULL },
        };

        const struct table_entry *p;
        ExecDirectoryType i;
        int r;

        assert(m);

        if (MANAGER_IS_SYSTEM(m))
                p = paths_system;
        else
                p = paths_user;

        for (i = 0; i < _EXEC_DIRECTORY_TYPE_MAX; i++) {
                r = sd_path_home(p[i].type, p[i].suffix, &m->prefix[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void manager_free_unit_name_maps(Manager *m) {
        m->unit_id_map = hashmap_free(m->unit_id_map);
        m->unit_name_map = hashmap_free(m->unit_name_map);
        m->unit_path_cache = set_free_free(m->unit_path_cache);
        m->unit_cache_mtime =  0;
}

static int manager_setup_run_queue(Manager *m) {
        int r;

        assert(m);
        assert(!m->run_queue_event_source);

        r = sd_event_add_defer(m->event, &m->run_queue_event_source, manager_dispatch_run_queue, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->run_queue_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->run_queue_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->run_queue_event_source, "manager-run-queue");

        return 0;
}

static int manager_setup_sigchld_event_source(Manager *m) {
        int r;

        assert(m);
        assert(!m->sigchld_event_source);

        r = sd_event_add_defer(m->event, &m->sigchld_event_source, manager_dispatch_sigchld, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->sigchld_event_source, SD_EVENT_PRIORITY_NORMAL-7);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->sigchld_event_source, "manager-sigchld");

        return 0;
}

int manager_new(UnitFileScope scope, ManagerTestRunFlags test_run_flags, Manager **_m) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(_m);
        assert(IN_SET(scope, UNIT_FILE_SYSTEM, UNIT_FILE_USER));

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .unit_file_scope = scope,
                .objective = _MANAGER_OBJECTIVE_INVALID,

                .status_unit_format = STATUS_UNIT_FORMAT_DEFAULT,

                .default_timer_accuracy_usec = USEC_PER_MINUTE,
                .default_memory_accounting = MEMORY_ACCOUNTING_DEFAULT,
                .default_tasks_accounting = true,
                .default_tasks_max = UINT64_MAX,
                .default_timeout_start_usec = DEFAULT_TIMEOUT_USEC,
                .default_timeout_stop_usec = DEFAULT_TIMEOUT_USEC,
                .default_restart_usec = DEFAULT_RESTART_USEC,

                .original_log_level = -1,
                .original_log_target = _LOG_TARGET_INVALID,

                .notify_fd = -1,
                .cgroups_agent_fd = -1,
                .signal_fd = -1,
                .time_change_fd = -1,
                .user_lookup_fds = { -1, -1 },
                .private_listen_fd = -1,
                .dev_autofs_fd = -1,
                .cgroup_inotify_fd = -1,
                .pin_cgroupfs_fd = -1,
                .ask_password_inotify_fd = -1,
                .idle_pipe = { -1, -1, -1, -1},

                 /* start as id #1, so that we can leave #0 around as "null-like" value */
                .current_job_id = 1,

                .have_ask_password = -EINVAL, /* we don't know */
                .first_boot = -1,
                .test_run_flags = test_run_flags,

                .default_oom_policy = OOM_STOP,
        };

#if ENABLE_EFI
        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0)
                boot_timestamps(m->timestamps + MANAGER_TIMESTAMP_USERSPACE,
                                m->timestamps + MANAGER_TIMESTAMP_FIRMWARE,
                                m->timestamps + MANAGER_TIMESTAMP_LOADER);
#endif

        /* Prepare log fields we can use for structured logging */
        if (MANAGER_IS_SYSTEM(m)) {
                m->unit_log_field = "UNIT=";
                m->unit_log_format_string = "UNIT=%s";

                m->invocation_log_field = "INVOCATION_ID=";
                m->invocation_log_format_string = "INVOCATION_ID=%s";
        } else {
                m->unit_log_field = "USER_UNIT=";
                m->unit_log_format_string = "USER_UNIT=%s";

                m->invocation_log_field = "USER_INVOCATION_ID=";
                m->invocation_log_format_string = "USER_INVOCATION_ID=%s";
        }

        /* Reboot immediately if the user hits C-A-D more often than 7x per 2s */
        RATELIMIT_INIT(m->ctrl_alt_del_ratelimit, 2 * USEC_PER_SEC, 7);

        r = manager_default_environment(m);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->units, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->jobs, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->cgroup_unit, &path_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->watch_bus, &string_hash_ops);
        if (r < 0)
                return r;

        r = prioq_ensure_allocated(&m->run_queue, compare_job_priority);
        if (r < 0)
                return r;

        r = manager_setup_prefix(m);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = manager_setup_run_queue(m);
        if (r < 0)
                return r;

        if (test_run_flags == MANAGER_TEST_RUN_MINIMAL) {
                m->cgroup_root = strdup("");
                if (!m->cgroup_root)
                        return -ENOMEM;
        } else {
                r = manager_setup_signals(m);
                if (r < 0)
                        return r;

                r = manager_setup_cgroup(m);
                if (r < 0)
                        return r;

                r = manager_setup_time_change(m);
                if (r < 0)
                        return r;

                r = manager_read_timezone_stat(m);
                if (r < 0)
                        return r;

                (void) manager_setup_timezone_change(m);

                r = manager_setup_sigchld_event_source(m);
                if (r < 0)
                        return r;
        }

        if (MANAGER_IS_SYSTEM(m) && test_run_flags == 0) {
                r = mkdir_label("/run/systemd/units", 0755);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        m->taint_usr =
                !in_initrd() &&
                dir_is_empty("/usr") > 0;

        /* Note that we do not set up the notify fd here. We do that after deserialization,
         * since they might have gotten serialized across the reexec. */

        *_m = TAKE_PTR(m);

        return 0;
}

static int manager_setup_notify(Manager *m) {
        int r;

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        if (m->notify_fd < 0) {
                _cleanup_close_ int fd = -1;
                union sockaddr_union sa = {};
                int salen;

                /* First free all secondary fields */
                m->notify_socket = mfree(m->notify_socket);
                m->notify_event_source = sd_event_source_unref(m->notify_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate notification socket: %m");

                fd_inc_rcvbuf(fd, NOTIFY_RCVBUF_SIZE);

                m->notify_socket = path_join(m->prefix[EXEC_DIRECTORY_RUNTIME], "systemd/notify");
                if (!m->notify_socket)
                        return log_oom();

                salen = sockaddr_un_set_path(&sa.un, m->notify_socket);
                if (salen < 0)
                        return log_error_errno(salen, "Notify socket '%s' not valid for AF_UNIX socket address, refusing.", m->notify_socket);

                (void) mkdir_parents_label(m->notify_socket, 0755);
                (void) sockaddr_un_unlink(&sa.un);

                r = bind(fd, &sa.sa, salen);
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", m->notify_socket);

                r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
                if (r < 0)
                        return log_error_errno(r, "SO_PASSCRED failed: %m");

                m->notify_fd = TAKE_FD(fd);

                log_debug("Using notification socket %s", m->notify_socket);
        }

        if (!m->notify_event_source) {
                r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOLLIN, manager_dispatch_notify_fd, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate notify event source: %m");

                /* Process notification messages a bit earlier than SIGCHLD, so that we can still identify to which
                 * service an exit message belongs. */
                r = sd_event_source_set_priority(m->notify_event_source, SD_EVENT_PRIORITY_NORMAL-8);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of notify event source: %m");

                (void) sd_event_source_set_description(m->notify_event_source, "manager-notify");
        }

        return 0;
}

static int manager_setup_cgroups_agent(Manager *m) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/cgroups-agent",
        };
        int r;

        /* This creates a listening socket we receive cgroups agent messages on. We do not use D-Bus for delivering
         * these messages from the cgroups agent binary to PID 1, as the cgroups agent binary is very short-living, and
         * each instance of it needs a new D-Bus connection. Since D-Bus connections are SOCK_STREAM/AF_UNIX, on
         * overloaded systems the backlog of the D-Bus socket becomes relevant, as not more than the configured number
         * of D-Bus connections may be queued until the kernel will start dropping further incoming connections,
         * possibly resulting in lost cgroups agent messages. To avoid this, we'll use a private SOCK_DGRAM/AF_UNIX
         * socket, where no backlog is relevant as communication may take place without an actual connect() cycle, and
         * we thus won't lose messages.
         *
         * Note that PID 1 will forward the agent message to system bus, so that the user systemd instance may listen
         * to it. The system instance hence listens on this special socket, but the user instances listen on the system
         * bus for these messages. */

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether unified cgroups hierarchy is used: %m");
        if (r > 0) /* We don't need this anymore on the unified hierarchy */
                return 0;

        if (m->cgroups_agent_fd < 0) {
                _cleanup_close_ int fd = -1;

                /* First free all secondary fields */
                m->cgroups_agent_event_source = sd_event_source_unref(m->cgroups_agent_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate cgroups agent socket: %m");

                fd_inc_rcvbuf(fd, CGROUPS_AGENT_RCVBUF_SIZE);

                (void) sockaddr_un_unlink(&sa.un);

                /* Only allow root to connect to this socket */
                RUN_WITH_UMASK(0077)
                        r = bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                m->cgroups_agent_fd = TAKE_FD(fd);
        }

        if (!m->cgroups_agent_event_source) {
                r = sd_event_add_io(m->event, &m->cgroups_agent_event_source, m->cgroups_agent_fd, EPOLLIN, manager_dispatch_cgroups_agent_fd, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate cgroups agent event source: %m");

                /* Process cgroups notifications early. Note that when the agent notification is received
                 * we'll just enqueue the unit in the cgroup empty queue, hence pick a high priority than
                 * that. Also see handling of cgroup inotify for the unified cgroup stuff. */
                r = sd_event_source_set_priority(m->cgroups_agent_event_source, SD_EVENT_PRIORITY_NORMAL-9);
                if (r < 0)
                        return log_error_errno(r, "Failed to set priority of cgroups agent event source: %m");

                (void) sd_event_source_set_description(m->cgroups_agent_event_source, "manager-cgroups-agent");
        }

        return 0;
}

static int manager_setup_user_lookup_fd(Manager *m) {
        int r;

        assert(m);

        /* Set up the socket pair used for passing UID/GID resolution results from forked off processes to PID
         * 1. Background: we can't do name lookups (NSS) from PID 1, since it might involve IPC and thus activation,
         * and we might hence deadlock on ourselves. Hence we do all user/group lookups asynchronously from the forked
         * off processes right before executing the binaries to start. In order to be able to clean up any IPC objects
         * created by a unit (see RemoveIPC=) we need to know in PID 1 the used UID/GID of the executed processes,
         * hence we establish this communication channel so that forked off processes can pass their UID/GID
         * information back to PID 1. The forked off processes send their resolved UID/GID to PID 1 in a simple
         * datagram, along with their unit name, so that we can share one communication socket pair among all units for
         * this purpose.
         *
         * You might wonder why we need a communication channel for this that is independent of the usual notification
         * socket scheme (i.e. $NOTIFY_SOCKET). The primary difference is about trust: data sent via the $NOTIFY_SOCKET
         * channel is only accepted if it originates from the right unit and if reception was enabled for it. The user
         * lookup socket OTOH is only accessible by PID 1 and its children until they exec(), and always available.
         *
         * Note that this function is called under two circumstances: when we first initialize (in which case we
         * allocate both the socket pair and the event source to listen on it), and when we deserialize after a reload
         * (in which case the socket pair already exists but we still need to allocate the event source for it). */

        if (m->user_lookup_fds[0] < 0) {

                /* Free all secondary fields */
                safe_close_pair(m->user_lookup_fds);
                m->user_lookup_event_source = sd_event_source_unref(m->user_lookup_event_source);

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, m->user_lookup_fds) < 0)
                        return log_error_errno(errno, "Failed to allocate user lookup socket: %m");

                (void) fd_inc_rcvbuf(m->user_lookup_fds[0], NOTIFY_RCVBUF_SIZE);
        }

        if (!m->user_lookup_event_source) {
                r = sd_event_add_io(m->event, &m->user_lookup_event_source, m->user_lookup_fds[0], EPOLLIN, manager_dispatch_user_lookup_fd, m);
                if (r < 0)
                        return log_error_errno(errno, "Failed to allocate user lookup event source: %m");

                /* Process even earlier than the notify event source, so that we always know first about valid UID/GID
                 * resolutions */
                r = sd_event_source_set_priority(m->user_lookup_event_source, SD_EVENT_PRIORITY_NORMAL-11);
                if (r < 0)
                        return log_error_errno(errno, "Failed to set priority of user lookup event source: %m");

                (void) sd_event_source_set_description(m->user_lookup_event_source, "user-lookup");
        }

        return 0;
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

static void unit_gc_mark_good(Unit *u, unsigned gc_marker) {
        Unit *other;
        Iterator i;
        void *v;

        u->gc_marker = gc_marker + GC_OFFSET_GOOD;

        /* Recursively mark referenced units as GOOD as well */
        HASHMAP_FOREACH_KEY(v, other, u->dependencies[UNIT_REFERENCES], i)
                if (other->gc_marker == gc_marker + GC_OFFSET_UNSURE)
                        unit_gc_mark_good(other, gc_marker);
}

static void unit_gc_sweep(Unit *u, unsigned gc_marker) {
        Unit *other;
        bool is_bad;
        Iterator i;
        void *v;

        assert(u);

        if (IN_SET(u->gc_marker - gc_marker,
                   GC_OFFSET_GOOD, GC_OFFSET_BAD, GC_OFFSET_UNSURE, GC_OFFSET_IN_PATH))
                return;

        if (u->in_cleanup_queue)
                goto bad;

        if (!unit_may_gc(u))
                goto good;

        u->gc_marker = gc_marker + GC_OFFSET_IN_PATH;

        is_bad = true;

        HASHMAP_FOREACH_KEY(v, other, u->dependencies[UNIT_REFERENCED_BY], i) {
                unit_gc_sweep(other, gc_marker);

                if (other->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        if (u->refs_by_target) {
                const UnitRef *ref;

                LIST_FOREACH(refs_by_target, ref, u->refs_by_target) {
                        unit_gc_sweep(ref->source, gc_marker);

                        if (ref->source->gc_marker == gc_marker + GC_OFFSET_GOOD)
                                goto good;

                        if (ref->source->gc_marker != gc_marker + GC_OFFSET_BAD)
                                is_bad = false;
                }
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
        unit_gc_mark_good(u, gc_marker);
}

static unsigned manager_dispatch_gc_unit_queue(Manager *m) {
        unsigned n = 0, gc_marker;
        Unit *u;

        assert(m);

        /* log_debug("Running GC..."); */

        m->gc_marker += _GC_OFFSET_MAX;
        if (m->gc_marker + _GC_OFFSET_MAX <= _GC_OFFSET_MAX)
                m->gc_marker = 1;

        gc_marker = m->gc_marker;

        while ((u = m->gc_unit_queue)) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

                LIST_REMOVE(gc_queue, m->gc_unit_queue, u);
                u->in_gc_queue = false;

                n++;

                if (IN_SET(u->gc_marker - gc_marker,
                           GC_OFFSET_BAD, GC_OFFSET_UNSURE)) {
                        if (u->id)
                                log_unit_debug(u, "Collecting.");
                        u->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(u);
                }
        }

        return n;
}

static unsigned manager_dispatch_gc_job_queue(Manager *m) {
        unsigned n = 0;
        Job *j;

        assert(m);

        while ((j = m->gc_job_queue)) {
                assert(j->in_gc_queue);

                LIST_REMOVE(gc_queue, m->gc_job_queue, j);
                j->in_gc_queue = false;

                n++;

                if (!job_may_gc(j))
                        continue;

                log_unit_debug(j->unit, "Collecting job.");
                (void) job_finish_and_invalidate(j, JOB_COLLECTED, false, false);
        }

        return n;
}

static unsigned manager_dispatch_stop_when_unneeded_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;
        int r;

        assert(m);

        while ((u = m->stop_when_unneeded_queue)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                assert(m->stop_when_unneeded_queue);

                assert(u->in_stop_when_unneeded_queue);
                LIST_REMOVE(stop_when_unneeded_queue, m->stop_when_unneeded_queue, u);
                u->in_stop_when_unneeded_queue = false;

                n++;

                if (!unit_is_unneeded(u))
                        continue;

                log_unit_debug(u, "Unit is not needed anymore.");

                /* If stopping a unit fails continuously we might enter a stop loop here, hence stop acting on the
                 * service being unnecessary after a while. */

                if (!ratelimit_below(&u->auto_stop_ratelimit)) {
                        log_unit_warning(u, "Unit not needed anymore, but not stopping since we tried this too often recently.");
                        continue;
                }

                /* Ok, nobody needs us anymore. Sniff. Then let's commit suicide */
                r = manager_add_job(u->manager, JOB_STOP, u, JOB_FAIL, NULL, &error, NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enqueue stop job, ignoring: %s", bus_error_message(&error, r));
        }

        return n;
}

static void manager_clear_jobs_and_units(Manager *m) {
        Unit *u;

        assert(m);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        manager_dispatch_cleanup_queue(m);

        assert(!m->load_queue);
        assert(prioq_isempty(m->run_queue));
        assert(!m->dbus_unit_queue);
        assert(!m->dbus_job_queue);
        assert(!m->cleanup_queue);
        assert(!m->gc_unit_queue);
        assert(!m->gc_job_queue);
        assert(!m->stop_when_unneeded_queue);

        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));

        m->n_on_console = 0;
        m->n_running_jobs = 0;
        m->n_installed_jobs = 0;
        m->n_failed_jobs = 0;
}

Manager* manager_free(Manager *m) {
        ExecDirectoryType dt;
        UnitType c;

        if (!m)
                return NULL;

        manager_clear_jobs_and_units(m);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        /* Keep the cgroup hierarchy in place except when we know we are going down for good */
        manager_shutdown_cgroup(m, IN_SET(m->objective, MANAGER_EXIT, MANAGER_REBOOT, MANAGER_POWEROFF, MANAGER_HALT, MANAGER_KEXEC));

        lookup_paths_flush_generator(&m->lookup_paths);

        bus_done(m);

        exec_runtime_vacuum(m);
        hashmap_free(m->exec_runtime_by_id);

        dynamic_user_vacuum(m, false);
        hashmap_free(m->dynamic_users);

        hashmap_free(m->units);
        hashmap_free(m->units_by_invocation_id);
        hashmap_free(m->jobs);
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_bus);

        prioq_free(m->run_queue);

        set_free(m->startup_units);
        set_free(m->failed_units);

        sd_event_source_unref(m->signal_event_source);
        sd_event_source_unref(m->sigchld_event_source);
        sd_event_source_unref(m->notify_event_source);
        sd_event_source_unref(m->cgroups_agent_event_source);
        sd_event_source_unref(m->time_change_event_source);
        sd_event_source_unref(m->timezone_change_event_source);
        sd_event_source_unref(m->jobs_in_progress_event_source);
        sd_event_source_unref(m->run_queue_event_source);
        sd_event_source_unref(m->user_lookup_event_source);
        sd_event_source_unref(m->sync_bus_names_event_source);

        safe_close(m->signal_fd);
        safe_close(m->notify_fd);
        safe_close(m->cgroups_agent_fd);
        safe_close(m->time_change_fd);
        safe_close_pair(m->user_lookup_fds);

        manager_close_ask_password(m);

        manager_close_idle_pipe(m);

        sd_event_unref(m->event);

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->transient_environment);
        strv_free(m->client_environment);

        hashmap_free(m->cgroup_unit);
        manager_free_unit_name_maps(m);

        free(m->switch_root);
        free(m->switch_root_init);

        rlimit_free_all(m->rlimit);

        assert(hashmap_isempty(m->units_requiring_mounts_for));
        hashmap_free(m->units_requiring_mounts_for);

        hashmap_free(m->uid_refs);
        hashmap_free(m->gid_refs);

        for (dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++)
                m->prefix[dt] = mfree(m->prefix[dt]);

        return mfree(m);
}

static void manager_enumerate_perpetual(Manager *m) {
        UnitType c;

        assert(m);

        if (m->test_run_flags == MANAGER_TEST_RUN_MINIMAL)
                return;

        /* Let's ask every type to load all units from disk/kernel that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++) {
                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (unit_vtable[c]->enumerate_perpetual)
                        unit_vtable[c]->enumerate_perpetual(m);
        }
}

static void manager_enumerate(Manager *m) {
        UnitType c;

        assert(m);

        if (m->test_run_flags == MANAGER_TEST_RUN_MINIMAL)
                return;

        /* Let's ask every type to load all units from disk/kernel that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++) {
                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (unit_vtable[c]->enumerate)
                        unit_vtable[c]->enumerate(m);
        }

        manager_dispatch_load_queue(m);
}

static void manager_coldplug(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;
        int r;

        assert(m);

        log_debug("Invoking unit coldplug() handlers…");

        /* Let's place the units back into their deserialized state */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                r = unit_coldplug(u);
                if (r < 0)
                        log_warning_errno(r, "We couldn't coldplug %s, proceeding anyway: %m", u->id);
        }
}

static void manager_catchup(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;

        assert(m);

        log_debug("Invoking unit catchup() handlers…");

        /* Let's catch up on any state changes that happened while we were reloading/reexecing */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                unit_catchup(u);
        }
}

static void manager_distribute_fds(Manager *m, FDSet *fds) {
        Iterator i;
        Unit *u;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i) {

                if (fdset_size(fds) <= 0)
                        break;

                if (!UNIT_VTABLE(u)->distribute_fds)
                        continue;

                UNIT_VTABLE(u)->distribute_fds(u, fds);
        }
}

static bool manager_dbus_is_running(Manager *m, bool deserialized) {
        Unit *u;

        assert(m);

        /* This checks whether the dbus instance we are supposed to expose our APIs on is up. We check both the socket
         * and the service unit. If the 'deserialized' parameter is true we'll check the deserialized state of the unit
         * rather than the current one. */

        if (MANAGER_IS_TEST_RUN(m))
                return false;

        u = manager_get_unit(m, SPECIAL_DBUS_SOCKET);
        if (!u)
                return false;
        if ((deserialized ? SOCKET(u)->deserialized_state : SOCKET(u)->state) != SOCKET_RUNNING)
                return false;

        u = manager_get_unit(m, SPECIAL_DBUS_SERVICE);
        if (!u)
                return false;
        if (!IN_SET((deserialized ? SERVICE(u)->deserialized_state : SERVICE(u)->state), SERVICE_RUNNING, SERVICE_RELOAD))
                return false;

        return true;
}

static void manager_setup_bus(Manager *m) {
        assert(m);

        /* Let's set up our private bus connection now, unconditionally */
        (void) bus_init_private(m);

        /* If we are in --user mode also connect to the system bus now */
        if (MANAGER_IS_USER(m))
                (void) bus_init_system(m);

        /* Let's connect to the bus now, but only if the unit is supposed to be up */
        if (manager_dbus_is_running(m, MANAGER_IS_RELOADING(m))) {
                (void) bus_init_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_init_system(m);
        }
}

static void manager_preset_all(Manager *m) {
        int r;

        assert(m);

        if (m->first_boot <= 0)
                return;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (MANAGER_IS_TEST_RUN(m))
                return;

        /* If this is the first boot, and we are in the host system, then preset everything */
        r = unit_file_preset_all(UNIT_FILE_SYSTEM, 0, NULL, UNIT_FILE_PRESET_ENABLE_ONLY, NULL, 0);
        if (r < 0)
                log_full_errno(r == -EEXIST ? LOG_NOTICE : LOG_WARNING, r,
                               "Failed to populate /etc with preset unit settings, ignoring: %m");
        else
                log_info("Populated /etc with preset unit settings.");
}

static void manager_vacuum(Manager *m) {
        assert(m);

        /* Release any dynamic users no longer referenced */
        dynamic_user_vacuum(m, true);

        /* Release any references to UIDs/GIDs no longer referenced, and destroy any IPC owned by them */
        manager_vacuum_uid_refs(m);
        manager_vacuum_gid_refs(m);

        /* Release any runtimes no longer referenced */
        exec_runtime_vacuum(m);
}

static void manager_ready(Manager *m) {
        assert(m);

        /* After having loaded everything, do the final round of catching up with what might have changed */

        m->objective = MANAGER_OK; /* Tell everyone we are up now */

        /* It might be safe to log to the journal now and connect to dbus */
        manager_recheck_journal(m);
        manager_recheck_dbus(m);

        /* Sync current state of bus names with our set of listening units */
        (void) manager_enqueue_sync_bus_names(m);

        /* Let's finally catch up with any changes that took place while we were reloading/reexecing */
        manager_catchup(m);

        m->honor_device_enumeration = true;
}

static Manager* manager_reloading_start(Manager *m) {
        m->n_reloading++;
        return m;
}
static void manager_reloading_stopp(Manager **m) {
        if (*m) {
                assert((*m)->n_reloading > 0);
                (*m)->n_reloading--;
        }
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r;

        assert(m);

        /* If we are running in test mode, we still want to run the generators,
         * but we should not touch the real generator directories. */
        r = lookup_paths_init(&m->lookup_paths, m->unit_file_scope,
                              MANAGER_IS_TEST_RUN(m) ? LOOKUP_PATHS_TEMPORARY_GENERATED : 0,
                              NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize path lookup table: %m");

        dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_START));
        r = manager_run_environment_generators(m);
        if (r >= 0)
                r = manager_run_generators(m);
        dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_FINISH));
        if (r < 0)
                return r;

        manager_preset_all(m);

        lookup_paths_log(&m->lookup_paths);

        {
                /* This block is (optionally) done with the reloading counter bumped */
                _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;

                /* If we will deserialize make sure that during enumeration this is already known, so we increase the
                 * counter here already */
                if (serialization)
                        reloading = manager_reloading_start(m);

                /* First, enumerate what we can from all config files */
                dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_START));
                manager_enumerate_perpetual(m);
                manager_enumerate(m);
                dual_timestamp_get(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_FINISH));

                /* Second, deserialize if there is something to deserialize */
                if (serialization) {
                        r = manager_deserialize(m, serialization, fds);
                        if (r < 0)
                                return log_error_errno(r, "Deserialization failed: %m");
                }

                /* Any fds left? Find some unit which wants them. This is useful to allow container managers to pass
                 * some file descriptors to us pre-initialized. This enables socket-based activation of entire
                 * containers. */
                manager_distribute_fds(m, fds);

                /* We might have deserialized the notify fd, but if we didn't then let's create the bus now */
                r = manager_setup_notify(m);
                if (r < 0)
                        /* No sense to continue without notifications, our children would fail anyway. */
                        return r;

                r = manager_setup_cgroups_agent(m);
                if (r < 0)
                        /* Likewise, no sense to continue without empty cgroup notifications. */
                        return r;

                r = manager_setup_user_lookup_fd(m);
                if (r < 0)
                        /* This shouldn't fail, except if things are really broken. */
                        return r;

                /* Connect to the bus if we are good for it */
                manager_setup_bus(m);

                /* Now that we are connected to all possible buses, let's deserialize who is tracking us. */
                r = bus_track_coldplug(m, &m->subscribed, false, m->deserialized_subscribed);
                if (r < 0)
                        log_warning_errno(r, "Failed to deserialized tracked clients, ignoring: %m");
                m->deserialized_subscribed = strv_free(m->deserialized_subscribed);

                /* Third, fire things up! */
                manager_coldplug(m);

                /* Clean up runtime objects */
                manager_vacuum(m);

                if (serialization)
                        /* Let's wait for the UnitNew/JobNew messages being sent, before we notify that the
                         * reload is finished */
                        m->send_reloading_done = true;
        }

        manager_ready(m);

        return 0;
}

int manager_add_job(
                Manager *m,
                JobType type,
                Unit *unit,
                JobMode mode,
                Set *affected_jobs,
                sd_bus_error *error,
                Job **ret) {

        Transaction *tr;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Isolate is only valid for start.");

        if (mode == JOB_ISOLATE && !unit->allow_isolate)
                return sd_bus_error_setf(error, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");

        log_unit_debug(unit, "Trying to enqueue job %s/%s/%s", unit->id, job_type_to_string(type), job_mode_to_string(mode));

        type = job_type_collapse(type, unit);

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        r = transaction_add_job_and_dependencies(tr, type, unit, NULL, true, false,
                                                 IN_SET(mode, JOB_IGNORE_DEPENDENCIES, JOB_IGNORE_REQUIREMENTS),
                                                 mode == JOB_IGNORE_DEPENDENCIES, error);
        if (r < 0)
                goto tr_abort;

        if (mode == JOB_ISOLATE) {
                r = transaction_add_isolate_jobs(tr, m);
                if (r < 0)
                        goto tr_abort;
        }

        r = transaction_activate(tr, m, mode, affected_jobs, error);
        if (r < 0)
                goto tr_abort;

        log_unit_debug(unit,
                       "Enqueued job %s/%s as %u", unit->id,
                       job_type_to_string(type), (unsigned) tr->anchor_job->id);

        if (ret)
                *ret = tr->anchor_job;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs, sd_bus_error *e, Job **ret) {
        Unit *unit = NULL;  /* just to appease gcc, initialization is not really necessary */
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_load_unit(m, name, NULL, NULL, &unit);
        if (r < 0)
                return r;
        assert(unit);

        return manager_add_job(m, type, unit, mode, affected_jobs, e, ret);
}

int manager_add_job_by_name_and_warn(Manager *m, JobType type, const char *name, JobMode mode, Set *affected_jobs, Job **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        r = manager_add_job_by_name(m, type, name, mode, affected_jobs, &error, ret);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue %s job for %s: %s", job_mode_to_string(mode), name, bus_error_message(&error, r));

        return r;
}

int manager_propagate_reload(Manager *m, Unit *unit, JobMode mode, sd_bus_error *e) {
        int r;
        Transaction *tr;

        assert(m);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);
        assert(mode != JOB_ISOLATE); /* Isolate is only valid for start */

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        /* We need an anchor job */
        r = transaction_add_job_and_dependencies(tr, JOB_NOP, unit, NULL, false, false, true, true, e);
        if (r < 0)
                goto tr_abort;

        /* Failure in adding individual dependencies is ignored, so this always succeeds. */
        transaction_add_propagate_reload_jobs(tr, unit, tr->anchor_job, mode == JOB_IGNORE_DEPENDENCIES, e);

        r = transaction_activate(tr, m, mode, NULL, e);
        if (r < 0)
                goto tr_abort;

        transaction_free(tr);
        return 0;

tr_abort:
        transaction_abort(tr);
        transaction_free(tr);
        return r;
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

static int manager_dispatch_target_deps_queue(Manager *m) {
        Unit *u;
        unsigned k;
        int r = 0;

        static const UnitDependency deps[] = {
                UNIT_REQUIRED_BY,
                UNIT_REQUISITE_OF,
                UNIT_WANTED_BY,
                UNIT_BOUND_BY
        };

        assert(m);

        while ((u = m->target_deps_queue)) {
                assert(u->in_target_deps_queue);

                LIST_REMOVE(target_deps_queue, u->manager->target_deps_queue, u);
                u->in_target_deps_queue = false;

                for (k = 0; k < ELEMENTSOF(deps); k++) {
                        Unit *target;
                        Iterator i;
                        void *v;

                        HASHMAP_FOREACH_KEY(v, target, u->dependencies[deps[k]], i) {
                                r = unit_add_default_target_dependency(u, target);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return r;
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

        /* Dispatch the units waiting for their target dependencies to be added now, as all targets that we know about
         * should be loaded and have aliases resolved */
        (void) manager_dispatch_target_deps_queue(m);

        return n;
}

int manager_load_unit_prepare(
                Manager *m,
                const char *name,
                const char *path,
                sd_bus_error *e,
                Unit **_ret) {

        _cleanup_(unit_freep) Unit *cleanup_ret = NULL;
        Unit *ret;
        UnitType t;
        int r;

        assert(m);
        assert(name || path);
        assert(_ret);

        /* This will prepare the unit for loading, but not actually
         * load anything from disk. */

        if (path && !is_path(path))
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not absolute.", path);

        if (!name)
                name = basename(path);

        t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                        return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is missing the instance name.", name);

                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is not valid.", name);
        }

        ret = manager_get_unit(m, name);
        if (ret) {
                *_ret = ret;
                return 1;
        }

        ret = cleanup_ret = unit_new(m, unit_vtable[t]->object_size);
        if (!ret)
                return -ENOMEM;

        if (path) {
                ret->fragment_path = strdup(path);
                if (!ret->fragment_path)
                        return -ENOMEM;
        }

        r = unit_add_name(ret, name);
        if (r < 0)
                return r;

        unit_add_to_load_queue(ret);
        unit_add_to_dbus_queue(ret);
        unit_add_to_gc_queue(ret);

        *_ret = ret;
        cleanup_ret = NULL;

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
        assert(_ret);

        /* This will load the service information files, but not actually
         * start any services or anything. */

        r = manager_load_unit_prepare(m, name, path, e, _ret);
        if (r != 0)
                return r;

        manager_dispatch_load_queue(m);

        *_ret = unit_follow_merge(*_ret);
        return 0;
}

int manager_load_startable_unit_or_warn(
                Manager *m,
                const char *name,
                const char *path,
                Unit **ret) {

        /* Load a unit, make sure it loaded fully and is not masked. */

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Unit *unit;
        int r;

        r = manager_load_unit(m, name, path, &error, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to load %s %s: %s",
                                       name ? "unit" : "unit file", name ?: path,
                                       bus_error_message(&error, r));

        r = bus_unit_validate_load_state(unit, &error);
        if (r < 0)
                return log_error_errno(r, "%s", bus_error_message(&error, r));

        *ret = unit;
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

void manager_dump(Manager *m, FILE *f, const char *prefix) {
        ManagerTimestamp q;

        assert(m);
        assert(f);

        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                const dual_timestamp *t = m->timestamps + q;
                char buf[CONST_MAX(FORMAT_TIMESPAN_MAX, FORMAT_TIMESTAMP_MAX)];

                if (dual_timestamp_is_set(t))
                        fprintf(f, "%sTimestamp %s: %s\n",
                                strempty(prefix),
                                manager_timestamp_to_string(q),
                                timestamp_is_set(t->realtime) ? format_timestamp(buf, sizeof buf, t->realtime) :
                                                                format_timespan(buf, sizeof buf, t->monotonic, 1));
        }

        manager_dump_units(m, f, prefix);
        manager_dump_jobs(m, f, prefix);
}

int manager_get_dump_string(Manager *m, char **ret) {
        _cleanup_free_ char *dump = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t size;
        int r;

        assert(m);
        assert(ret);

        f = open_memstream_unlocked(&dump, &size);
        if (!f)
                return -errno;

        manager_dump(m, f, NULL);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        f = safe_fclose(f);

        *ret = TAKE_PTR(dump);

        return 0;
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->jobs)))
                /* No need to recurse. We're cancelling all jobs. */
                job_finish_and_invalidate(j, JOB_CANCELED, false, false);
}

void manager_unwatch_pid(Manager *m, pid_t pid) {
        assert(m);

        /* First let's drop the unit keyed as "pid". */
        (void) hashmap_remove(m->watch_pids, PID_TO_PTR(pid));

        /* Then, let's also drop the array keyed by -pid. */
        free(hashmap_remove(m->watch_pids, PID_TO_PTR(-pid)));
}

static int manager_dispatch_run_queue(sd_event_source *source, void *userdata) {
        Manager *m = userdata;
        Job *j;

        assert(source);
        assert(m);

        while ((j = prioq_peek(m->run_queue))) {
                assert(j->installed);
                assert(j->in_run_queue);

                (void) job_run_and_invalidate(j);
        }

        if (m->n_running_jobs > 0)
                manager_watch_jobs_in_progress(m);

        if (m->n_on_console > 0)
                manager_watch_idle_pipe(m);

        return 1;
}

static unsigned manager_dispatch_dbus_queue(Manager *m) {
        unsigned n = 0, budget;
        Unit *u;
        Job *j;

        assert(m);

        /* When we are reloading, let's not wait with generating signals, since we need to exit the manager as quickly
         * as we can. There's no point in throttling generation of signals in that case. */
        if (MANAGER_IS_RELOADING(m) || m->send_reloading_done || m->pending_reload_message)
                budget = (unsigned) -1; /* infinite budget in this case */
        else {
                /* Anything to do at all? */
                if (!m->dbus_unit_queue && !m->dbus_job_queue)
                        return 0;

                /* Do we have overly many messages queued at the moment? If so, let's not enqueue more on top, let's
                 * sit this cycle out, and process things in a later cycle when the queues got a bit emptier. */
                if (manager_bus_n_queued_write(m) > MANAGER_BUS_BUSY_THRESHOLD)
                        return 0;

                /* Only process a certain number of units/jobs per event loop iteration. Even if the bus queue wasn't
                 * overly full before this call we shouldn't increase it in size too wildly in one step, and we
                 * shouldn't monopolize CPU time with generating these messages. Note the difference in counting of
                 * this "budget" and the "threshold" above: the "budget" is decreased only once per generated message,
                 * regardless how many buses/direct connections it is enqueued on, while the "threshold" is applied to
                 * each queued instance of bus message, i.e. if the same message is enqueued to five buses/direct
                 * connections it will be counted five times. This difference in counting ("references"
                 * vs. "instances") is primarily a result of the fact that it's easier to implement it this way,
                 * however it also reflects the thinking that the "threshold" should put a limit on used queue memory,
                 * i.e. space, while the "budget" should put a limit on time. Also note that the "threshold" is
                 * currently chosen much higher than the "budget". */
                budget = MANAGER_BUS_MESSAGE_BUDGET;
        }

        while (budget != 0 && (u = m->dbus_unit_queue)) {

                assert(u->in_dbus_queue);

                bus_unit_send_change_signal(u);
                n++;

                if (budget != (unsigned) -1)
                        budget--;
        }

        while (budget != 0 && (j = m->dbus_job_queue)) {
                assert(j->in_dbus_queue);

                bus_job_send_change_signal(j);
                n++;

                if (budget != (unsigned) -1)
                        budget--;
        }

        if (m->send_reloading_done) {
                m->send_reloading_done = false;
                bus_manager_send_reloading(m, false);
                n++;
        }

        if (m->pending_reload_message) {
                bus_send_pending_reload_message(m);
                n++;
        }

        return n;
}

static int manager_dispatch_cgroups_agent_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        char buf[PATH_MAX];
        ssize_t n;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to read cgroups agent message: %m");
        if (n == 0) {
                log_error("Got zero-length cgroups agent message, ignoring.");
                return 0;
        }
        if ((size_t) n >= sizeof(buf)) {
                log_error("Got overly long cgroups agent message, ignoring.");
                return 0;
        }

        if (memchr(buf, 0, n)) {
                log_error("Got cgroups agent message with embedded NUL byte, ignoring.");
                return 0;
        }
        buf[n] = 0;

        manager_notify_cgroup_empty(m, buf);
        (void) bus_forward_agent_released(m, buf);

        return 0;
}

static void manager_invoke_notify_message(
                Manager *m,
                Unit *u,
                const struct ucred *ucred,
                const char *buf,
                FDSet *fds) {

        assert(m);
        assert(u);
        assert(ucred);
        assert(buf);

        if (u->notifygen == m->notifygen) /* Already invoked on this same unit in this same iteration? */
                return;
        u->notifygen = m->notifygen;

        if (UNIT_VTABLE(u)->notify_message) {
                _cleanup_strv_free_ char **tags = NULL;

                tags = strv_split(buf, NEWLINE);
                if (!tags) {
                        log_oom();
                        return;
                }

                UNIT_VTABLE(u)->notify_message(u, ucred, tags, fds);

        } else if (DEBUG_LOGGING) {
                _cleanup_free_ char *x = NULL, *y = NULL;

                x = ellipsize(buf, 20, 90);
                if (x)
                        y = cescape(x);

                log_unit_debug(u, "Got notification message \"%s\", ignoring.", strnull(y));
        }
}

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {

        _cleanup_fdset_free_ FDSet *fds = NULL;
        Manager *m = userdata;
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
        _cleanup_free_ Unit **array_copy = NULL;
        Unit *u1, *u2, **array;
        int r, *fd_array = NULL;
        size_t n_fds = 0;
        bool found = false;
        ssize_t n;

        assert(m);
        assert(m->notify_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        n = recvmsg(m->notify_fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC|MSG_TRUNC);
        if (n < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0; /* Spurious wakeup, try again */

                /* If this is any other, real error, then let's stop processing this socket. This of course means we
                 * won't take notification messages anymore, but that's still better than busy looping around this:
                 * being woken up over and over again but being unable to actually read the message off the socket. */
                return log_error_errno(errno, "Failed to receive notification message: %m");
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
                        log_oom();
                        return 0;
                }
        }

        if (!ucred || !pid_is_valid(ucred->pid)) {
                log_warning("Received notify message without valid credentials. Ignoring.");
                return 0;
        }

        if ((size_t) n >= sizeof(buf) || (msghdr.msg_flags & MSG_TRUNC)) {
                log_warning("Received notify message exceeded maximum size. Ignoring.");
                return 0;
        }

        /* As extra safety check, let's make sure the string we get doesn't contain embedded NUL bytes. We permit one
         * trailing NUL byte in the message, but don't expect it. */
        if (n > 1 && memchr(buf, 0, n-1)) {
                log_warning("Received notify message with embedded NUL bytes. Ignoring.");
                return 0;
        }

        /* Make sure it's NUL-terminated. */
        buf[n] = 0;

        /* Increase the generation counter used for filtering out duplicate unit invocations. */
        m->notifygen++;

        /* Notify every unit that might be interested, which might be multiple. */
        u1 = manager_get_unit_by_pid_cgroup(m, ucred->pid);
        u2 = hashmap_get(m->watch_pids, PID_TO_PTR(ucred->pid));
        array = hashmap_get(m->watch_pids, PID_TO_PTR(-ucred->pid));
        if (array) {
                size_t k = 0;

                while (array[k])
                        k++;

                array_copy = newdup(Unit*, array, k+1);
                if (!array_copy)
                        log_oom();
        }
        /* And now invoke the per-unit callbacks. Note that manager_invoke_notify_message() will handle duplicate units
         * make sure we only invoke each unit's handler once. */
        if (u1) {
                manager_invoke_notify_message(m, u1, ucred, buf, fds);
                found = true;
        }
        if (u2) {
                manager_invoke_notify_message(m, u2, ucred, buf, fds);
                found = true;
        }
        if (array_copy)
                for (size_t i = 0; array_copy[i]; i++) {
                        manager_invoke_notify_message(m, array_copy[i], ucred, buf, fds);
                        found = true;
                }

        if (!found)
                log_warning("Cannot find unit for notify message of PID "PID_FMT", ignoring.", ucred->pid);

        if (fdset_size(fds) > 0)
                log_warning("Got extra auxiliary fds with notification message, closing them.");

        return 0;
}

static void manager_invoke_sigchld_event(
                Manager *m,
                Unit *u,
                const siginfo_t *si) {

        assert(m);
        assert(u);
        assert(si);

        /* Already invoked the handler of this unit in this iteration? Then don't process this again */
        if (u->sigchldgen == m->sigchldgen)
                return;
        u->sigchldgen = m->sigchldgen;

        log_unit_debug(u, "Child "PID_FMT" belongs to %s.", si->si_pid, u->id);
        unit_unwatch_pid(u, si->si_pid);

        if (UNIT_VTABLE(u)->sigchld_event)
                UNIT_VTABLE(u)->sigchld_event(u, si->si_pid, si->si_code, si->si_status);
}

static int manager_dispatch_sigchld(sd_event_source *source, void *userdata) {
        Manager *m = userdata;
        siginfo_t si = {};
        int r;

        assert(source);
        assert(m);

        /* First we call waitid() for a PID and do not reap the zombie. That way we can still access /proc/$PID for it
         * while it is a zombie. */

        if (waitid(P_ALL, 0, &si, WEXITED|WNOHANG|WNOWAIT) < 0) {

                if (errno != ECHILD)
                        log_error_errno(errno, "Failed to peek for child with waitid(), ignoring: %m");

                goto turn_off;
        }

        if (si.si_pid <= 0)
                goto turn_off;

        if (IN_SET(si.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED)) {
                _cleanup_free_ Unit **array_copy = NULL;
                _cleanup_free_ char *name = NULL;
                Unit *u1, *u2, **array;

                (void) get_process_comm(si.si_pid, &name);

                log_debug("Child "PID_FMT" (%s) died (code=%s, status=%i/%s)",
                          si.si_pid, strna(name),
                          sigchld_code_to_string(si.si_code),
                          si.si_status,
                          strna(si.si_code == CLD_EXITED
                                ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)
                                : signal_to_string(si.si_status)));

                /* Increase the generation counter used for filtering out duplicate unit invocations */
                m->sigchldgen++;

                /* And now figure out the unit this belongs to, it might be multiple... */
                u1 = manager_get_unit_by_pid_cgroup(m, si.si_pid);
                u2 = hashmap_get(m->watch_pids, PID_TO_PTR(si.si_pid));
                array = hashmap_get(m->watch_pids, PID_TO_PTR(-si.si_pid));
                if (array) {
                        size_t n = 0;

                        /* Count how many entries the array has */
                        while (array[n])
                                n++;

                        /* Make a copy of the array so that we don't trip up on the array changing beneath us */
                        array_copy = newdup(Unit*, array, n+1);
                        if (!array_copy)
                                log_oom();
                }

                /* Finally, execute them all. Note that u1, u2 and the array might contain duplicates, but
                 * that's fine, manager_invoke_sigchld_event() will ensure we only invoke the handlers once for
                 * each iteration. */
                if (u1) {
                        /* We check for oom condition, in case we got SIGCHLD before the oom notification.
                         * We only do this for the cgroup the PID belonged to. */
                        (void) unit_check_oom(u1);

                        manager_invoke_sigchld_event(m, u1, &si);
                }
                if (u2)
                        manager_invoke_sigchld_event(m, u2, &si);
                if (array_copy)
                        for (size_t i = 0; array_copy[i]; i++)
                                manager_invoke_sigchld_event(m, array_copy[i], &si);
        }

        /* And now, we actually reap the zombie. */
        if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                log_error_errno(errno, "Failed to dequeue child, ignoring: %m");
                return 0;
        }

        return 0;

turn_off:
        /* All children processed for now, turn off event source */

        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to disable SIGCHLD event source: %m");

        return 0;
}

static void manager_start_target(Manager *m, const char *name, JobMode mode) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        log_debug("Activating special unit %s", name);

        r = manager_add_job_by_name(m, JOB_START, name, mode, NULL, &error, NULL);
        if (r < 0)
                log_error("Failed to enqueue %s job: %s", name, bus_error_message(&error, r));
}

static void manager_handle_ctrl_alt_del(Manager *m) {
        /* If the user presses C-A-D more than
         * 7 times within 2s, we reboot/shutdown immediately,
         * unless it was disabled in system.conf */

        if (ratelimit_below(&m->ctrl_alt_del_ratelimit) || m->cad_burst_action == EMERGENCY_ACTION_NONE)
                manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE_IRREVERSIBLY);
        else
                emergency_action(m, m->cad_burst_action, EMERGENCY_ACTION_WARN, NULL, -1,
                                "Ctrl-Alt-Del was pressed more than 7 times within 2s");
}

static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        ssize_t n;
        struct signalfd_siginfo sfsi;
        int r;

        assert(m);
        assert(m->signal_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected events from signal file descriptor.");
                return 0;
        }

        n = read(m->signal_fd, &sfsi, sizeof(sfsi));
        if (n != sizeof(sfsi)) {
                if (n >= 0) {
                        log_warning("Truncated read from signal fd (%zu bytes), ignoring!", n);
                        return 0;
                }

                if (IN_SET(errno, EINTR, EAGAIN))
                        return 0;

                /* We return an error here, which will kill this handler,
                 * to avoid a busy loop on read error. */
                return log_error_errno(errno, "Reading from signal fd failed: %m");
        }

        log_received_signal(sfsi.ssi_signo == SIGCHLD ||
                            (sfsi.ssi_signo == SIGTERM && MANAGER_IS_USER(m))
                            ? LOG_DEBUG : LOG_INFO,
                            &sfsi);

        switch (sfsi.ssi_signo) {

        case SIGCHLD:
                r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_ON);
                if (r < 0)
                        log_warning_errno(r, "Failed to enable SIGCHLD event source, ignoring: %m");

                break;

        case SIGTERM:
                if (MANAGER_IS_SYSTEM(m)) {
                        /* This is for compatibility with the original sysvinit */
                        if (verify_run_space_and_log("Refusing to reexecute") < 0)
                                break;

                        m->objective = MANAGER_REEXECUTE;
                        break;
                }

                _fallthrough_;
        case SIGINT:
                if (MANAGER_IS_SYSTEM(m))
                        manager_handle_ctrl_alt_del(m);
                else
                        manager_start_target(m, SPECIAL_EXIT_TARGET,
                                             JOB_REPLACE_IRREVERSIBLY);
                break;

        case SIGWINCH:
                /* This is a nop on non-init */
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_target(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                break;

        case SIGPWR:
                /* This is a nop on non-init */
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_target(m, SPECIAL_SIGPWR_TARGET, JOB_REPLACE);

                break;

        case SIGUSR1:
                if (manager_dbus_is_running(m, false)) {
                        log_info("Trying to reconnect to bus...");

                        (void) bus_init_api(m);

                        if (MANAGER_IS_SYSTEM(m))
                                (void) bus_init_system(m);
                } else {
                        log_info("Starting D-Bus service...");
                        manager_start_target(m, SPECIAL_DBUS_SERVICE, JOB_REPLACE);
                }

                break;

        case SIGUSR2: {
                _cleanup_free_ char *dump = NULL;

                r = manager_get_dump_string(m, &dump);
                if (r < 0) {
                        log_warning_errno(errno, "Failed to acquire manager dump: %m");
                        break;
                }

                log_dump(LOG_INFO, dump);
                break;
        }

        case SIGHUP:
                if (verify_run_space_and_log("Refusing to reload") < 0)
                        break;

                m->objective = MANAGER_RELOAD;
                break;

        default: {

                /* Starting SIGRTMIN+0 */
                static const struct {
                        const char *target;
                        JobMode mode;
                } target_table[] = {
                        [0] = { SPECIAL_DEFAULT_TARGET,   JOB_ISOLATE },
                        [1] = { SPECIAL_RESCUE_TARGET,    JOB_ISOLATE },
                        [2] = { SPECIAL_EMERGENCY_TARGET, JOB_ISOLATE },
                        [3] = { SPECIAL_HALT_TARGET,      JOB_REPLACE_IRREVERSIBLY },
                        [4] = { SPECIAL_POWEROFF_TARGET,  JOB_REPLACE_IRREVERSIBLY },
                        [5] = { SPECIAL_REBOOT_TARGET,    JOB_REPLACE_IRREVERSIBLY },
                        [6] = { SPECIAL_KEXEC_TARGET,     JOB_REPLACE_IRREVERSIBLY },
                };

                /* Starting SIGRTMIN+13, so that target halt and system halt are 10 apart */
                static const ManagerObjective objective_table[] = {
                        [0] = MANAGER_HALT,
                        [1] = MANAGER_POWEROFF,
                        [2] = MANAGER_REBOOT,
                        [3] = MANAGER_KEXEC,
                };

                if ((int) sfsi.ssi_signo >= SIGRTMIN+0 &&
                    (int) sfsi.ssi_signo < SIGRTMIN+(int) ELEMENTSOF(target_table)) {
                        int idx = (int) sfsi.ssi_signo - SIGRTMIN;
                        manager_start_target(m, target_table[idx].target,
                                             target_table[idx].mode);
                        break;
                }

                if ((int) sfsi.ssi_signo >= SIGRTMIN+13 &&
                    (int) sfsi.ssi_signo < SIGRTMIN+13+(int) ELEMENTSOF(objective_table)) {
                        m->objective = objective_table[sfsi.ssi_signo - SIGRTMIN - 13];
                        break;
                }

                switch (sfsi.ssi_signo - SIGRTMIN) {

                case 20:
                        manager_set_show_status(m, SHOW_STATUS_YES);
                        break;

                case 21:
                        manager_set_show_status(m, SHOW_STATUS_NO);
                        break;

                case 22:
                        manager_override_log_level(m, LOG_DEBUG);
                        break;

                case 23:
                        manager_restore_original_log_level(m);
                        break;

                case 24:
                        if (MANAGER_IS_USER(m)) {
                                m->objective = MANAGER_EXIT;
                                return 0;
                        }

                        /* This is a nop on init */
                        break;

                case 26:
                case 29: /* compatibility: used to be mapped to LOG_TARGET_SYSLOG_OR_KMSG */
                        manager_restore_original_log_target(m);
                        break;

                case 27:
                        manager_override_log_target(m, LOG_TARGET_CONSOLE);
                        break;

                case 28:
                        manager_override_log_target(m, LOG_TARGET_KMSG);
                        break;

                default:
                        log_warning("Got unhandled signal <%s>.", signal_to_string(sfsi.ssi_signo));
                }
        }}

        return 0;
}

static int manager_dispatch_time_change_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Iterator i;
        Unit *u;

        assert(m);
        assert(m->time_change_fd == fd);

        log_struct(LOG_DEBUG,
                   "MESSAGE_ID=" SD_MESSAGE_TIME_CHANGE_STR,
                   LOG_MESSAGE("Time has been changed"));

        /* Restart the watch */
        (void) manager_setup_time_change(m);

        HASHMAP_FOREACH(u, m->units, i)
                if (UNIT_VTABLE(u)->time_change)
                        UNIT_VTABLE(u)->time_change(u);

        return 0;
}

static int manager_dispatch_timezone_change(
                sd_event_source *source,
                const struct inotify_event *e,
                void *userdata) {

        Manager *m = userdata;
        int changed;
        Iterator i;
        Unit *u;

        assert(m);

        log_debug("inotify event for /etc/localtime");

        changed = manager_read_timezone_stat(m);
        if (changed <= 0)
                return changed;

        /* Something changed, restart the watch, to ensure we watch the new /etc/localtime if it changed */
        (void) manager_setup_timezone_change(m);

        /* Read the new timezone */
        tzset();

        log_debug("Timezone has been changed (now: %s).", tzname[daylight]);

        HASHMAP_FOREACH(u, m->units, i)
                if (UNIT_VTABLE(u)->timezone_change)
                        UNIT_VTABLE(u)->timezone_change(u);

        return 0;
}

static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;

        assert(m);
        assert(m->idle_pipe[2] == fd);

        /* There's at least one Type=idle child that just gave up on us waiting for the boot process to complete. Let's
         * now turn off any further console output if there's at least one service that needs console access, so that
         * from now on our own output should not spill into that service's output anymore. After all, we support
         * Type=idle only to beautify console output and it generally is set on services that want to own the console
         * exclusively without our interference. */
        m->no_console_output = m->n_on_console > 0;

        /* Acknowledge the child's request, and let all all other children know too that they shouldn't wait any longer
         * by closing the pipes towards them, which is what they are waiting for. */
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
        assert(m->objective == MANAGER_OK); /* Ensure manager_startup() has been called */

        manager_check_finished(m);

        /* There might still be some zombies hanging around from before we were exec()'ed. Let's reap them. */
        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SIGCHLD event source: %m");

        while (m->objective == MANAGER_OK) {
                usec_t wait_usec;

                if (timestamp_is_set(m->runtime_watchdog) && MANAGER_IS_SYSTEM(m))
                        watchdog_ping();

                if (!ratelimit_below(&rl)) {
                        /* Yay, something is going seriously wrong, pause a little */
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
                }

                if (manager_dispatch_load_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_job_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_unit_queue(m) > 0)
                        continue;

                if (manager_dispatch_cleanup_queue(m) > 0)
                        continue;

                if (manager_dispatch_cgroup_realize_queue(m) > 0)
                        continue;

                if (manager_dispatch_stop_when_unneeded_queue(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

                /* Sleep for half the watchdog time */
                if (timestamp_is_set(m->runtime_watchdog) && MANAGER_IS_SYSTEM(m)) {
                        wait_usec = m->runtime_watchdog / 2;
                        if (wait_usec <= 0)
                                wait_usec = 1;
                } else
                        wait_usec = USEC_INFINITY;

                r = sd_event_run(m->event, wait_usec);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
        }

        return m->objective;
}

int manager_load_unit_from_dbus_path(Manager *m, const char *s, sd_bus_error *e, Unit **_u) {
        _cleanup_free_ char *n = NULL;
        sd_id128_t invocation_id;
        Unit *u;
        int r;

        assert(m);
        assert(s);
        assert(_u);

        r = unit_name_from_dbus_path(s, &n);
        if (r < 0)
                return r;

        /* Permit addressing units by invocation ID: if the passed bus path is suffixed by a 128bit ID then we use it
         * as invocation ID. */
        r = sd_id128_from_string(n, &invocation_id);
        if (r >= 0) {
                u = hashmap_get(m->units_by_invocation_id, &invocation_id);
                if (u) {
                        *_u = u;
                        return 0;
                }

                return sd_bus_error_setf(e, BUS_ERROR_NO_UNIT_FOR_INVOCATION_ID,
                                         "No unit with the specified invocation ID " SD_ID128_FORMAT_STR " known.",
                                         SD_ID128_FORMAT_VAL(invocation_id));
        }

        /* If this didn't work, we check if this is a unit name */
        if (!unit_name_is_valid(n, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                _cleanup_free_ char *nn = NULL;

                nn = cescape(n);
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unit name %s is neither a valid invocation ID nor unit name.", strnull(nn));
        }

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

#if HAVE_AUDIT
        _cleanup_free_ char *p = NULL;
        const char *msg;
        int audit_fd, r;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        audit_fd = get_audit_fd();
        if (audit_fd < 0)
                return;

        /* Don't generate audit events if the service was already
         * started and we're just deserializing */
        if (MANAGER_IS_RELOADING(m))
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
        static const union sockaddr_union sa = PLYMOUTH_SOCKET;
        _cleanup_free_ char *message = NULL;
        _cleanup_close_ int fd = -1;
        int n = 0;

        /* Don't generate plymouth events if the service was already
         * started and we're just deserializing */
        if (MANAGER_IS_RELOADING(m))
                return;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (detect_container() > 0)
                return;

        if (!IN_SET(u->type, UNIT_SERVICE, UNIT_MOUNT, UNIT_SWAP))
                return;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message then wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error_errno(errno, "socket() failed: %m");
                return;
        }

        if (connect(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0) {
                if (!IN_SET(errno, EAGAIN, ENOENT) && !ERRNO_IS_DISCONNECT(errno))
                        log_error_errno(errno, "connect() failed: %m");
                return;
        }

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->id) + 1), u->id, &n) < 0) {
                log_oom();
                return;
        }

        errno = 0;
        if (write(fd, message, n + 1) != n + 1)
                if (!IN_SET(errno, EAGAIN, ENOENT) && !ERRNO_IS_DISCONNECT(errno))
                        log_error_errno(errno, "Failed to write Plymouth message: %m");
}

int manager_open_serialization(Manager *m, FILE **_f) {
        int fd;
        FILE *f;

        assert(_f);

        fd = open_serialization_fd("systemd-state");
        if (fd < 0)
                return fd;

        f = fdopen(fd, "w+");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        *_f = f;
        return 0;
}

static bool manager_timestamp_shall_serialize(ManagerTimestamp t) {

        if (!in_initrd())
                return true;

        /* The following timestamps only apply to the host system, hence only serialize them there */
        return !IN_SET(t,
                       MANAGER_TIMESTAMP_USERSPACE, MANAGER_TIMESTAMP_FINISH,
                       MANAGER_TIMESTAMP_SECURITY_START, MANAGER_TIMESTAMP_SECURITY_FINISH,
                       MANAGER_TIMESTAMP_GENERATORS_START, MANAGER_TIMESTAMP_GENERATORS_FINISH,
                       MANAGER_TIMESTAMP_UNITS_LOAD_START, MANAGER_TIMESTAMP_UNITS_LOAD_FINISH);
}

int manager_serialize(
                Manager *m,
                FILE *f,
                FDSet *fds,
                bool switching_root) {

        ManagerTimestamp q;
        const char *t;
        Iterator i;
        Unit *u;
        int r;

        assert(m);
        assert(f);
        assert(fds);

        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        (void) serialize_item_format(f, "current-job-id", "%" PRIu32, m->current_job_id);
        (void) serialize_item_format(f, "n-installed-jobs", "%u", m->n_installed_jobs);
        (void) serialize_item_format(f, "n-failed-jobs", "%u", m->n_failed_jobs);
        (void) serialize_bool(f, "taint-usr", m->taint_usr);
        (void) serialize_bool(f, "ready-sent", m->ready_sent);
        (void) serialize_bool(f, "taint-logged", m->taint_logged);
        (void) serialize_bool(f, "service-watchdogs", m->service_watchdogs);

        /* After switching root, udevd has not been started yet. So, enumeration results should not be emitted. */
        (void) serialize_bool(f, "honor-device-enumeration", !switching_root);

        t = show_status_to_string(m->show_status);
        if (t)
                (void) serialize_item(f, "show-status", t);

        if (m->log_level_overridden)
                (void) serialize_item_format(f, "log-level-override", "%i", log_get_max_level());
        if (m->log_target_overridden)
                (void) serialize_item(f, "log-target-override", log_target_to_string(log_get_target()));

        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                _cleanup_free_ char *joined = NULL;

                if (!manager_timestamp_shall_serialize(q))
                        continue;

                joined = strjoin(manager_timestamp_to_string(q), "-timestamp");
                if (!joined)
                        return log_oom();

                (void) serialize_dual_timestamp(f, joined, m->timestamps + q);
        }

        if (!switching_root)
                (void) serialize_strv(f, "env", m->client_environment);

        if (m->notify_fd >= 0) {
                r = serialize_fd(f, fds, "notify-fd", m->notify_fd);
                if (r < 0)
                        return r;

                (void) serialize_item(f, "notify-socket", m->notify_socket);
        }

        if (m->cgroups_agent_fd >= 0) {
                r = serialize_fd(f, fds, "cgroups-agent-fd", m->cgroups_agent_fd);
                if (r < 0)
                        return r;
        }

        if (m->user_lookup_fds[0] >= 0) {
                int copy0, copy1;

                copy0 = fdset_put_dup(fds, m->user_lookup_fds[0]);
                if (copy0 < 0)
                        return log_error_errno(copy0, "Failed to add user lookup fd to serialization: %m");

                copy1 = fdset_put_dup(fds, m->user_lookup_fds[1]);
                if (copy1 < 0)
                        return log_error_errno(copy1, "Failed to add user lookup fd to serialization: %m");

                (void) serialize_item_format(f, "user-lookup", "%i %i", copy0, copy1);
        }

        bus_track_serialize(m->subscribed, f, "subscribed");

        r = dynamic_user_serialize(m, f, fds);
        if (r < 0)
                return r;

        manager_serialize_uid_refs(m, f);
        manager_serialize_gid_refs(m, f);

        r = exec_runtime_serialize(m, f, fds);
        if (r < 0)
                return r;

        (void) fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->id != t)
                        continue;

                /* Start marker */
                fputs(u->id, f);
                fputc('\n', f);

                r = unit_serialize(u, f, fds, !switching_root);
                if (r < 0)
                        return r;
        }

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to flush serialization: %m");

        r = bus_fdset_add_all(m, fds);
        if (r < 0)
                return log_error_errno(r, "Failed to add bus sockets to serialization: %m");

        return 0;
}

static int manager_deserialize_one_unit(Manager *m, const char *name, FILE *f, FDSet *fds) {
        Unit *u;
        int r;

        r = manager_load_unit(m, name, NULL, NULL, &u);
        if (r < 0) {
                if (r == -ENOMEM)
                        return r;
                return log_notice_errno(r, "Failed to load unit \"%s\", skipping deserialization: %m", name);
        }

        r = unit_deserialize(u, f, fds);
        if (r < 0) {
                if (r == -ENOMEM)
                        return r;
                return log_notice_errno(r, "Failed to deserialize unit \"%s\", skipping: %m", name);
        }

        return 0;
}

static int manager_deserialize_units(Manager *m, FILE *f, FDSet *fds) {
        const char *unit_name;
        int r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                /* Start marker */
                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                unit_name = strstrip(line);

                r = manager_deserialize_one_unit(m, unit_name, f, fds);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        r = unit_deserialize_skip(f);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r = 0;

        assert(m);
        assert(f);

        log_debug("Deserializing state...");

        /* If we are not in reload mode yet, enter it now. Not that this is recursive, a caller might already have
         * increased it to non-zero, which is why we just increase it by one here and down again at the end of this
         * call. */
        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "current-job-id="))) {
                        uint32_t id;

                        if (safe_atou32(val, &id) < 0)
                                log_notice("Failed to parse current job id value '%s', ignoring.", val);
                        else
                                m->current_job_id = MAX(m->current_job_id, id);

                } else if ((val = startswith(l, "n-installed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse installed jobs counter '%s', ignoring.", val);
                        else
                                m->n_installed_jobs += n;

                } else if ((val = startswith(l, "n-failed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse failed jobs counter '%s', ignoring.", val);
                        else
                                m->n_failed_jobs += n;

                } else if ((val = startswith(l, "taint-usr="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse taint /usr flag '%s', ignoring.", val);
                        else
                                m->taint_usr = m->taint_usr || b;

                } else if ((val = startswith(l, "ready-sent="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse ready-sent flag '%s', ignoring.", val);
                        else
                                m->ready_sent = m->ready_sent || b;

                } else if ((val = startswith(l, "taint-logged="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse taint-logged flag '%s', ignoring.", val);
                        else
                                m->taint_logged = m->taint_logged || b;

                } else if ((val = startswith(l, "service-watchdogs="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse service-watchdogs flag '%s', ignoring.", val);
                        else
                                m->service_watchdogs = b;

                } else if ((val = startswith(l, "honor-device-enumeration="))) {
                        int b;

                        b = parse_boolean(val);
                        if (b < 0)
                                log_notice("Failed to parse honor-device-enumeration flag '%s', ignoring.", val);
                        else
                                m->honor_device_enumeration = b;

                } else if ((val = startswith(l, "show-status="))) {
                        ShowStatus s;

                        s = show_status_from_string(val);
                        if (s < 0)
                                log_notice("Failed to parse show-status flag '%s', ignoring.", val);
                        else
                                manager_set_show_status(m, s);

                } else if ((val = startswith(l, "log-level-override="))) {
                        int level;

                        level = log_level_from_string(val);
                        if (level < 0)
                                log_notice("Failed to parse log-level-override value '%s', ignoring.", val);
                        else
                                manager_override_log_level(m, level);

                } else if ((val = startswith(l, "log-target-override="))) {
                        LogTarget target;

                        target = log_target_from_string(val);
                        if (target < 0)
                                log_notice("Failed to parse log-target-override value '%s', ignoring.", val);
                        else
                                manager_override_log_target(m, target);

                } else if (startswith(l, "env=")) {
                        r = deserialize_environment(l + 4, &m->client_environment);
                        if (r < 0)
                                log_notice_errno(r, "Failed to parse environment entry: \"%s\", ignoring: %m", l);

                } else if ((val = startswith(l, "notify-fd="))) {
                        int fd;

                        if (safe_atoi(val, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_notice("Failed to parse notify fd, ignoring: \"%s\"", val);
                        else {
                                m->notify_event_source = sd_event_source_unref(m->notify_event_source);
                                safe_close(m->notify_fd);
                                m->notify_fd = fdset_remove(fds, fd);
                        }

                } else if ((val = startswith(l, "notify-socket="))) {
                        r = free_and_strdup(&m->notify_socket, val);
                        if (r < 0)
                                return r;

                } else if ((val = startswith(l, "cgroups-agent-fd="))) {
                        int fd;

                        if (safe_atoi(val, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd))
                                log_notice("Failed to parse cgroups agent fd, ignoring.: %s", val);
                        else {
                                m->cgroups_agent_event_source = sd_event_source_unref(m->cgroups_agent_event_source);
                                safe_close(m->cgroups_agent_fd);
                                m->cgroups_agent_fd = fdset_remove(fds, fd);
                        }

                } else if ((val = startswith(l, "user-lookup="))) {
                        int fd0, fd1;

                        if (sscanf(val, "%i %i", &fd0, &fd1) != 2 || fd0 < 0 || fd1 < 0 || fd0 == fd1 || !fdset_contains(fds, fd0) || !fdset_contains(fds, fd1))
                                log_notice("Failed to parse user lookup fd, ignoring: %s", val);
                        else {
                                m->user_lookup_event_source = sd_event_source_unref(m->user_lookup_event_source);
                                safe_close_pair(m->user_lookup_fds);
                                m->user_lookup_fds[0] = fdset_remove(fds, fd0);
                                m->user_lookup_fds[1] = fdset_remove(fds, fd1);
                        }

                } else if ((val = startswith(l, "dynamic-user=")))
                        dynamic_user_deserialize_one(m, val, fds);
                else if ((val = startswith(l, "destroy-ipc-uid=")))
                        manager_deserialize_uid_refs_one(m, val);
                else if ((val = startswith(l, "destroy-ipc-gid=")))
                        manager_deserialize_gid_refs_one(m, val);
                else if ((val = startswith(l, "exec-runtime=")))
                        exec_runtime_deserialize_one(m, val, fds);
                else if ((val = startswith(l, "subscribed="))) {

                        if (strv_extend(&m->deserialized_subscribed, val) < 0)
                                return -ENOMEM;

                } else {
                        ManagerTimestamp q;

                        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                                val = startswith(l, manager_timestamp_to_string(q));
                                if (!val)
                                        continue;

                                val = startswith(val, "-timestamp=");
                                if (val)
                                        break;
                        }

                        if (q < _MANAGER_TIMESTAMP_MAX) /* found it */
                                (void) deserialize_dual_timestamp(val, m->timestamps + q);
                        else if (!startswith(l, "kdbus-fd=")) /* ignore kdbus */
                                log_notice("Unknown serialization item '%s', ignoring.", l);
                }
        }

        return manager_deserialize_units(m, f, fds);
}

int manager_reload(Manager *m) {
        _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create serialization file: %m");

        fds = fdset_new();
        if (!fds)
                return log_oom();

        /* We are officially in reload mode from here on. */
        reloading = manager_reloading_start(m);

        r = manager_serialize(m, f, fds, false);
        if (r < 0)
                return r;

        if (fseeko(f, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to beginning of serialization: %m");

        /* 💀 This is the point of no return, from here on there is no way back. 💀 */
        reloading = NULL;

        bus_manager_send_reloading(m, true);

        /* Start by flushing out all jobs and units, all generated units, all runtime environments, all dynamic users
         * and everything else that is worth flushing out. We'll get it all back from the serialization — if we need
         * it.*/

        manager_clear_jobs_and_units(m);
        lookup_paths_flush_generator(&m->lookup_paths);
        lookup_paths_free(&m->lookup_paths);
        exec_runtime_vacuum(m);
        dynamic_user_vacuum(m, false);
        m->uid_refs = hashmap_free(m->uid_refs);
        m->gid_refs = hashmap_free(m->gid_refs);

        r = lookup_paths_init(&m->lookup_paths, m->unit_file_scope, 0, NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to initialize path lookup table, ignoring: %m");

        (void) manager_run_environment_generators(m);
        (void) manager_run_generators(m);

        lookup_paths_log(&m->lookup_paths);

        /* We flushed out generated files, for which we don't watch mtime, so we should flush the old map. */
        manager_free_unit_name_maps(m);

        /* First, enumerate what we can from kernel and suchlike */
        manager_enumerate_perpetual(m);
        manager_enumerate(m);

        /* Second, deserialize our stored data */
        r = manager_deserialize(m, f, fds);
        if (r < 0)
                log_warning_errno(r, "Deserialization failed, proceeding anyway: %m");

        /* We don't need the serialization anymore */
        f = safe_fclose(f);

        /* Re-register notify_fd as event source, and set up other sockets/communication channels we might need */
        (void) manager_setup_notify(m);
        (void) manager_setup_cgroups_agent(m);
        (void) manager_setup_user_lookup_fd(m);

        /* Third, fire things up! */
        manager_coldplug(m);

        /* Clean up runtime objects no longer referenced */
        manager_vacuum(m);

        /* Consider the reload process complete now. */
        assert(m->n_reloading > 0);
        m->n_reloading--;

        /* On manager reloading, device tag data should exists, thus, we should honor the results of device
         * enumeration. The flag should be always set correctly by the serialized data, but it may fail. So,
         * let's always set the flag here for safety. */
        m->honor_device_enumeration = true;

        manager_ready(m);

        m->send_reloading_done = true;
        return 0;
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

static void log_taint_string(Manager *m) {
        _cleanup_free_ char *taint = NULL;

        assert(m);

        if (MANAGER_IS_USER(m) || m->taint_logged)
                return;

        m->taint_logged = true; /* only check for taint once */

        taint = manager_taint_string(m);
        if (isempty(taint))
                return;

        log_struct(LOG_NOTICE,
                   LOG_MESSAGE("System is tainted: %s", taint),
                   "TAINT=%s", taint,
                   "MESSAGE_ID=" SD_MESSAGE_TAINTED_STR);
}

static void manager_notify_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        if (MANAGER_IS_TEST_RUN(m))
                return;

        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0) {
                char ts[FORMAT_TIMESPAN_MAX];
                char buf[FORMAT_TIMESPAN_MAX + STRLEN(" (firmware) + ") + FORMAT_TIMESPAN_MAX + STRLEN(" (loader) + ")]
                        = {};
                char *p = buf;
                size_t size = sizeof buf;

                /* Note that MANAGER_TIMESTAMP_KERNEL's monotonic value is always at 0, and
                 * MANAGER_TIMESTAMP_FIRMWARE's and MANAGER_TIMESTAMP_LOADER's monotonic value should be considered
                 * negative values. */

                firmware_usec = m->timestamps[MANAGER_TIMESTAMP_FIRMWARE].monotonic - m->timestamps[MANAGER_TIMESTAMP_LOADER].monotonic;
                loader_usec = m->timestamps[MANAGER_TIMESTAMP_LOADER].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                userspace_usec = m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic - m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;
                total_usec = m->timestamps[MANAGER_TIMESTAMP_FIRMWARE].monotonic + m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic;

                if (firmware_usec > 0)
                        size = strpcpyf(&p, size, "%s (firmware) + ", format_timespan(ts, sizeof(ts), firmware_usec, USEC_PER_MSEC));
                if (loader_usec > 0)
                        size = strpcpyf(&p, size, "%s (loader) + ", format_timespan(ts, sizeof(ts), loader_usec, USEC_PER_MSEC));

                if (dual_timestamp_is_set(&m->timestamps[MANAGER_TIMESTAMP_INITRD])) {

                        /* The initrd case on bare-metal*/
                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic;

                        log_struct(LOG_INFO,
                                   "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR,
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "INITRD_USEC="USEC_FMT, initrd_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                               buf,
                                               format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                               format_timespan(initrd, sizeof(initrd), initrd_usec, USEC_PER_MSEC),
                                               format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                               format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));
                } else {
                        /* The initrd-less case on bare-metal*/

                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = 0;

                        log_struct(LOG_INFO,
                                   "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR,
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (userspace) = %s.",
                                               buf,
                                               format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                               format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                               format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));
                }
        } else {
                /* The container and --user case */
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic - m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;

                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_USER_STARTUP_FINISHED_STR,
                           "USERSPACE_USEC="USEC_FMT, userspace_usec,
                           LOG_MESSAGE("Startup finished in %s.",
                                       format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC)));
        }

        bus_manager_send_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false,
                   m->ready_sent ? "STATUS=Startup finished in %s."
                                 : "READY=1\n"
                                   "STATUS=Startup finished in %s.",
                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC));
        m->ready_sent = true;

        log_taint_string(m);
}

static void manager_send_ready(Manager *m) {
        assert(m);

        /* We send READY=1 on reaching basic.target only when running in --user mode. */
        if (!MANAGER_IS_USER(m) || m->ready_sent)
                return;

        m->ready_sent = true;

        sd_notifyf(false,
                   "READY=1\n"
                   "STATUS=Reached " SPECIAL_BASIC_TARGET ".");
}

static void manager_check_basic_target(Manager *m) {
        Unit *u;

        assert(m);

        /* Small shortcut */
        if (m->ready_sent && m->taint_logged)
                return;

        u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
        if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                return;

        /* For user managers, send out READY=1 as soon as we reach basic.target */
        manager_send_ready(m);

        /* Log the taint string as soon as we reach basic.target */
        log_taint_string(m);
}

void manager_check_finished(Manager *m) {
        assert(m);

        if (MANAGER_IS_RELOADING(m))
                return;

        /* Verify that we have entered the event loop already, and not left it again. */
        if (!MANAGER_IS_RUNNING(m))
                return;

        manager_check_basic_target(m);

        if (hashmap_size(m->jobs) > 0) {
                if (m->jobs_in_progress_event_source)
                        /* Ignore any failure, this is only for feedback */
                        (void) sd_event_source_set_time(m->jobs_in_progress_event_source, now(CLOCK_MONOTONIC) + JOBS_IN_PROGRESS_WAIT_USEC);

                return;
        }

        manager_flip_auto_status(m, false);

        /* Notify Type=idle units that we are done now */
        manager_close_idle_pipe(m);

        /* Turn off confirm spawn now */
        m->confirm_spawn = NULL;

        /* No need to update ask password status when we're going non-interactive */
        manager_close_ask_password(m);

        /* This is no longer the first boot */
        manager_set_first_boot(m, false);

        if (MANAGER_IS_FINISHED(m))
                return;

        dual_timestamp_get(m->timestamps + MANAGER_TIMESTAMP_FINISH);

        manager_notify_finished(m);

        manager_invalidate_startup_units(m);
}

static bool generator_path_any(const char* const* paths) {
        char **path;
        bool found = false;

        /* Optimize by skipping the whole process by not creating output directories
         * if no generators are found. */
        STRV_FOREACH(path, (char**) paths)
                if (access(*path, F_OK) == 0)
                        found = true;
                else if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open generator directory %s: %m", *path);

        return found;
}

static const char *const system_env_generator_binary_paths[] = {
        "/run/systemd/system-environment-generators",
        "/etc/systemd/system-environment-generators",
        "/usr/local/lib/systemd/system-environment-generators",
        SYSTEM_ENV_GENERATOR_PATH,
        NULL
};

static const char *const user_env_generator_binary_paths[] = {
        "/run/systemd/user-environment-generators",
        "/etc/systemd/user-environment-generators",
        "/usr/local/lib/systemd/user-environment-generators",
        USER_ENV_GENERATOR_PATH,
        NULL
};

static int manager_run_environment_generators(Manager *m) {
        char **tmp = NULL; /* this is only used in the forked process, no cleanup here */
        const char *const *paths;
        void* args[] = {
                [STDOUT_GENERATE] = &tmp,
                [STDOUT_COLLECT] = &tmp,
                [STDOUT_CONSUME] = &m->transient_environment,
        };
        int r;

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_ENV_GENERATORS))
                return 0;

        paths = MANAGER_IS_SYSTEM(m) ? system_env_generator_binary_paths : user_env_generator_binary_paths;

        if (!generator_path_any(paths))
                return 0;

        RUN_WITH_UMASK(0022)
                r = execute_directories(paths, DEFAULT_TIMEOUT_USEC, gather_environment,
                                        args, NULL, m->transient_environment, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        return r;
}

static int manager_run_generators(Manager *m) {
        _cleanup_strv_free_ char **paths = NULL;
        const char *argv[5];
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_GENERATORS))
                return 0;

        paths = generator_binary_paths(m->unit_file_scope);
        if (!paths)
                return log_oom();

        if (!generator_path_any((const char* const*) paths))
                return 0;

        r = lookup_paths_mkdir_generator(&m->lookup_paths);
        if (r < 0) {
                log_error_errno(r, "Failed to create generator directories: %m");
                goto finish;
        }

        argv[0] = NULL; /* Leave this empty, execute_directory() will fill something in */
        argv[1] = m->lookup_paths.generator;
        argv[2] = m->lookup_paths.generator_early;
        argv[3] = m->lookup_paths.generator_late;
        argv[4] = NULL;

        RUN_WITH_UMASK(0022)
                (void) execute_directories((const char* const*) paths, DEFAULT_TIMEOUT_USEC, NULL, NULL,
                                           (char**) argv, m->transient_environment, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);

        r = 0;

finish:
        lookup_paths_trim_generator(&m->lookup_paths);
        return r;
}

int manager_transient_environment_add(Manager *m, char **plus) {
        char **a;

        assert(m);

        if (strv_isempty(plus))
                return 0;

        a = strv_env_merge(2, m->transient_environment, plus);
        if (!a)
                return log_oom();

        sanitize_environment(a);

        return strv_free_and_replace(m->transient_environment, a);
}

int manager_client_environment_modify(
                Manager *m,
                char **minus,
                char **plus) {

        char **a = NULL, **b = NULL, **l;

        assert(m);

        if (strv_isempty(minus) && strv_isempty(plus))
                return 0;

        l = m->client_environment;

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

        if (m->client_environment != l)
                strv_free(m->client_environment);

        if (a != l)
                strv_free(a);
        if (b != l)
                strv_free(b);

        m->client_environment = sanitize_environment(l);
        return 0;
}

int manager_get_effective_environment(Manager *m, char ***ret) {
        char **l;

        assert(m);
        assert(ret);

        l = strv_env_merge(2, m->transient_environment, m->client_environment);
        if (!l)
                return -ENOMEM;

        *ret = l;
        return 0;
}

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit) {
        int i;

        assert(m);

        for (i = 0; i < _RLIMIT_MAX; i++) {
                m->rlimit[i] = mfree(m->rlimit[i]);

                if (!default_rlimit[i])
                        continue;

                m->rlimit[i] = newdup(struct rlimit, default_rlimit[i], 1);
                if (!m->rlimit[i])
                        return log_oom();
        }

        return 0;
}

void manager_recheck_dbus(Manager *m) {
        assert(m);

        /* Connects to the bus if the dbus service and socket are running. If we are running in user mode this is all
         * it does. In system mode we'll also connect to the system bus (which will most likely just reuse the
         * connection of the API bus). That's because the system bus after all runs as service of the system instance,
         * while in the user instance we can assume it's already there. */

        if (MANAGER_IS_RELOADING(m))
                return; /* don't check while we are reloading… */

        if (manager_dbus_is_running(m, false)) {
                (void) bus_init_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_init_system(m);
        } else {
                (void) bus_done_api(m);

                if (MANAGER_IS_SYSTEM(m))
                        (void) bus_done_system(m);
        }
}

static bool manager_journal_is_running(Manager *m) {
        Unit *u;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return false;

        /* If we are the user manager we can safely assume that the journal is up */
        if (!MANAGER_IS_SYSTEM(m))
                return true;

        /* Check that the socket is not only up, but in RUNNING state */
        u = manager_get_unit(m, SPECIAL_JOURNALD_SOCKET);
        if (!u)
                return false;
        if (SOCKET(u)->state != SOCKET_RUNNING)
                return false;

        /* Similar, check if the daemon itself is fully up, too */
        u = manager_get_unit(m, SPECIAL_JOURNALD_SERVICE);
        if (!u)
                return false;
        if (!IN_SET(SERVICE(u)->state, SERVICE_RELOAD, SERVICE_RUNNING))
                return false;

        return true;
}

void manager_recheck_journal(Manager *m) {

        assert(m);

        /* Don't bother with this unless we are in the special situation of being PID 1 */
        if (getpid_cached() != 1)
                return;

        /* Don't check this while we are reloading, things might still change */
        if (MANAGER_IS_RELOADING(m))
                return;

        /* The journal is fully and entirely up? If so, let's permit logging to it, if that's configured. If the
         * journal is down, don't ever log to it, otherwise we might end up deadlocking ourselves as we might trigger
         * an activation ourselves we can't fulfill. */
        log_set_prohibit_ipc(!manager_journal_is_running(m));
        log_open();
}

void manager_set_show_status(Manager *m, ShowStatus mode) {
        assert(m);
        assert(IN_SET(mode, SHOW_STATUS_AUTO, SHOW_STATUS_NO, SHOW_STATUS_YES, SHOW_STATUS_TEMPORARY));

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (m->show_status != mode)
                log_debug("%s showing of status.",
                          mode == SHOW_STATUS_NO ? "Disabling" : "Enabling");
        m->show_status = mode;

        if (IN_SET(mode, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES))
                (void) touch("/run/systemd/show-status");
        else
                (void) unlink("/run/systemd/show-status");
}

static bool manager_get_show_status(Manager *m, StatusType type) {
        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return false;

        if (m->no_console_output)
                return false;

        if (!IN_SET(manager_state(m), MANAGER_INITIALIZING, MANAGER_STARTING, MANAGER_STOPPING))
                return false;

        /* If we cannot find out the status properly, just proceed. */
        if (type != STATUS_TYPE_EMERGENCY && manager_check_ask_password(m) > 0)
                return false;

        return IN_SET(m->show_status, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES);
}

const char *manager_get_confirm_spawn(Manager *m) {
        static int last_errno = 0;
        struct stat st;
        int r;

        assert(m);

        /* Here's the deal: we want to test the validity of the console but don't want
         * PID1 to go through the whole console process which might block. But we also
         * want to warn the user only once if something is wrong with the console so we
         * cannot do the sanity checks after spawning our children. So here we simply do
         * really basic tests to hopefully trap common errors.
         *
         * If the console suddenly disappear at the time our children will really it
         * then they will simply fail to acquire it and a positive answer will be
         * assumed. New children will fallback to /dev/console though.
         *
         * Note: TTYs are devices that can come and go any time, and frequently aren't
         * available yet during early boot (consider a USB rs232 dongle...). If for any
         * reason the configured console is not ready, we fallback to the default
         * console. */

        if (!m->confirm_spawn || path_equal(m->confirm_spawn, "/dev/console"))
                return m->confirm_spawn;

        if (stat(m->confirm_spawn, &st) < 0) {
                r = -errno;
                goto fail;
        }

        if (!S_ISCHR(st.st_mode)) {
                r = -ENOTTY;
                goto fail;
        }

        last_errno = 0;
        return m->confirm_spawn;

fail:
        if (last_errno != r)
                last_errno = log_warning_errno(r, "Failed to open %s, using default console: %m", m->confirm_spawn);

        return "/dev/console";
}

void manager_set_first_boot(Manager *m, bool b) {
        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (m->first_boot != (int) b) {
                if (b)
                        (void) touch("/run/systemd/first-boot");
                else
                        (void) unlink("/run/systemd/first-boot");
        }

        m->first_boot = b;
}

void manager_disable_confirm_spawn(void) {
        (void) touch("/run/systemd/confirm_spawn_disabled");
}

bool manager_is_confirm_spawn_disabled(Manager *m) {
        if (!m->confirm_spawn)
                return true;

        return access("/run/systemd/confirm_spawn_disabled", F_OK) >= 0;
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
        status_vprintf(status, SHOW_STATUS_ELLIPSIZE|(type == STATUS_TYPE_EPHEMERAL ? SHOW_STATUS_EPHEMERAL : 0), format, ap);
        va_end(ap);
}

Set *manager_get_units_requiring_mounts_for(Manager *m, const char *path) {
        char p[strlen(path)+1];

        assert(m);
        assert(path);

        strcpy(p, path);
        path_simplify(p, false);

        return hashmap_get(m->units_requiring_mounts_for, streq(p, "/") ? "" : p);
}

int manager_update_failed_units(Manager *m, Unit *u, bool failed) {
        unsigned size;
        int r;

        assert(m);
        assert(u->manager == m);

        size = set_size(m->failed_units);

        if (failed) {
                r = set_ensure_allocated(&m->failed_units, NULL);
                if (r < 0)
                        return log_oom();

                if (set_put(m->failed_units, u) < 0)
                        return log_oom();
        } else
                (void) set_remove(m->failed_units, u);

        if (set_size(m->failed_units) != size)
                bus_manager_send_change_signal(m);

        return 0;
}

ManagerState manager_state(Manager *m) {
        Unit *u;

        assert(m);

        /* Did we ever finish booting? If not then we are still starting up */
        if (!MANAGER_IS_FINISHED(m)) {

                u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
                if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                        return MANAGER_INITIALIZING;

                return MANAGER_STARTING;
        }

        /* Is the special shutdown target active or queued? If so, we are in shutdown state */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u && unit_active_or_pending(u))
                return MANAGER_STOPPING;

        if (MANAGER_IS_SYSTEM(m)) {
                /* Are the rescue or emergency targets active or queued? If so we are in maintenance state */
                u = manager_get_unit(m, SPECIAL_RESCUE_TARGET);
                if (u && unit_active_or_pending(u))
                        return MANAGER_MAINTENANCE;

                u = manager_get_unit(m, SPECIAL_EMERGENCY_TARGET);
                if (u && unit_active_or_pending(u))
                        return MANAGER_MAINTENANCE;
        }

        /* Are there any failed units? If so, we are in degraded mode */
        if (set_size(m->failed_units) > 0)
                return MANAGER_DEGRADED;

        return MANAGER_RUNNING;
}

#define DESTROY_IPC_FLAG (UINT32_C(1) << 31)

static void manager_unref_uid_internal(
                Manager *m,
                Hashmap **uid_refs,
                uid_t uid,
                bool destroy_now,
                int (*_clean_ipc)(uid_t uid)) {

        uint32_t c, n;

        assert(m);
        assert(uid_refs);
        assert(uid_is_valid(uid));
        assert(_clean_ipc);

        /* A generic implementation, covering both manager_unref_uid() and manager_unref_gid(), under the assumption
         * that uid_t and gid_t are actually defined the same way, with the same validity rules.
         *
         * We store a hashmap where the UID/GID is they key and the value is a 32bit reference counter, whose highest
         * bit is used as flag for marking UIDs/GIDs whose IPC objects to remove when the last reference to the UID/GID
         * is dropped. The flag is set to on, once at least one reference from a unit where RemoveIPC= is set is added
         * on a UID/GID. It is reset when the UID's/GID's reference counter drops to 0 again. */

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (uid == 0) /* We don't keep track of root, and will never destroy it */
                return;

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));

        n = c & ~DESTROY_IPC_FLAG;
        assert(n > 0);
        n--;

        if (destroy_now && n == 0) {
                hashmap_remove(*uid_refs, UID_TO_PTR(uid));

                if (c & DESTROY_IPC_FLAG) {
                        log_debug("%s " UID_FMT " is no longer referenced, cleaning up its IPC.",
                                  _clean_ipc == clean_ipc_by_uid ? "UID" : "GID",
                                  uid);
                        (void) _clean_ipc(uid);
                }
        } else {
                c = n | (c & DESTROY_IPC_FLAG);
                assert_se(hashmap_update(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c)) >= 0);
        }
}

void manager_unref_uid(Manager *m, uid_t uid, bool destroy_now) {
        manager_unref_uid_internal(m, &m->uid_refs, uid, destroy_now, clean_ipc_by_uid);
}

void manager_unref_gid(Manager *m, gid_t gid, bool destroy_now) {
        manager_unref_uid_internal(m, &m->gid_refs, (uid_t) gid, destroy_now, clean_ipc_by_gid);
}

static int manager_ref_uid_internal(
                Manager *m,
                Hashmap **uid_refs,
                uid_t uid,
                bool clean_ipc) {

        uint32_t c, n;
        int r;

        assert(m);
        assert(uid_refs);
        assert(uid_is_valid(uid));

        /* A generic implementation, covering both manager_ref_uid() and manager_ref_gid(), under the assumption
         * that uid_t and gid_t are actually defined the same way, with the same validity rules. */

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (uid == 0) /* We don't keep track of root, and will never destroy it */
                return 0;

        r = hashmap_ensure_allocated(uid_refs, &trivial_hash_ops);
        if (r < 0)
                return r;

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));

        n = c & ~DESTROY_IPC_FLAG;
        n++;

        if (n & DESTROY_IPC_FLAG) /* check for overflow */
                return -EOVERFLOW;

        c = n | (c & DESTROY_IPC_FLAG) | (clean_ipc ? DESTROY_IPC_FLAG : 0);

        return hashmap_replace(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c));
}

int manager_ref_uid(Manager *m, uid_t uid, bool clean_ipc) {
        return manager_ref_uid_internal(m, &m->uid_refs, uid, clean_ipc);
}

int manager_ref_gid(Manager *m, gid_t gid, bool clean_ipc) {
        return manager_ref_uid_internal(m, &m->gid_refs, (uid_t) gid, clean_ipc);
}

static void manager_vacuum_uid_refs_internal(
                Manager *m,
                Hashmap **uid_refs,
                int (*_clean_ipc)(uid_t uid)) {

        Iterator i;
        void *p, *k;

        assert(m);
        assert(uid_refs);
        assert(_clean_ipc);

        HASHMAP_FOREACH_KEY(p, k, *uid_refs, i) {
                uint32_t c, n;
                uid_t uid;

                uid = PTR_TO_UID(k);
                c = PTR_TO_UINT32(p);

                n = c & ~DESTROY_IPC_FLAG;
                if (n > 0)
                        continue;

                if (c & DESTROY_IPC_FLAG) {
                        log_debug("Found unreferenced %s " UID_FMT " after reload/reexec. Cleaning up.",
                                  _clean_ipc == clean_ipc_by_uid ? "UID" : "GID",
                                  uid);
                        (void) _clean_ipc(uid);
                }

                assert_se(hashmap_remove(*uid_refs, k) == p);
        }
}

void manager_vacuum_uid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m, &m->uid_refs, clean_ipc_by_uid);
}

void manager_vacuum_gid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m, &m->gid_refs, clean_ipc_by_gid);
}

static void manager_serialize_uid_refs_internal(
                Manager *m,
                FILE *f,
                Hashmap **uid_refs,
                const char *field_name) {

        Iterator i;
        void *p, *k;

        assert(m);
        assert(f);
        assert(uid_refs);
        assert(field_name);

        /* Serialize the UID reference table. Or actually, just the IPC destruction flag of it, as the actual counter
         * of it is better rebuild after a reload/reexec. */

        HASHMAP_FOREACH_KEY(p, k, *uid_refs, i) {
                uint32_t c;
                uid_t uid;

                uid = PTR_TO_UID(k);
                c = PTR_TO_UINT32(p);

                if (!(c & DESTROY_IPC_FLAG))
                        continue;

                (void) serialize_item_format(f, field_name, UID_FMT, uid);
        }
}

void manager_serialize_uid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(m, f, &m->uid_refs, "destroy-ipc-uid");
}

void manager_serialize_gid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(m, f, &m->gid_refs, "destroy-ipc-gid");
}

static void manager_deserialize_uid_refs_one_internal(
                Manager *m,
                Hashmap** uid_refs,
                const char *value) {

        uid_t uid;
        uint32_t c;
        int r;

        assert(m);
        assert(uid_refs);
        assert(value);

        r = parse_uid(value, &uid);
        if (r < 0 || uid == 0) {
                log_debug("Unable to parse UID reference serialization");
                return;
        }

        r = hashmap_ensure_allocated(uid_refs, &trivial_hash_ops);
        if (r < 0) {
                log_oom();
                return;
        }

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));
        if (c & DESTROY_IPC_FLAG)
                return;

        c |= DESTROY_IPC_FLAG;

        r = hashmap_replace(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c));
        if (r < 0) {
                log_debug_errno(r, "Failed to add UID reference entry: %m");
                return;
        }
}

void manager_deserialize_uid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(m, &m->uid_refs, value);
}

void manager_deserialize_gid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(m, &m->gid_refs, value);
}

int manager_dispatch_user_lookup_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        struct buffer {
                uid_t uid;
                gid_t gid;
                char unit_name[UNIT_NAME_MAX+1];
        } _packed_ buffer;

        Manager *m = userdata;
        ssize_t l;
        size_t n;
        Unit *u;

        assert_se(source);
        assert_se(m);

        /* Invoked whenever a child process succeeded resolving its user/group to use and sent us the resulting UID/GID
         * in a datagram. We parse the datagram here and pass it off to the unit, so that it can add a reference to the
         * UID/GID so that it can destroy the UID/GID's IPC objects when the reference counter drops to 0. */

        l = recv(fd, &buffer, sizeof(buffer), MSG_DONTWAIT);
        if (l < 0) {
                if (IN_SET(errno, EINTR, EAGAIN))
                        return 0;

                return log_error_errno(errno, "Failed to read from user lookup fd: %m");
        }

        if ((size_t) l <= offsetof(struct buffer, unit_name)) {
                log_warning("Received too short user lookup message, ignoring.");
                return 0;
        }

        if ((size_t) l > offsetof(struct buffer, unit_name) + UNIT_NAME_MAX) {
                log_warning("Received too long user lookup message, ignoring.");
                return 0;
        }

        if (!uid_is_valid(buffer.uid) && !gid_is_valid(buffer.gid)) {
                log_warning("Got user lookup message with invalid UID/GID pair, ignoring.");
                return 0;
        }

        n = (size_t) l - offsetof(struct buffer, unit_name);
        if (memchr(buffer.unit_name, 0, n)) {
                log_warning("Received lookup message with embedded NUL character, ignoring.");
                return 0;
        }

        buffer.unit_name[n] = 0;
        u = manager_get_unit(m, buffer.unit_name);
        if (!u) {
                log_debug("Got user lookup message but unit doesn't exist, ignoring.");
                return 0;
        }

        log_unit_debug(u, "User lookup succeeded: uid=" UID_FMT " gid=" GID_FMT, buffer.uid, buffer.gid);

        unit_notify_user_lookup(u, buffer.uid, buffer.gid);
        return 0;
}

char *manager_taint_string(Manager *m) {
        _cleanup_free_ char *destination = NULL, *overflowuid = NULL, *overflowgid = NULL;
        char *buf, *e;
        int r;

        /* Returns a "taint string", e.g. "local-hwclock:var-run-bad".
         * Only things that are detected at runtime should be tagged
         * here. For stuff that is set during compilation, emit a warning
         * in the configuration phase. */

        assert(m);

        buf = new(char, sizeof("split-usr:"
                               "cgroups-missing:"
                               "local-hwclock:"
                               "var-run-bad:"
                               "overflowuid-not-65534:"
                               "overflowgid-not-65534:"));
        if (!buf)
                return NULL;

        e = buf;
        buf[0] = 0;

        if (m->taint_usr)
                e = stpcpy(e, "split-usr:");

        if (access("/proc/cgroups", F_OK) < 0)
                e = stpcpy(e, "cgroups-missing:");

        if (clock_is_localtime(NULL) > 0)
                e = stpcpy(e, "local-hwclock:");

        r = readlink_malloc("/var/run", &destination);
        if (r < 0 || !PATH_IN_SET(destination, "../run", "/run"))
                e = stpcpy(e, "var-run-bad:");

        r = read_one_line_file("/proc/sys/kernel/overflowuid", &overflowuid);
        if (r >= 0 && !streq(overflowuid, "65534"))
                e = stpcpy(e, "overflowuid-not-65534:");

        r = read_one_line_file("/proc/sys/kernel/overflowgid", &overflowgid);
        if (r >= 0 && !streq(overflowgid, "65534"))
                e = stpcpy(e, "overflowgid-not-65534:");

        /* remove the last ':' */
        if (e != buf)
                e[-1] = 0;

        return buf;
}

void manager_ref_console(Manager *m) {
        assert(m);

        m->n_on_console++;
}

void manager_unref_console(Manager *m) {

        assert(m->n_on_console > 0);
        m->n_on_console--;

        if (m->n_on_console == 0)
                m->no_console_output = false; /* unset no_console_output flag, since the console is definitely free now */
}

void manager_override_log_level(Manager *m, int level) {
        _cleanup_free_ char *s = NULL;
        assert(m);

        if (!m->log_level_overridden) {
                m->original_log_level = log_get_max_level();
                m->log_level_overridden = true;
        }

        (void) log_level_to_string_alloc(level, &s);
        log_info("Setting log level to %s.", strna(s));

        log_set_max_level(level);
}

void manager_restore_original_log_level(Manager *m) {
        _cleanup_free_ char *s = NULL;
        assert(m);

        if (!m->log_level_overridden)
                return;

        (void) log_level_to_string_alloc(m->original_log_level, &s);
        log_info("Restoring log level to original (%s).", strna(s));

        log_set_max_level(m->original_log_level);
        m->log_level_overridden = false;
}

void manager_override_log_target(Manager *m, LogTarget target) {
        assert(m);

        if (!m->log_target_overridden) {
                m->original_log_target = log_get_target();
                m->log_target_overridden = true;
        }

        log_info("Setting log target to %s.", log_target_to_string(target));
        log_set_target(target);
}

void manager_restore_original_log_target(Manager *m) {
        assert(m);

        if (!m->log_target_overridden)
                return;

        log_info("Restoring log target to original %s.", log_target_to_string(m->original_log_target));

        log_set_target(m->original_log_target);
        m->log_target_overridden = false;
}

ManagerTimestamp manager_timestamp_initrd_mangle(ManagerTimestamp s) {
        if (in_initrd() &&
            s >= MANAGER_TIMESTAMP_SECURITY_START &&
            s <= MANAGER_TIMESTAMP_UNITS_LOAD_FINISH)
                return s - MANAGER_TIMESTAMP_SECURITY_START + MANAGER_TIMESTAMP_INITRD_SECURITY_START;
        return s;
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

static const char *const manager_timestamp_table[_MANAGER_TIMESTAMP_MAX] = {
        [MANAGER_TIMESTAMP_FIRMWARE] = "firmware",
        [MANAGER_TIMESTAMP_LOADER] = "loader",
        [MANAGER_TIMESTAMP_KERNEL] = "kernel",
        [MANAGER_TIMESTAMP_INITRD] = "initrd",
        [MANAGER_TIMESTAMP_USERSPACE] = "userspace",
        [MANAGER_TIMESTAMP_FINISH] = "finish",
        [MANAGER_TIMESTAMP_SECURITY_START] = "security-start",
        [MANAGER_TIMESTAMP_SECURITY_FINISH] = "security-finish",
        [MANAGER_TIMESTAMP_GENERATORS_START] = "generators-start",
        [MANAGER_TIMESTAMP_GENERATORS_FINISH] = "generators-finish",
        [MANAGER_TIMESTAMP_UNITS_LOAD_START] = "units-load-start",
        [MANAGER_TIMESTAMP_UNITS_LOAD_FINISH] = "units-load-finish",
        [MANAGER_TIMESTAMP_INITRD_SECURITY_START] = "initrd-security-start",
        [MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH] = "initrd-security-finish",
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_START] = "initrd-generators-start",
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH] = "initrd-generators-finish",
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START] = "initrd-units-load-start",
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH] = "initrd-units-load-finish",
};

DEFINE_STRING_TABLE_LOOKUP(manager_timestamp, ManagerTimestamp);

static const char* const oom_policy_table[_OOM_POLICY_MAX] = {
        [OOM_CONTINUE] = "continue",
        [OOM_STOP] = "stop",
        [OOM_KILL] = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(oom_policy, OOMPolicy);
