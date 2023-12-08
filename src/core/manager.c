/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
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
#include "common-signal.h"
#include "confidential-virt.h"
#include "constants.h"
#include "core-varlink.h"
#include "creds-util.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "dirent-util.h"
#include "env-util.h"
#include "escape.h"
#include "event-util.h"
#include "exec-util.h"
#include "execute.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator-setup.h"
#include "hashmap.h"
#include "initrd-util.h"
#include "inotify-util.h"
#include "install.h"
#include "io-util.h"
#include "label-util.h"
#include "load-fragment.h"
#include "locale-setup.h"
#include "log.h"
#include "macro.h"
#include "manager.h"
#include "manager-dump.h"
#include "manager-serialize.h"
#include "memory-util.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "plymouth-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "psi-util.h"
#include "ratelimit.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "sysctl-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "transaction.h"
#include "uid-range.h"
#include "umask-util.h"
#include "unit-name.h"
#include "user-util.h"
#include "virt.h"
#include "watchdog.h"

#define NOTIFY_RCVBUF_SIZE (8*1024*1024)
#define CGROUPS_AGENT_RCVBUF_SIZE (8*1024*1024)

/* Initial delay and the interval for printing status messages about running jobs */
#define JOBS_IN_PROGRESS_WAIT_USEC (2*USEC_PER_SEC)
#define JOBS_IN_PROGRESS_QUIET_WAIT_USEC (25*USEC_PER_SEC)
#define JOBS_IN_PROGRESS_PERIOD_USEC (USEC_PER_SEC / 3)
#define JOBS_IN_PROGRESS_PERIOD_DIVISOR 3

/* If there are more than 1K bus messages queue across our API and direct buses, then let's not add more on top until
 * the queue gets more empty. */
#define MANAGER_BUS_BUSY_THRESHOLD 1024LU

/* How many units and jobs to process of the bus queue before returning to the event loop. */
#define MANAGER_BUS_MESSAGE_BUDGET 100U

#define DEFAULT_TASKS_MAX ((CGroupTasksMax) { 15U, 100U }) /* 15% */

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
static void manager_vacuum(Manager *m);

static usec_t manager_watch_jobs_next_time(Manager *m) {
        usec_t timeout;

        if (MANAGER_IS_USER(m))
                /* Let the user manager without a timeout show status quickly, so the system manager can make
                 * use of it, if it wants to. */
                timeout = JOBS_IN_PROGRESS_WAIT_USEC * 2 / 3;
        else if (show_status_on(m->show_status))
                /* When status is on, just use the usual timeout. */
                timeout = JOBS_IN_PROGRESS_WAIT_USEC;
        else
                timeout = JOBS_IN_PROGRESS_QUIET_WAIT_USEC;

        return usec_add(now(CLOCK_MONOTONIC), timeout);
}

static bool manager_is_confirm_spawn_disabled(Manager *m) {
        assert(m);

        if (!m->confirm_spawn)
                return true;

        return access("/run/systemd/confirm_spawn_disabled", F_OK) >= 0;
}

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

        next = manager_watch_jobs_next_time(m);
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

static void manager_flip_auto_status(Manager *m, bool enable, const char *reason) {
        assert(m);

        if (enable) {
                if (m->show_status == SHOW_STATUS_AUTO)
                        manager_set_show_status(m, SHOW_STATUS_TEMPORARY, reason);
        } else {
                if (m->show_status == SHOW_STATUS_TEMPORARY)
                        manager_set_show_status(m, SHOW_STATUS_AUTO, reason);
        }
}

static void manager_print_jobs_in_progress(Manager *m) {
        Job *j;
        unsigned counter = 0, print_nr;
        char cylon[6 + CYLON_BUFFER_EXTRA + 1];
        unsigned cylon_pos;
        uint64_t timeout = 0;

        assert(m);
        assert(m->n_running_jobs > 0);

        manager_flip_auto_status(m, true, "delay");

        print_nr = (m->jobs_in_progress_iteration / JOBS_IN_PROGRESS_PERIOD_DIVISOR) % m->n_running_jobs;

        HASHMAP_FOREACH(j, m->jobs)
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

        char job_of_n[STRLEN("( of ) ") + DECIMAL_STR_MAX(unsigned)*2] = "";
        if (m->n_running_jobs > 1)
                xsprintf(job_of_n, "(%u of %u) ", counter, m->n_running_jobs);

        (void) job_get_timeout(j, &timeout);

        /* We want to use enough information for the user to identify previous lines talking about the same
         * unit, but keep the message as short as possible. So if 'Starting foo.service' or 'Starting
         * foo.service - Description' were used, 'foo.service' is enough here. On the other hand, if we used
         * 'Starting Description' before, then we shall also use 'Description' here. So we pass NULL as the
         * second argument to unit_status_string(). */
        const char *ident = unit_status_string(j->unit, NULL);

        const char *time = FORMAT_TIMESPAN(now(CLOCK_MONOTONIC) - j->begin_usec, 1*USEC_PER_SEC);
        const char *limit = timeout > 0 ? FORMAT_TIMESPAN(timeout - j->begin_usec, 1*USEC_PER_SEC) : "no limit";

        if (m->status_unit_format == STATUS_UNIT_FORMAT_DESCRIPTION)
                /* When using 'Description', we effectively don't have enough space to show the nested status
                 * without ellipsization, so let's not even try. */
                manager_status_printf(m, STATUS_TYPE_EPHEMERAL, cylon,
                                      "%sA %s job is running for %s (%s / %s)",
                                      job_of_n,
                                      job_type_to_string(j->type),
                                      ident,
                                      time, limit);
        else {
                const char *status_text = unit_status_text(j->unit);

                manager_status_printf(m, STATUS_TYPE_EPHEMERAL, cylon,
                                      "%sJob %s/%s running (%s / %s)%s%s",
                                      job_of_n,
                                      ident,
                                      job_type_to_string(j->type),
                                      time, limit,
                                      status_text ? ": " : "",
                                      strempty(status_text));
        }

        sd_notifyf(false,
                   "STATUS=%sUser job %s/%s running (%s / %s)...",
                   job_of_n,
                   ident,
                   job_type_to_string(j->type),
                   time, limit);
        m->status_ready = false;
}

static int have_ask_password(void) {
        _cleanup_closedir_ DIR *dir = NULL;

        dir = opendir("/run/systemd/ask-password");
        if (!dir) {
                if (errno == ENOENT)
                        return false;
                else
                        return -errno;
        }

        FOREACH_DIRENT_ALL(de, dir, return -errno)
                if (startswith(de->d_name, "ask."))
                        return true;
        return false;
}

static int manager_dispatch_ask_password_fd(sd_event_source *source,
                                            int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

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

        m->ask_password_event_source = sd_event_source_disable_unref(m->ask_password_event_source);
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

                r = inotify_add_watch_and_warn(m->ask_password_inotify_fd,
                                               "/run/systemd/ask-password",
                                               IN_CREATE|IN_DELETE|IN_MOVE);
                if (r < 0) {
                        manager_close_ask_password(m);
                        return r;
                }

                r = sd_event_add_io(m->event, &m->ask_password_event_source,
                                    m->ask_password_inotify_fd, EPOLLIN,
                                    manager_dispatch_ask_password_fd, m);
                if (r < 0) {
                        log_error_errno(r, "Failed to add event source for /run/systemd/ask-password: %m");
                        manager_close_ask_password(m);
                        return r;
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

        m->idle_pipe_event_source = sd_event_source_disable_unref(m->idle_pipe_event_source);

        safe_close_pair(m->idle_pipe);
        safe_close_pair(m->idle_pipe + 2);
}

static int manager_setup_time_change(Manager *m) {
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        m->time_change_event_source = sd_event_source_disable_unref(m->time_change_event_source);

        r = event_add_time_change(m->event, &m->time_change_event_source, manager_dispatch_time_change_fd, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create time change event source: %m");

        /* Schedule this slightly earlier than the .timer event sources */
        r = sd_event_source_set_priority(m->time_change_event_source, SD_EVENT_PRIORITY_NORMAL-1);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of time change event sources: %m");

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
        _cleanup_close_ int fd = -EBADF;

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
                        SIGUSR1,     /* systemd: reconnect to D-Bus */
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
                        SIGRTMIN+7,  /* systemd: start soft-reboot.target */

                        /* ... space for more special targets ... */

                        SIGRTMIN+13, /* systemd: Immediate halt */
                        SIGRTMIN+14, /* systemd: Immediate poweroff */
                        SIGRTMIN+15, /* systemd: Immediate reboot */
                        SIGRTMIN+16, /* systemd: Immediate kexec */
                        SIGRTMIN+17, /* systemd: Immediate soft-reboot */
                        SIGRTMIN+18, /* systemd: control command */

                        /* ... space ... */

                        SIGRTMIN+20, /* systemd: enable status messages */
                        SIGRTMIN+21, /* systemd: disable status messages */
                        SIGRTMIN+22, /* systemd: set log level to LOG_DEBUG */
                        SIGRTMIN+23, /* systemd: set log level to LOG_INFO */
                        SIGRTMIN+24, /* systemd: Immediate exit (--user only) */
                        SIGRTMIN+25, /* systemd: reexecute manager */

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
                        "CACHE_DIRECTORY",
                        "CONFIGURATION_DIRECTORY",
                        "CREDENTIALS_DIRECTORY",
                        "EXIT_CODE",
                        "EXIT_STATUS",
                        "INVOCATION_ID",
                        "JOURNAL_STREAM",
                        "LISTEN_FDNAMES",
                        "LISTEN_FDS",
                        "LISTEN_PID",
                        "LOGS_DIRECTORY",
                        "LOG_NAMESPACE",
                        "MAINPID",
                        "MANAGERPID",
                        "MEMORY_PRESSURE_WATCH",
                        "MEMORY_PRESSURE_WRITE",
                        "MONITOR_EXIT_CODE",
                        "MONITOR_EXIT_STATUS",
                        "MONITOR_INVOCATION_ID",
                        "MONITOR_SERVICE_RESULT",
                        "MONITOR_UNIT",
                        "NOTIFY_SOCKET",
                        "PIDFILE",
                        "REMOTE_ADDR",
                        "REMOTE_PORT",
                        "RUNTIME_DIRECTORY",
                        "SERVICE_RESULT",
                        "STATE_DIRECTORY",
                        "SYSTEMD_EXEC_PID",
                        "TRIGGER_PATH",
                        "TRIGGER_TIMER_MONOTONIC_USEC",
                        "TRIGGER_TIMER_REALTIME_USEC",
                        "TRIGGER_UNIT",
                        "WATCHDOG_PID",
                        "WATCHDOG_USEC",
                        NULL);

        /* Let's order the environment alphabetically, just to make it pretty */
        return strv_sort(l);
}

int manager_default_environment(Manager *m) {
        int r;

        assert(m);

        m->transient_environment = strv_free(m->transient_environment);

        if (MANAGER_IS_SYSTEM(m)) {
                /* The system manager always starts with a clean environment for its children. It does not
                 * import the kernel's or the parents' exported variables.
                 *
                 * The initial passed environment is untouched to keep /proc/self/environ valid; it is used
                 * for tagging the init process inside containers. */
                m->transient_environment = strv_new("PATH=" DEFAULT_PATH);
                if (!m->transient_environment)
                        return log_oom();

                /* Import locale variables LC_*= from configuration */
                (void) locale_setup(&m->transient_environment);
        } else {
                /* The user manager passes its own environment along to its children, except for $PATH. */
                m->transient_environment = strv_copy(environ);
                if (!m->transient_environment)
                        return log_oom();

                r = strv_env_replace_strdup(&m->transient_environment, "PATH=" DEFAULT_USER_PATH);
                if (r < 0)
                        return log_oom();
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
                [EXEC_DIRECTORY_RUNTIME] =       { SD_PATH_SYSTEM_RUNTIME,       NULL },
                [EXEC_DIRECTORY_STATE] =         { SD_PATH_SYSTEM_STATE_PRIVATE, NULL },
                [EXEC_DIRECTORY_CACHE] =         { SD_PATH_SYSTEM_STATE_CACHE,   NULL },
                [EXEC_DIRECTORY_LOGS] =          { SD_PATH_SYSTEM_STATE_LOGS,    NULL },
                [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_SYSTEM_CONFIGURATION, NULL },
        };

        static const struct table_entry paths_user[_EXEC_DIRECTORY_TYPE_MAX] = {
                [EXEC_DIRECTORY_RUNTIME] =       { SD_PATH_USER_RUNTIME,       NULL  },
                [EXEC_DIRECTORY_STATE] =         { SD_PATH_USER_STATE_PRIVATE, NULL  },
                [EXEC_DIRECTORY_CACHE] =         { SD_PATH_USER_STATE_CACHE,   NULL  },
                [EXEC_DIRECTORY_LOGS] =          { SD_PATH_USER_STATE_PRIVATE, "log" },
                [EXEC_DIRECTORY_CONFIGURATION] = { SD_PATH_USER_CONFIGURATION, NULL  },
        };

        assert(m);

        const struct table_entry *p = MANAGER_IS_SYSTEM(m) ? paths_system : paths_user;
        int r;

        for (ExecDirectoryType i = 0; i < _EXEC_DIRECTORY_TYPE_MAX; i++) {
                r = sd_path_lookup(p[i].type, p[i].suffix, &m->prefix[i]);
                if (r < 0)
                        return log_warning_errno(r, "Failed to lookup %s path: %m",
                                                 exec_directory_type_to_string(i));
        }

        return 0;
}

static void manager_free_unit_name_maps(Manager *m) {
        m->unit_id_map = hashmap_free(m->unit_id_map);
        m->unit_name_map = hashmap_free(m->unit_name_map);
        m->unit_path_cache = set_free(m->unit_path_cache);
        m->unit_cache_timestamp_hash = 0;
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

int manager_setup_memory_pressure_event_source(Manager *m) {
        int r;

        assert(m);

        m->memory_pressure_event_source = sd_event_source_disable_unref(m->memory_pressure_event_source);

        r = sd_event_add_memory_pressure(m->event, &m->memory_pressure_event_source, NULL, NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN) ? LOG_DEBUG : LOG_NOTICE, r,
                               "Failed to establish memory pressure event source, ignoring: %m");
        else if (m->defaults.memory_pressure_threshold_usec != USEC_INFINITY) {

                /* If there's a default memory pressure threshold set, also apply it to the service manager itself */
                r = sd_event_source_set_memory_pressure_period(
                                m->memory_pressure_event_source,
                                m->defaults.memory_pressure_threshold_usec,
                                MEMORY_PRESSURE_DEFAULT_WINDOW_USEC);
                if (r < 0)
                        log_warning_errno(r, "Failed to adjust memory pressure threshold, ignoring: %m");
        }

        return 0;
}

static int manager_find_credentials_dirs(Manager *m) {
        const char *e;
        int r;

        assert(m);

        r = get_credentials_dir(&e);
        if (r < 0) {
                if (r != -ENXIO)
                        log_debug_errno(r, "Failed to determine credentials directory, ignoring: %m");
        } else {
                m->received_credentials_directory = strdup(e);
                if (!m->received_credentials_directory)
                        return -ENOMEM;
        }

        r = get_encrypted_credentials_dir(&e);
        if (r < 0) {
                if (r != -ENXIO)
                        log_debug_errno(r, "Failed to determine encrypted credentials directory, ignoring: %m");
        } else {
                m->received_encrypted_credentials_directory = strdup(e);
                if (!m->received_encrypted_credentials_directory)
                        return -ENOMEM;
        }

        return 0;
}

void manager_set_switching_root(Manager *m, bool switching_root) {
        assert(m);

        m->switching_root = MANAGER_IS_SYSTEM(m) && switching_root;
}

double manager_get_progress(Manager *m) {
        assert(m);

        if (MANAGER_IS_FINISHED(m) || m->n_installed_jobs == 0)
                return 1.0;

        return 1.0 - ((double) hashmap_size(m->jobs) / (double) m->n_installed_jobs);
}

static int compare_job_priority(const void *a, const void *b) {
        const Job *x = a, *y = b;

        return unit_compare_priority(x->unit, y->unit);
}

int manager_new(RuntimeScope runtime_scope, ManagerTestRunFlags test_run_flags, Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(IN_SET(runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));
        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .runtime_scope = runtime_scope,
                .objective = _MANAGER_OBJECTIVE_INVALID,

                .status_unit_format = STATUS_UNIT_FORMAT_DEFAULT,

                .original_log_level = -1,
                .original_log_target = _LOG_TARGET_INVALID,

                .watchdog_overridden[WATCHDOG_RUNTIME] = USEC_INFINITY,
                .watchdog_overridden[WATCHDOG_REBOOT] = USEC_INFINITY,
                .watchdog_overridden[WATCHDOG_KEXEC] = USEC_INFINITY,
                .watchdog_overridden[WATCHDOG_PRETIMEOUT] = USEC_INFINITY,

                .show_status_overridden = _SHOW_STATUS_INVALID,

                .notify_fd = -EBADF,
                .cgroups_agent_fd = -EBADF,
                .signal_fd = -EBADF,
                .user_lookup_fds = EBADF_PAIR,
                .private_listen_fd = -EBADF,
                .dev_autofs_fd = -EBADF,
                .cgroup_inotify_fd = -EBADF,
                .pin_cgroupfs_fd = -EBADF,
                .ask_password_inotify_fd = -EBADF,
                .idle_pipe = { -EBADF, -EBADF, -EBADF, -EBADF},

                 /* start as id #1, so that we can leave #0 around as "null-like" value */
                .current_job_id = 1,

                .have_ask_password = -EINVAL, /* we don't know */
                .first_boot = -1,
                .test_run_flags = test_run_flags,

                .dump_ratelimit = (const RateLimit) { .interval = 10 * USEC_PER_MINUTE, .burst = 10 },

                .executor_fd = -EBADF,
        };

        unit_defaults_init(&m->defaults, runtime_scope);

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
        m->ctrl_alt_del_ratelimit = (const RateLimit) { .interval = 2 * USEC_PER_SEC, .burst = 7 };

        r = manager_default_environment(m);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&m->units, &string_hash_ops);
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

        r = manager_find_credentials_dirs(m);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = manager_setup_run_queue(m);
        if (r < 0)
                return r;

        if (FLAGS_SET(test_run_flags, MANAGER_TEST_RUN_MINIMAL)) {
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

                r = manager_setup_memory_pressure_event_source(m);
                if (r < 0)
                        return r;

#if HAVE_LIBBPF
                if (MANAGER_IS_SYSTEM(m) && lsm_bpf_supported(/* initialize = */ true)) {
                        r = lsm_bpf_setup(m);
                        if (r < 0)
                                log_warning_errno(r, "Failed to setup LSM BPF, ignoring: %m");
                }
#endif
        }

        if (test_run_flags == 0) {
                if (MANAGER_IS_SYSTEM(m))
                        r = mkdir_label("/run/systemd/units", 0755);
                else {
                        _cleanup_free_ char *units_path = NULL;
                        r = xdg_user_runtime_dir(&units_path, "/systemd/units");
                        if (r < 0)
                                return r;
                        r = mkdir_p_label(units_path, 0755);
                }

                if (r < 0 && r != -EEXIST)
                        return r;

                m->executor_fd = open(SYSTEMD_EXECUTOR_BINARY_PATH, O_CLOEXEC|O_PATH);
                if (m->executor_fd < 0)
                        return log_warning_errno(errno,
                                                 "Failed to open executor binary '%s': %m",
                                                 SYSTEMD_EXECUTOR_BINARY_PATH);
        } else if (!FLAGS_SET(test_run_flags, MANAGER_TEST_DONT_OPEN_EXECUTOR)) {
                _cleanup_free_ char *self_exe = NULL, *executor_path = NULL;
                _cleanup_close_ int self_dir_fd = -EBADF;
                int level = LOG_DEBUG;

                /* Prefer sd-executor from the same directory as the test, e.g.: when running unit tests from the
                * build directory. Fallback to working directory and then the installation path. */
                r = readlink_and_make_absolute("/proc/self/exe", &self_exe);
                if (r < 0)
                        return r;

                self_dir_fd = open_parent(self_exe, O_CLOEXEC|O_PATH|O_DIRECTORY, 0);
                if (self_dir_fd < 0)
                        return self_dir_fd;

                m->executor_fd = RET_NERRNO(openat(self_dir_fd, "systemd-executor", O_CLOEXEC|O_PATH));
                if (m->executor_fd == -ENOENT)
                        m->executor_fd = RET_NERRNO(openat(AT_FDCWD, "systemd-executor", O_CLOEXEC|O_PATH));
                if (m->executor_fd == -ENOENT) {
                        m->executor_fd = RET_NERRNO(open(SYSTEMD_EXECUTOR_BINARY_PATH, O_CLOEXEC|O_PATH));
                        level = LOG_WARNING; /* Tests should normally use local builds */
                }
                if (m->executor_fd < 0)
                        return m->executor_fd;

                r = fd_get_path(m->executor_fd, &executor_path);
                if (r < 0)
                        return r;

                log_full(level, "Using systemd-executor binary from '%s'.", executor_path);
        }

        /* Note that we do not set up the notify fd here. We do that after deserialization,
         * since they might have gotten serialized across the reexec. */

        *ret = TAKE_PTR(m);

        return 0;
}

static int manager_setup_notify(Manager *m) {
        int r;

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        if (m->notify_fd < 0) {
                _cleanup_close_ int fd = -EBADF;
                union sockaddr_union sa;
                socklen_t sa_len;

                /* First free all secondary fields */
                m->notify_socket = mfree(m->notify_socket);
                m->notify_event_source = sd_event_source_disable_unref(m->notify_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate notification socket: %m");

                fd_increase_rxbuf(fd, NOTIFY_RCVBUF_SIZE);

                m->notify_socket = path_join(m->prefix[EXEC_DIRECTORY_RUNTIME], "systemd/notify");
                if (!m->notify_socket)
                        return log_oom();

                r = sockaddr_un_set_path(&sa.un, m->notify_socket);
                if (r < 0)
                        return log_error_errno(r, "Notify socket '%s' not valid for AF_UNIX socket address, refusing.",
                                               m->notify_socket);
                sa_len = r;

                (void) mkdir_parents_label(m->notify_socket, 0755);
                (void) sockaddr_un_unlink(&sa.un);

                r = mac_selinux_bind(fd, &sa.sa, sa_len);
                if (r < 0)
                        return log_error_errno(r, "bind(%s) failed: %m", m->notify_socket);

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
                _cleanup_close_ int fd = -EBADF;

                /* First free all secondary fields */
                m->cgroups_agent_event_source = sd_event_source_disable_unref(m->cgroups_agent_event_source);

                fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to allocate cgroups agent socket: %m");

                fd_increase_rxbuf(fd, CGROUPS_AGENT_RCVBUF_SIZE);

                (void) sockaddr_un_unlink(&sa.un);

                /* Only allow root to connect to this socket */
                WITH_UMASK(0077)
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
                m->user_lookup_event_source = sd_event_source_disable_unref(m->user_lookup_event_source);

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, m->user_lookup_fds) < 0)
                        return log_error_errno(errno, "Failed to allocate user lookup socket: %m");

                (void) fd_increase_rxbuf(m->user_lookup_fds[0], NOTIFY_RCVBUF_SIZE);
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

static unsigned manager_dispatch_release_resources_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;

        assert(m);

        while ((u = LIST_POP(release_resources_queue, m->release_resources_queue))) {
                assert(u->in_release_resources_queue);
                u->in_release_resources_queue = false;

                n++;

                unit_release_resources(u);
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

        u->gc_marker = gc_marker + GC_OFFSET_GOOD;

        /* Recursively mark referenced units as GOOD as well */
        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_REFERENCES)
                if (other->gc_marker == gc_marker + GC_OFFSET_UNSURE)
                        unit_gc_mark_good(other, gc_marker);
}

static void unit_gc_sweep(Unit *u, unsigned gc_marker) {
        Unit *other;
        bool is_bad;

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

        UNIT_FOREACH_DEPENDENCY(other, u, UNIT_ATOM_REFERENCED_BY) {
                unit_gc_sweep(other, gc_marker);

                if (other->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        LIST_FOREACH(refs_by_target, ref, u->refs_by_target) {
                unit_gc_sweep(ref->source, gc_marker);

                if (ref->source->gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (ref->source->gc_marker != gc_marker + GC_OFFSET_BAD)
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

        while ((u = LIST_POP(gc_queue, m->gc_unit_queue))) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

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

        while ((j = LIST_POP(gc_queue, m->gc_job_queue))) {
                assert(j->in_gc_queue);
                j->in_gc_queue = false;

                n++;

                if (!job_may_gc(j))
                        continue;

                log_unit_debug(j->unit, "Collecting job.");
                (void) job_finish_and_invalidate(j, JOB_COLLECTED, false, false);
        }

        return n;
}

static int manager_ratelimit_requeue(sd_event_source *s, uint64_t usec, void *userdata) {
        Unit *u = userdata;

        assert(u);
        assert(s == u->auto_start_stop_event_source);

        u->auto_start_stop_event_source = sd_event_source_unref(u->auto_start_stop_event_source);

        /* Re-queue to all queues, if the rate limit hit we might have been throttled on any of them. */
        unit_submit_to_stop_when_unneeded_queue(u);
        unit_submit_to_start_when_upheld_queue(u);
        unit_submit_to_stop_when_bound_queue(u);

        return 0;
}

static int manager_ratelimit_check_and_queue(Unit *u) {
        int r;

        assert(u);

        if (ratelimit_below(&u->auto_start_stop_ratelimit))
                return 1;

        /* Already queued, no need to requeue */
        if (u->auto_start_stop_event_source)
                return 0;

        r = sd_event_add_time(
                        u->manager->event,
                        &u->auto_start_stop_event_source,
                        CLOCK_MONOTONIC,
                        ratelimit_end(&u->auto_start_stop_ratelimit),
                        0,
                        manager_ratelimit_requeue,
                        u);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to queue timer on event loop: %m");

        return 0;
}

static unsigned manager_dispatch_stop_when_unneeded_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;
        int r;

        assert(m);

        while ((u = LIST_POP(stop_when_unneeded_queue, m->stop_when_unneeded_queue))) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                assert(u->in_stop_when_unneeded_queue);
                u->in_stop_when_unneeded_queue = false;

                n++;

                if (!unit_is_unneeded(u))
                        continue;

                log_unit_debug(u, "Unit is not needed anymore.");

                /* If stopping a unit fails continuously we might enter a stop loop here, hence stop acting on the
                 * service being unnecessary after a while. */

                r = manager_ratelimit_check_and_queue(u);
                if (r <= 0) {
                        log_unit_warning(u,
                                         "Unit not needed anymore, but not stopping since we tried this too often recently.%s",
                                         r == 0 ? " Will retry later." : "");
                        continue;
                }

                /* Ok, nobody needs us anymore. Sniff. Then let's commit suicide */
                r = manager_add_job(u->manager, JOB_STOP, u, JOB_FAIL, NULL, &error, NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enqueue stop job, ignoring: %s", bus_error_message(&error, r));
        }

        return n;
}

static unsigned manager_dispatch_start_when_upheld_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;
        int r;

        assert(m);

        while ((u = LIST_POP(start_when_upheld_queue, m->start_when_upheld_queue))) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                Unit *culprit = NULL;

                assert(u->in_start_when_upheld_queue);
                u->in_start_when_upheld_queue = false;

                n++;

                if (!unit_is_upheld_by_active(u, &culprit))
                        continue;

                log_unit_debug(u, "Unit is started because upheld by active unit %s.", culprit->id);

                /* If stopping a unit fails continuously we might enter a stop loop here, hence stop acting on the
                 * service being unnecessary after a while. */

                r = manager_ratelimit_check_and_queue(u);
                if (r <= 0) {
                        log_unit_warning(u,
                                         "Unit needs to be started because active unit %s upholds it, but not starting since we tried this too often recently.%s",
                                         culprit->id,
                                         r == 0 ? " Will retry later." : "");
                        continue;
                }

                r = manager_add_job(u->manager, JOB_START, u, JOB_FAIL, NULL, &error, NULL);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Failed to enqueue start job, ignoring: %s", bus_error_message(&error, r));
        }

        return n;
}

static unsigned manager_dispatch_stop_when_bound_queue(Manager *m) {
        unsigned n = 0;
        Unit *u;
        int r;

        assert(m);

        while ((u = LIST_POP(stop_when_bound_queue, m->stop_when_bound_queue))) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                Unit *culprit = NULL;

                assert(u->in_stop_when_bound_queue);
                u->in_stop_when_bound_queue = false;

                n++;

                if (!unit_is_bound_by_inactive(u, &culprit))
                        continue;

                log_unit_debug(u, "Unit is stopped because bound to inactive unit %s.", culprit->id);

                /* If stopping a unit fails continuously we might enter a stop loop here, hence stop acting on the
                 * service being unnecessary after a while. */

                r = manager_ratelimit_check_and_queue(u);
                if (r <= 0) {
                        log_unit_warning(u,
                                         "Unit needs to be stopped because it is bound to inactive unit %s it, but not stopping since we tried this too often recently.%s",
                                         culprit->id,
                                         r == 0 ? " Will retry later." : "");
                        continue;
                }

                r = manager_add_job(u->manager, JOB_STOP, u, JOB_REPLACE, NULL, &error, NULL);
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
        assert(!m->cgroup_realize_queue);
        assert(!m->cgroup_empty_queue);
        assert(!m->cgroup_oom_queue);
        assert(!m->target_deps_queue);
        assert(!m->stop_when_unneeded_queue);
        assert(!m->start_when_upheld_queue);
        assert(!m->stop_when_bound_queue);
        assert(!m->release_resources_queue);

        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));

        m->n_on_console = 0;
        m->n_running_jobs = 0;
        m->n_installed_jobs = 0;
        m->n_failed_jobs = 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        manager_clear_jobs_and_units(m);

        for (UnitType c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        /* Keep the cgroup hierarchy in place except when we know we are going down for good */
        manager_shutdown_cgroup(m, /* delete= */ IN_SET(m->objective, MANAGER_EXIT, MANAGER_REBOOT, MANAGER_POWEROFF, MANAGER_HALT, MANAGER_KEXEC));

        lookup_paths_flush_generator(&m->lookup_paths);

        bus_done(m);
        manager_varlink_done(m);

        exec_shared_runtime_vacuum(m);
        hashmap_free(m->exec_shared_runtime_by_id);

        dynamic_user_vacuum(m, false);
        hashmap_free(m->dynamic_users);

        hashmap_free(m->units);
        hashmap_free(m->units_by_invocation_id);
        hashmap_free(m->jobs);
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_pids_more);
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
        sd_event_source_unref(m->memory_pressure_event_source);

        safe_close(m->signal_fd);
        safe_close(m->notify_fd);
        safe_close(m->cgroups_agent_fd);
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

        unit_defaults_done(&m->defaults);

        FOREACH_ARRAY(map, m->units_needing_mounts_for, _UNIT_MOUNT_DEPENDENCY_TYPE_MAX) {
                assert(hashmap_isempty(*map));
                hashmap_free(*map);
        }

        hashmap_free(m->uid_refs);
        hashmap_free(m->gid_refs);

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++)
                m->prefix[dt] = mfree(m->prefix[dt]);
        free(m->received_credentials_directory);
        free(m->received_encrypted_credentials_directory);

        free(m->watchdog_pretimeout_governor);
        free(m->watchdog_pretimeout_governor_overridden);

        m->fw_ctx = fw_ctx_free(m->fw_ctx);

#if BPF_FRAMEWORK
        lsm_bpf_destroy(m->restrict_fs);
#endif

        safe_close(m->executor_fd);

        return mfree(m);
}

static void manager_enumerate_perpetual(Manager *m) {
        assert(m);

        if (FLAGS_SET(m->test_run_flags, MANAGER_TEST_RUN_MINIMAL))
                return;

        /* Let's ask every type to load all units from disk/kernel that it might know */
        for (UnitType c = 0; c < _UNIT_TYPE_MAX; c++) {
                if (!unit_type_supported(c)) {
                        log_debug("Unit type .%s is not supported on this system.", unit_type_to_string(c));
                        continue;
                }

                if (unit_vtable[c]->enumerate_perpetual)
                        unit_vtable[c]->enumerate_perpetual(m);
        }
}

static void manager_enumerate(Manager *m) {
        assert(m);

        if (FLAGS_SET(m->test_run_flags, MANAGER_TEST_RUN_MINIMAL))
                return;

        /* Let's ask every type to load all units from disk/kernel that it might know */
        for (UnitType c = 0; c < _UNIT_TYPE_MAX; c++) {
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
        Unit *u;
        char *k;
        int r;

        assert(m);

        log_debug("Invoking unit coldplug() handlers%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        /* Let's place the units back into their deserialized state */
        HASHMAP_FOREACH_KEY(u, k, m->units) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                r = unit_coldplug(u);
                if (r < 0)
                        log_warning_errno(r, "We couldn't coldplug %s, proceeding anyway: %m", u->id);
        }
}

static void manager_catchup(Manager *m) {
        Unit *u;
        char *k;

        assert(m);

        log_debug("Invoking unit catchup() handlers%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        /* Let's catch up on any state changes that happened while we were reloading/reexecing */
        HASHMAP_FOREACH_KEY(u, k, m->units) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                unit_catchup(u);
        }
}

static void manager_distribute_fds(Manager *m, FDSet *fds) {
        Unit *u;

        assert(m);

        HASHMAP_FOREACH(u, m->units) {

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
        if (!IN_SET((deserialized ? SERVICE(u)->deserialized_state : SERVICE(u)->state),
                    SERVICE_RUNNING,
                    SERVICE_RELOAD,
                    SERVICE_RELOAD_NOTIFY,
                    SERVICE_RELOAD_SIGNAL))
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
        UnitFilePresetMode mode =
                ENABLE_FIRST_BOOT_FULL_PRESET ? UNIT_FILE_PRESET_FULL : UNIT_FILE_PRESET_ENABLE_ONLY;

        r = unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, NULL, mode, NULL, 0);
        if (r < 0)
                log_full_errno(r == -EEXIST ? LOG_NOTICE : LOG_WARNING, r,
                               "Failed to populate /etc with preset unit settings, ignoring: %m");
        else
                log_info("Populated /etc with preset unit settings.");
}

static void manager_ready(Manager *m) {
        assert(m);

        /* After having loaded everything, do the final round of catching up with what might have changed */

        m->objective = MANAGER_OK; /* Tell everyone we are up now */

        /* It might be safe to log to the journal now and connect to dbus */
        manager_recheck_journal(m);
        manager_recheck_dbus(m);

        /* Let's finally catch up with any changes that took place while we were reloading/reexecing */
        manager_catchup(m);

        /* Create a file which will indicate when the manager started loading units the last time. */
        if (MANAGER_IS_SYSTEM(m))
                (void) touch_file("/run/systemd/systemd-units-load", false,
                        m->timestamps[MANAGER_TIMESTAMP_UNITS_LOAD].realtime ?: now(CLOCK_REALTIME),
                        UID_INVALID, GID_INVALID, 0444);
}

Manager* manager_reloading_start(Manager *m) {
        m->n_reloading++;
        dual_timestamp_now(m->timestamps + MANAGER_TIMESTAMP_UNITS_LOAD);
        return m;
}

void manager_reloading_stopp(Manager **m) {
        if (*m) {
                assert((*m)->n_reloading > 0);
                (*m)->n_reloading--;
        }
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds, const char *root) {
        int r;

        assert(m);

        /* If we are running in test mode, we still want to run the generators,
         * but we should not touch the real generator directories. */
        r = lookup_paths_init_or_warn(&m->lookup_paths, m->runtime_scope,
                                      MANAGER_IS_TEST_RUN(m) ? LOOKUP_PATHS_TEMPORARY_GENERATED : 0,
                                      root);
        if (r < 0)
                return r;

        dual_timestamp_now(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_START));
        r = manager_run_environment_generators(m);
        if (r >= 0)
                r = manager_run_generators(m);
        dual_timestamp_now(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_GENERATORS_FINISH));
        if (r < 0)
                return r;

        manager_preset_all(m);

        lookup_paths_log(&m->lookup_paths);

        {
                /* This block is (optionally) done with the reloading counter bumped */
                _unused_ _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;

                /* Make sure we don't have a left-over from a previous run */
                if (!serialization)
                        (void) rm_rf(m->lookup_paths.transient, 0);

                /* If we will deserialize make sure that during enumeration this is already known, so we increase the
                 * counter here already */
                if (serialization)
                        reloading = manager_reloading_start(m);

                /* First, enumerate what we can from all config files */
                dual_timestamp_now(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_START));
                manager_enumerate_perpetual(m);
                manager_enumerate(m);
                dual_timestamp_now(m->timestamps + manager_timestamp_initrd_mangle(MANAGER_TIMESTAMP_UNITS_LOAD_FINISH));

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

                r = manager_varlink_init(m);
                if (r < 0)
                        log_warning_errno(r, "Failed to set up Varlink, ignoring: %m");

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

        manager_set_switching_root(m, false);

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

        _cleanup_(transaction_abort_and_freep) Transaction *tr = NULL;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Isolate is only valid for start.");

        if (mode == JOB_ISOLATE && !unit->allow_isolate)
                return sd_bus_error_set(error, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");

        if (mode == JOB_TRIGGERING && type != JOB_STOP)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "--job-mode=triggering is only valid for stop.");

        if (mode == JOB_RESTART_DEPENDENCIES && type != JOB_START)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "--job-mode=restart-dependencies is only valid for start.");

        log_unit_debug(unit, "Trying to enqueue job %s/%s/%s", unit->id, job_type_to_string(type), job_mode_to_string(mode));

        type = job_type_collapse(type, unit);

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        r = transaction_add_job_and_dependencies(
                        tr,
                        type,
                        unit,
                        /* by= */ NULL,
                        TRANSACTION_MATTERS |
                        (IN_SET(mode, JOB_IGNORE_DEPENDENCIES, JOB_IGNORE_REQUIREMENTS) ? TRANSACTION_IGNORE_REQUIREMENTS : 0) |
                        (mode == JOB_IGNORE_DEPENDENCIES ? TRANSACTION_IGNORE_ORDER : 0) |
                        (mode == JOB_RESTART_DEPENDENCIES ? TRANSACTION_PROPAGATE_START_AS_RESTART : 0),
                        error);
        if (r < 0)
                return r;

        if (mode == JOB_ISOLATE) {
                r = transaction_add_isolate_jobs(tr, m);
                if (r < 0)
                        return r;
        }

        if (mode == JOB_TRIGGERING) {
                r = transaction_add_triggering_jobs(tr, unit);
                if (r < 0)
                        return r;
        }

        r = transaction_activate(tr, m, mode, affected_jobs, error);
        if (r < 0)
                return r;

        log_unit_debug(unit,
                       "Enqueued job %s/%s as %u", unit->id,
                       job_type_to_string(type), (unsigned) tr->anchor_job->id);

        if (ret)
                *ret = tr->anchor_job;

        tr = transaction_free(tr);
        return 0;
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
        _cleanup_(transaction_abort_and_freep) Transaction *tr = NULL;

        assert(m);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);
        assert(mode != JOB_ISOLATE); /* Isolate is only valid for start */

        tr = transaction_new(mode == JOB_REPLACE_IRREVERSIBLY);
        if (!tr)
                return -ENOMEM;

        /* We need an anchor job */
        r = transaction_add_job_and_dependencies(tr, JOB_NOP, unit, NULL, TRANSACTION_IGNORE_REQUIREMENTS|TRANSACTION_IGNORE_ORDER, e);
        if (r < 0)
                return r;

        /* Failure in adding individual dependencies is ignored, so this always succeeds. */
        transaction_add_propagate_reload_jobs(
                        tr,
                        unit,
                        tr->anchor_job,
                        mode == JOB_IGNORE_DEPENDENCIES ? TRANSACTION_IGNORE_ORDER : 0);

        r = transaction_activate(tr, m, mode, NULL, e);
        if (r < 0)
                return r;

        tr = transaction_free(tr);
        return 0;
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
        int r = 0;

        assert(m);

        while ((u = LIST_POP(target_deps_queue, m->target_deps_queue))) {
                _cleanup_free_ Unit **targets = NULL;
                int n_targets;

                assert(u->in_target_deps_queue);

                u->in_target_deps_queue = false;

                /* Take an "atomic" snapshot of dependencies here, as the call below will likely modify the
                 * dependencies, and we can't have it that hash tables we iterate through are modified while
                 * we are iterating through them. */
                n_targets = unit_get_dependency_array(u, UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES, &targets);
                if (n_targets < 0)
                        return n_targets;

                for (int i = 0; i < n_targets; i++) {
                        r = unit_add_default_target_dependency(u, targets[i]);
                        if (r < 0)
                                return r;
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

bool manager_unit_cache_should_retry_load(Unit *u) {
        assert(u);

        /* Automatic reloading from disk only applies to units which were not found sometime in the past, and
         * the not-found stub is kept pinned in the unit graph by dependencies. For units that were
         * previously loaded, we don't do automatic reloading, and daemon-reload is necessary to update. */
        if (u->load_state != UNIT_NOT_FOUND)
                return false;

        /* The cache has been updated since the last time we tried to load the unit. There might be new
         * fragment paths to read. */
        if (u->manager->unit_cache_timestamp_hash != u->fragment_not_found_timestamp_hash)
                return true;

        /* The cache needs to be updated because there are modifications on disk. */
        return !lookup_paths_timestamp_hash_same(&u->manager->lookup_paths, u->manager->unit_cache_timestamp_hash, NULL);
}

int manager_load_unit_prepare(
                Manager *m,
                const char *name,
                const char *path,
                sd_bus_error *e,
                Unit **ret) {

        _cleanup_(unit_freep) Unit *cleanup_unit = NULL;
        _cleanup_free_ char *nbuf = NULL;
        int r;

        assert(m);
        assert(ret);
        assert(name || path);

        /* This will prepare the unit for loading, but not actually load anything from disk. */

        if (path && !path_is_absolute(path))
                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not absolute.", path);

        if (!name) {
                r = path_extract_filename(path, &nbuf);
                if (r < 0)
                        return r;
                if (r == O_DIRECTORY)
                        return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Path '%s' refers to directory, refusing.", path);

                name = nbuf;
        }

        UnitType t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                        return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is missing the instance name.", name);

                return sd_bus_error_setf(e, SD_BUS_ERROR_INVALID_ARGS, "Unit name %s is not valid.", name);
        }

        Unit *unit = manager_get_unit(m, name);
        if (unit) {
                /* The time-based cache allows to start new units without daemon-reload,
                 * but if they are already referenced (because of dependencies or ordering)
                 * then we have to force a load of the fragment. As an optimization, check
                 * first if anything in the usual paths was modified since the last time
                 * the cache was loaded. Also check if the last time an attempt to load the
                 * unit was made was before the most recent cache refresh, so that we know
                 * we need to try again — even if the cache is current, it might have been
                 * updated in a different context before we had a chance to retry loading
                 * this particular unit. */
                if (manager_unit_cache_should_retry_load(unit))
                        unit->load_state = UNIT_STUB;
                else {
                        *ret = unit;
                        return 0;  /* The unit was already loaded */
                }
        } else {
                unit = cleanup_unit = unit_new(m, unit_vtable[t]->object_size);
                if (!unit)
                        return -ENOMEM;
        }

        if (path) {
                r = free_and_strdup(&unit->fragment_path, path);
                if (r < 0)
                        return r;
        }

        r = unit_add_name(unit, name);
        if (r < 0)
                return r;

        unit_add_to_load_queue(unit);
        unit_add_to_dbus_queue(unit);
        unit_add_to_gc_queue(unit);

        *ret = unit;
        TAKE_PTR(cleanup_unit);

        return 1;  /* The unit was added the load queue */
}

int manager_load_unit(
                Manager *m,
                const char *name,
                const char *path,
                sd_bus_error *e,
                Unit **ret) {
        int r;

        assert(m);
        assert(ret);

        /* This will load the unit config, but not actually start any services or anything. */

        r = manager_load_unit_prepare(m, name, path, e, ret);
        if (r <= 0)
                return r;

        /* Unit was newly loaded */
        manager_dispatch_load_queue(m);
        *ret = unit_follow_merge(*ret);
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

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->jobs)))
                /* No need to recurse. We're cancelling all jobs. */
                job_finish_and_invalidate(j, JOB_CANCELED, false, false);
}

void manager_unwatch_pidref(Manager *m, PidRef *pid) {
        assert(m);

        for (;;) {
                Unit *u;

                u = manager_get_unit_by_pidref_watching(m, pid);
                if (!u)
                        break;

                unit_unwatch_pidref(u, pid);
        }
}

static int manager_dispatch_run_queue(sd_event_source *source, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Job *j;

        assert(source);

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

void manager_trigger_run_queue(Manager *m) {
        int r;

        assert(m);

        r = sd_event_source_set_enabled(
                        m->run_queue_event_source,
                        prioq_isempty(m->run_queue) ? SD_EVENT_OFF : SD_EVENT_ONESHOT);
        if (r < 0)
                log_warning_errno(r, "Failed to enable job run queue event source, ignoring: %m");
}

static unsigned manager_dispatch_dbus_queue(Manager *m) {
        unsigned n = 0, budget;
        Unit *u;
        Job *j;

        assert(m);

        /* When we are reloading, let's not wait with generating signals, since we need to exit the manager as quickly
         * as we can. There's no point in throttling generation of signals in that case. */
        if (MANAGER_IS_RELOADING(m) || m->send_reloading_done || m->pending_reload_message)
                budget = UINT_MAX; /* infinite budget in this case */
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

                if (budget != UINT_MAX)
                        budget--;
        }

        while (budget != 0 && (j = m->dbus_job_queue)) {
                assert(j->in_dbus_queue);

                bus_job_send_change_signal(j);
                n++;

                if (budget != UINT_MAX)
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

static bool manager_process_barrier_fd(char * const *tags, FDSet *fds) {

        /* nothing else must be sent when using BARRIER=1 */
        if (strv_contains(tags, "BARRIER=1")) {
                if (strv_length(tags) != 1)
                        log_warning("Extra notification messages sent with BARRIER=1, ignoring everything.");
                else if (fdset_size(fds) != 1)
                        log_warning("Got incorrect number of fds with BARRIER=1, closing them.");

                /* Drop the message if BARRIER=1 was found */
                return true;
        }

        return false;
}

static void manager_invoke_notify_message(
                Manager *m,
                Unit *u,
                const struct ucred *ucred,
                char * const *tags,
                FDSet *fds) {

        assert(m);
        assert(u);
        assert(ucred);
        assert(tags);

        if (u->notifygen == m->notifygen) /* Already invoked on this same unit in this same iteration? */
                return;
        u->notifygen = m->notifygen;

        if (UNIT_VTABLE(u)->notify_message)
                UNIT_VTABLE(u)->notify_message(u, ucred, tags, fds);

        else if (DEBUG_LOGGING) {
                _cleanup_free_ char *buf = NULL, *x = NULL, *y = NULL;

                buf = strv_join(tags, ", ");
                if (buf)
                        x = ellipsize(buf, 20, 90);
                if (x)
                        y = cescape(x);

                log_unit_debug(u, "Got notification message \"%s\", ignoring.", strnull(y));
        }
}

static int manager_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {

        _cleanup_fdset_free_ FDSet *fds = NULL;
        Manager *m = ASSERT_PTR(userdata);
        char buf[NOTIFY_BUFFER_MAX+1];
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)) control;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        struct cmsghdr *cmsg;
        struct ucred *ucred = NULL;
        _cleanup_free_ Unit **array_copy = NULL;
        _cleanup_strv_free_ char **tags = NULL;
        Unit *u1, *u2, **array;
        int r, *fd_array = NULL;
        size_t n_fds = 0;
        bool found = false;
        ssize_t n;

        assert(m->notify_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        n = recvmsg_safe(m->notify_fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC|MSG_TRUNC);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0; /* Spurious wakeup, try again */
        if (n == -EXFULL) {
                log_warning("Got message with truncated control data (too many fds sent?), ignoring.");
                return 0;
        }
        if (n < 0)
                /* If this is any other, real error, then stop processing this socket. This of course means
                 * we won't take notification messages anymore, but that's still better than busy looping:
                 * being woken up over and over again, but being unable to actually read the message from the
                 * socket. */
                return log_error_errno(n, "Failed to receive notification message: %m");

        CMSG_FOREACH(cmsg, &msghdr)
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {

                        assert(!fd_array);
                        fd_array = CMSG_TYPED_DATA(cmsg, int);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                           cmsg->cmsg_type == SCM_CREDENTIALS &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        assert(!ucred);
                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
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

        /* As extra safety check, let's make sure the string we get doesn't contain embedded NUL bytes.
         * We permit one trailing NUL byte in the message, but don't expect it. */
        if (n > 1 && memchr(buf, 0, n-1)) {
                log_warning("Received notify message with embedded NUL bytes. Ignoring.");
                return 0;
        }

        /* Make sure it's NUL-terminated, then parse it to obtain the tags list. */
        buf[n] = 0;
        tags = strv_split_newlines(buf);
        if (!tags) {
                log_oom();
                return 0;
        }

        /* Possibly a barrier fd, let's see. */
        if (manager_process_barrier_fd(tags, fds)) {
                log_debug("Received barrier notification message from PID " PID_FMT ".", ucred->pid);
                return 0;
        }

        /* Increase the generation counter used for filtering out duplicate unit invocations. */
        m->notifygen++;

        /* Generate lookup key from the PID (we have no pidfd here, after all) */
        PidRef pidref = PIDREF_MAKE_FROM_PID(ucred->pid);

        /* Notify every unit that might be interested, which might be multiple. */
        u1 = manager_get_unit_by_pidref_cgroup(m, &pidref);
        u2 = hashmap_get(m->watch_pids, &pidref);
        array = hashmap_get(m->watch_pids_more, &pidref);
        if (array) {
                size_t k = 0;

                while (array[k])
                        k++;

                array_copy = newdup(Unit*, array, k+1);
                if (!array_copy)
                        log_oom();
        }
        /* And now invoke the per-unit callbacks. Note that manager_invoke_notify_message() will handle
         * duplicate units make sure we only invoke each unit's handler once. */
        if (u1) {
                manager_invoke_notify_message(m, u1, ucred, tags, fds);
                found = true;
        }
        if (u2) {
                manager_invoke_notify_message(m, u2, ucred, tags, fds);
                found = true;
        }
        if (array_copy)
                for (size_t i = 0; array_copy[i]; i++) {
                        manager_invoke_notify_message(m, array_copy[i], ucred, tags, fds);
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
        Manager *m = ASSERT_PTR(userdata);
        siginfo_t si = {};
        int r;

        assert(source);

        /* First we call waitid() for a PID and do not reap the zombie. That way we can still access
         * /proc/$PID for it while it is a zombie. */

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

                (void) pid_get_comm(si.si_pid, &name);

                log_debug("Child "PID_FMT" (%s) died (code=%s, status=%i/%s)",
                          si.si_pid, strna(name),
                          sigchld_code_to_string(si.si_code),
                          si.si_status,
                          strna(si.si_code == CLD_EXITED
                                ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)
                                : signal_to_string(si.si_status)));

                /* Increase the generation counter used for filtering out duplicate unit invocations */
                m->sigchldgen++;

                /* We look this up by a PidRef that only consists of the PID. After all we couldn't create a
                 * pidfd here any more even if we wanted (since the process just exited). */
                PidRef pidref = PIDREF_MAKE_FROM_PID(si.si_pid);

                /* And now figure out the unit this belongs to, it might be multiple... */
                u1 = manager_get_unit_by_pidref_cgroup(m, &pidref);
                u2 = hashmap_get(m->watch_pids, &pidref);
                array = hashmap_get(m->watch_pids_more, &pidref);
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

                        /* We check if systemd-oomd performed a kill so that we log and notify appropriately */
                        (void) unit_check_oomd_kill(u1);

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

static void manager_start_special(Manager *m, const char *name, JobMode mode) {
        Job *job;

        if (manager_add_job_by_name_and_warn(m, JOB_START, name, mode, NULL, &job) < 0)
                return;

        const char *s = unit_status_string(job->unit, NULL);

        log_info("Activating special unit %s...", s);

        sd_notifyf(false,
                   "STATUS=Activating special unit %s...", s);
        m->status_ready = false;
}

static void manager_handle_ctrl_alt_del(Manager *m) {
        /* If the user presses C-A-D more than
         * 7 times within 2s, we reboot/shutdown immediately,
         * unless it was disabled in system.conf */

        if (ratelimit_below(&m->ctrl_alt_del_ratelimit) || m->cad_burst_action == EMERGENCY_ACTION_NONE)
                manager_start_special(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE_IRREVERSIBLY);
        else
                emergency_action(m, m->cad_burst_action, EMERGENCY_ACTION_WARN, NULL, -1,
                                "Ctrl-Alt-Del was pressed more than 7 times within 2s");
}

static int manager_dispatch_signal_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        ssize_t n;
        struct signalfd_siginfo sfsi;
        int r;

        assert(m->signal_fd == fd);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected events from signal file descriptor.");
                return 0;
        }

        n = read(m->signal_fd, &sfsi, sizeof(sfsi));
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                /* We return an error here, which will kill this handler,
                 * to avoid a busy loop on read error. */
                return log_error_errno(errno, "Reading from signal fd failed: %m");
        }
        if (n != sizeof(sfsi)) {
                log_warning("Truncated read from signal fd (%zi bytes), ignoring!", n);
                return 0;
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
                        manager_start_special(m, SPECIAL_EXIT_TARGET, JOB_REPLACE_IRREVERSIBLY);
                break;

        case SIGWINCH:
                /* This is a nop on non-init */
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_special(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                break;

        case SIGPWR:
                /* This is a nop on non-init */
                if (MANAGER_IS_SYSTEM(m))
                        manager_start_special(m, SPECIAL_SIGPWR_TARGET, JOB_REPLACE);

                break;

        case SIGUSR1:
                if (manager_dbus_is_running(m, false)) {
                        log_info("Trying to reconnect to bus...");

                        (void) bus_init_api(m);

                        if (MANAGER_IS_SYSTEM(m))
                                (void) bus_init_system(m);
                } else
                        manager_start_special(m, SPECIAL_DBUS_SERVICE, JOB_REPLACE);

                break;

        case SIGUSR2: {
                _cleanup_free_ char *dump = NULL;

                r = manager_get_dump_string(m, /* patterns= */ NULL, &dump);
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
                        [0] = { SPECIAL_DEFAULT_TARGET,     JOB_ISOLATE },
                        [1] = { SPECIAL_RESCUE_TARGET,      JOB_ISOLATE },
                        [2] = { SPECIAL_EMERGENCY_TARGET,   JOB_ISOLATE },
                        [3] = { SPECIAL_HALT_TARGET,        JOB_REPLACE_IRREVERSIBLY },
                        [4] = { SPECIAL_POWEROFF_TARGET,    JOB_REPLACE_IRREVERSIBLY },
                        [5] = { SPECIAL_REBOOT_TARGET,      JOB_REPLACE_IRREVERSIBLY },
                        [6] = { SPECIAL_KEXEC_TARGET,       JOB_REPLACE_IRREVERSIBLY },
                        [7] = { SPECIAL_SOFT_REBOOT_TARGET, JOB_REPLACE_IRREVERSIBLY },
                };

                /* Starting SIGRTMIN+13, so that target halt and system halt are 10 apart */
                static const ManagerObjective objective_table[] = {
                        [0] = MANAGER_HALT,
                        [1] = MANAGER_POWEROFF,
                        [2] = MANAGER_REBOOT,
                        [3] = MANAGER_KEXEC,
                        [4] = MANAGER_SOFT_REBOOT,
                };

                if ((int) sfsi.ssi_signo >= SIGRTMIN+0 &&
                    (int) sfsi.ssi_signo < SIGRTMIN+(int) ELEMENTSOF(target_table)) {
                        int idx = (int) sfsi.ssi_signo - SIGRTMIN;
                        manager_start_special(m, target_table[idx].target, target_table[idx].mode);
                        break;
                }

                if ((int) sfsi.ssi_signo >= SIGRTMIN+13 &&
                    (int) sfsi.ssi_signo < SIGRTMIN+13+(int) ELEMENTSOF(objective_table)) {
                        m->objective = objective_table[sfsi.ssi_signo - SIGRTMIN - 13];
                        break;
                }

                switch (sfsi.ssi_signo - SIGRTMIN) {

                case 18: {
                        bool generic = false;

                        if (sfsi.ssi_code != SI_QUEUE)
                                generic = true;
                        else {
                                /* Override a few select commands by our own PID1-specific logic */

                                switch (sfsi.ssi_int) {

                                case _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE..._COMMON_SIGNAL_COMMAND_LOG_LEVEL_END:
                                        manager_override_log_level(m, sfsi.ssi_int - _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE);
                                        break;

                                case COMMON_SIGNAL_COMMAND_CONSOLE:
                                        manager_override_log_target(m, LOG_TARGET_CONSOLE);
                                        break;

                                case COMMON_SIGNAL_COMMAND_JOURNAL:
                                        manager_override_log_target(m, LOG_TARGET_JOURNAL);
                                        break;

                                case COMMON_SIGNAL_COMMAND_KMSG:
                                        manager_override_log_target(m, LOG_TARGET_KMSG);
                                        break;

                                case COMMON_SIGNAL_COMMAND_NULL:
                                        manager_override_log_target(m, LOG_TARGET_NULL);
                                        break;

                                case MANAGER_SIGNAL_COMMAND_DUMP_JOBS: {
                                        _cleanup_free_ char *dump_jobs = NULL;

                                        r = manager_get_dump_jobs_string(m, /* patterns= */ NULL, "  ", &dump_jobs);
                                        if (r < 0) {
                                                log_warning_errno(errno, "Failed to acquire manager jobs dump: %m");
                                                break;
                                        }

                                        log_dump(LOG_INFO, dump_jobs);
                                        break;
                                }

                                default:
                                        generic = true;
                                }
                        }

                        if (generic)
                                return sigrtmin18_handler(source, &sfsi, NULL);

                        break;
                }

                case 20:
                        manager_override_show_status(m, SHOW_STATUS_YES, "signal");
                        break;

                case 21:
                        manager_override_show_status(m, SHOW_STATUS_NO, "signal");
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

                case 25:
                        m->objective = MANAGER_REEXECUTE;
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
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;

        log_struct(LOG_DEBUG,
                   "MESSAGE_ID=" SD_MESSAGE_TIME_CHANGE_STR,
                   LOG_MESSAGE("Time has been changed"));

        /* Restart the watch */
        (void) manager_setup_time_change(m);

        HASHMAP_FOREACH(u, m->units)
                if (UNIT_VTABLE(u)->time_change)
                        UNIT_VTABLE(u)->time_change(u);

        return 0;
}

static int manager_dispatch_timezone_change(
                sd_event_source *source,
                const struct inotify_event *e,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int changed;
        Unit *u;

        log_debug("inotify event for /etc/localtime");

        changed = manager_read_timezone_stat(m);
        if (changed <= 0)
                return changed;

        /* Something changed, restart the watch, to ensure we watch the new /etc/localtime if it changed */
        (void) manager_setup_timezone_change(m);

        /* Read the new timezone */
        tzset();

        log_debug("Timezone has been changed (now: %s).", tzname[daylight]);

        HASHMAP_FOREACH(u, m->units)
                if (UNIT_VTABLE(u)->timezone_change)
                        UNIT_VTABLE(u)->timezone_change(u);

        return 0;
}

static int manager_dispatch_idle_pipe_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(m->idle_pipe[2] == fd);

        /* There's at least one Type=idle child that just gave up on us waiting for the boot process to
         * complete. Let's now turn off any further console output if there's at least one service that needs
         * console access, so that from now on our own output should not spill into that service's output
         * anymore. After all, we support Type=idle only to beautify console output and it generally is set
         * on services that want to own the console exclusively without our interference. */
        m->no_console_output = m->n_on_console > 0;

        /* Acknowledge the child's request, and let all other children know too that they shouldn't wait
         * any longer by closing the pipes towards them, which is what they are waiting for. */
        manager_close_idle_pipe(m);

        return 0;
}

static int manager_dispatch_jobs_in_progress(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(source);

        manager_print_jobs_in_progress(m);

        r = sd_event_source_set_time_relative(source, JOBS_IN_PROGRESS_PERIOD_USEC);
        if (r < 0)
                return r;

        return sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
}

int manager_loop(Manager *m) {
        RateLimit rl = { .interval = 1*USEC_PER_SEC, .burst = 50000 };
        int r;

        assert(m);
        assert(m->objective == MANAGER_OK); /* Ensure manager_startup() has been called */

        manager_check_finished(m);

        /* There might still be some zombies hanging around from before we were exec()'ed. Let's reap them. */
        r = sd_event_source_set_enabled(m->sigchld_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SIGCHLD event source: %m");

        while (m->objective == MANAGER_OK) {

                (void) watchdog_ping();

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

                if (manager_dispatch_start_when_upheld_queue(m) > 0)
                        continue;

                if (manager_dispatch_stop_when_bound_queue(m) > 0)
                        continue;

                if (manager_dispatch_stop_when_unneeded_queue(m) > 0)
                        continue;

                if (manager_dispatch_release_resources_queue(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

                /* Sleep for watchdog runtime wait time */
                r = sd_event_run(m->event, watchdog_runtime_wait());
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

        /* Permit addressing units by invocation ID: if the passed bus path is suffixed by a 128-bit ID then
         * we use it as invocation ID. */
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

        r = unit_name_to_prefix_and_instance(u->id, &p);
        if (r < 0) {
                log_warning_errno(r, "Failed to extract prefix and instance of unit name, ignoring: %m");
                return;
        }

        msg = strjoina("unit=", p);
        if (audit_log_user_comm_message(audit_fd, type, msg, "systemd", NULL, NULL, NULL, success) < 0) {
                if (ERRNO_IS_PRIVILEGE(errno)) {
                        /* We aren't allowed to send audit messages?  Then let's not retry again. */
                        log_debug_errno(errno, "Failed to send audit message, closing audit socket: %m");
                        close_audit_fd();
                } else
                        log_warning_errno(errno, "Failed to send audit message, ignoring: %m");
        }
#endif

}

void manager_send_unit_plymouth(Manager *m, Unit *u) {
        _cleanup_free_ char *message = NULL;
        int c, r;

        /* Don't generate plymouth events if the service was already
         * started and we're just deserializing */
        if (MANAGER_IS_RELOADING(m))
                return;

        if (!MANAGER_IS_SYSTEM(m))
                return;

        if (detect_container() > 0)
                return;

        if (!UNIT_VTABLE(u)->notify_plymouth)
                return;

        c = asprintf(&message, "U\x02%c%s%c", (int) (strlen(u->id) + 1), u->id, '\x00');
        if (c < 0)
                return (void) log_oom();

        /* We set SOCK_NONBLOCK here so that we rather drop the message then wait for plymouth */
        r = plymouth_send_raw(message, c, SOCK_NONBLOCK);
        if (r < 0)
                log_full_errno(ERRNO_IS_NO_PLYMOUTH(r) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to communicate with plymouth: %m");
}

usec_t manager_get_watchdog(Manager *m, WatchdogType t) {
        assert(m);

        if (MANAGER_IS_USER(m))
                return USEC_INFINITY;

        if (m->watchdog_overridden[t] != USEC_INFINITY)
                return m->watchdog_overridden[t];

        return m->watchdog[t];
}

void manager_set_watchdog(Manager *m, WatchdogType t, usec_t timeout) {

        assert(m);

        if (MANAGER_IS_USER(m))
                return;

        if (m->watchdog[t] == timeout)
                return;

        if (m->watchdog_overridden[t] == USEC_INFINITY) {
                if (t == WATCHDOG_RUNTIME)
                        (void) watchdog_setup(timeout);
                else if (t == WATCHDOG_PRETIMEOUT)
                        (void) watchdog_setup_pretimeout(timeout);
        }

        m->watchdog[t] = timeout;
}

void manager_override_watchdog(Manager *m, WatchdogType t, usec_t timeout) {
        usec_t usec;

        assert(m);

        if (MANAGER_IS_USER(m))
                return;

        if (m->watchdog_overridden[t] == timeout)
                return;

        usec = timeout == USEC_INFINITY ? m->watchdog[t] : timeout;
        if (t == WATCHDOG_RUNTIME)
                (void) watchdog_setup(usec);
        else if (t == WATCHDOG_PRETIMEOUT)
                (void) watchdog_setup_pretimeout(usec);

        m->watchdog_overridden[t] = timeout;
}

int manager_set_watchdog_pretimeout_governor(Manager *m, const char *governor) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);

        if (MANAGER_IS_USER(m))
                return 0;

        if (streq_ptr(m->watchdog_pretimeout_governor, governor))
                return 0;

        p = strdup(governor);
        if (!p)
                return -ENOMEM;

        r = watchdog_setup_pretimeout_governor(governor);
        if (r < 0)
                return r;

        return free_and_replace(m->watchdog_pretimeout_governor, p);
}

int manager_override_watchdog_pretimeout_governor(Manager *m, const char *governor) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);

        if (MANAGER_IS_USER(m))
                return 0;

        if (streq_ptr(m->watchdog_pretimeout_governor_overridden, governor))
                return 0;

        p = strdup(governor);
        if (!p)
                return -ENOMEM;

        r = watchdog_setup_pretimeout_governor(governor);
        if (r < 0)
                return r;

        return free_and_replace(m->watchdog_pretimeout_governor_overridden, p);
}

int manager_reload(Manager *m) {
        _unused_ _cleanup_(manager_reloading_stopp) Manager *reloading = NULL;
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
         * it. */

        manager_clear_jobs_and_units(m);
        lookup_paths_flush_generator(&m->lookup_paths);
        lookup_paths_free(&m->lookup_paths);
        exec_shared_runtime_vacuum(m);
        dynamic_user_vacuum(m, false);
        m->uid_refs = hashmap_free(m->uid_refs);
        m->gid_refs = hashmap_free(m->gid_refs);

        r = lookup_paths_init_or_warn(&m->lookup_paths, m->runtime_scope, 0, NULL);
        if (r < 0)
                return r;

        (void) manager_run_environment_generators(m);
        (void) manager_run_generators(m);

        lookup_paths_log(&m->lookup_paths);

        /* We flushed out generated files, for which we don't watch mtime, so we should flush the old map. */
        manager_free_unit_name_maps(m);
        m->unit_file_state_outdated = false;

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

        /* Clean up deserialized tracked clients */
        m->deserialized_subscribed = strv_free(m->deserialized_subscribed);

        /* Consider the reload process complete now. */
        assert(m->n_reloading > 0);
        m->n_reloading--;

        manager_ready(m);

        m->send_reloading_done = true;
        return 0;
}

void manager_reset_failed(Manager *m) {
        Unit *u;

        assert(m);

        HASHMAP_FOREACH(u, m->units)
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
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        if (MANAGER_IS_TEST_RUN(m))
                return;

        if (MANAGER_IS_SYSTEM(m) && detect_container() <= 0) {
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
                        size = strpcpyf(&p, size, "%s (firmware) + ", FORMAT_TIMESPAN(firmware_usec, USEC_PER_MSEC));
                if (loader_usec > 0)
                        size = strpcpyf(&p, size, "%s (loader) + ", FORMAT_TIMESPAN(loader_usec, USEC_PER_MSEC));

                if (dual_timestamp_is_set(&m->timestamps[MANAGER_TIMESTAMP_INITRD])) {

                        /* The initrd case on bare-metal */
                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_INITRD].monotonic;

                        log_struct(LOG_INFO,
                                   "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR,
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "INITRD_USEC="USEC_FMT, initrd_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                               buf,
                                               FORMAT_TIMESPAN(kernel_usec, USEC_PER_MSEC),
                                               FORMAT_TIMESPAN(initrd_usec, USEC_PER_MSEC),
                                               FORMAT_TIMESPAN(userspace_usec, USEC_PER_MSEC),
                                               FORMAT_TIMESPAN(total_usec, USEC_PER_MSEC)));
                } else {
                        /* The initrd-less case on bare-metal */

                        kernel_usec = m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic - m->timestamps[MANAGER_TIMESTAMP_KERNEL].monotonic;
                        initrd_usec = 0;

                        log_struct(LOG_INFO,
                                   "MESSAGE_ID=" SD_MESSAGE_STARTUP_FINISHED_STR,
                                   "KERNEL_USEC="USEC_FMT, kernel_usec,
                                   "USERSPACE_USEC="USEC_FMT, userspace_usec,
                                   LOG_MESSAGE("Startup finished in %s%s (kernel) + %s (userspace) = %s.",
                                               buf,
                                               FORMAT_TIMESPAN(kernel_usec, USEC_PER_MSEC),
                                               FORMAT_TIMESPAN(userspace_usec, USEC_PER_MSEC),
                                               FORMAT_TIMESPAN(total_usec, USEC_PER_MSEC)));
                }
        } else {
                /* The container and --user case */
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->timestamps[MANAGER_TIMESTAMP_FINISH].monotonic - m->timestamps[MANAGER_TIMESTAMP_USERSPACE].monotonic;

                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_USER_STARTUP_FINISHED_STR,
                           "USERSPACE_USEC="USEC_FMT, userspace_usec,
                           LOG_MESSAGE("Startup finished in %s.",
                                       FORMAT_TIMESPAN(total_usec, USEC_PER_MSEC)));
        }

        bus_manager_send_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        log_taint_string(m);
}

static void user_manager_send_ready(Manager *m) {
        int r;

        assert(m);

        /* We send READY=1 on reaching basic.target only when running in --user mode. */
        if (!MANAGER_IS_USER(m) || m->ready_sent)
                return;

        r = sd_notify(false,
                      "READY=1\n"
                      "STATUS=Reached " SPECIAL_BASIC_TARGET ".");
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        m->ready_sent = true;
        m->status_ready = false;
}

static void manager_send_ready(Manager *m) {
        int r;

        if (m->ready_sent && m->status_ready)
                /* Skip the notification if nothing changed. */
                return;

        r = sd_notify(false,
                      "READY=1\n"
                      "STATUS=Ready.");
        if (r < 0)
                log_full_errno(m->ready_sent ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to send readiness notification, ignoring: %m");

        m->ready_sent = m->status_ready = true;
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
        user_manager_send_ready(m);

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
                        (void) sd_event_source_set_time(m->jobs_in_progress_event_source,
                                                        manager_watch_jobs_next_time(m));
                return;
        }

        /* The jobs hashmap tends to grow a lot during boot, and then it's not reused until shutdown. Let's
           kill the hashmap if it is relatively large. */
        if (hashmap_buckets(m->jobs) > hashmap_size(m->units) / 10)
                m->jobs = hashmap_free(m->jobs);

        manager_send_ready(m);

        /* Notify Type=idle units that we are done now */
        manager_close_idle_pipe(m);

        if (MANAGER_IS_FINISHED(m))
                return;

        manager_flip_auto_status(m, false, "boot finished");

        /* Turn off confirm spawn now */
        m->confirm_spawn = NULL;

        /* No need to update ask password status when we're going non-interactive */
        manager_close_ask_password(m);

        /* This is no longer the first boot */
        manager_set_first_boot(m, false);

        dual_timestamp_now(m->timestamps + MANAGER_TIMESTAMP_FINISH);

        manager_notify_finished(m);

        manager_invalidate_startup_units(m);
}

void manager_send_reloading(Manager *m) {
        assert(m);

        /* Let whoever invoked us know that we are now reloading */
        (void) sd_notifyf(/* unset= */ false,
                          "RELOADING=1\n"
                          "MONOTONIC_USEC=" USEC_FMT "\n", now(CLOCK_MONOTONIC));

        /* And ensure that we'll send READY=1 again as soon as we are ready again */
        m->ready_sent = false;
}

static bool generator_path_any(const char* const* paths) {
        bool found = false;

        /* Optimize by skipping the whole process by not creating output directories
         * if no generators are found. */
        STRV_FOREACH(path, paths)
                if (access(*path, F_OK) == 0)
                        found = true;
                else if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open generator directory %s: %m", *path);

        return found;
}

static int manager_run_environment_generators(Manager *m) {
        char **tmp = NULL; /* this is only used in the forked process, no cleanup here */
        _cleanup_strv_free_ char **paths = NULL;
        void* args[] = {
                [STDOUT_GENERATE] = &tmp,
                [STDOUT_COLLECT] = &tmp,
                [STDOUT_CONSUME] = &m->transient_environment,
        };
        int r;

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_ENV_GENERATORS))
                return 0;

        paths = env_generator_binary_paths(m->runtime_scope);
        if (!paths)
                return log_oom();

        if (!generator_path_any((const char* const*) paths))
                return 0;

        WITH_UMASK(0022)
                r = execute_directories((const char* const*) paths, DEFAULT_TIMEOUT_USEC, gather_environment,
                                        args, NULL, m->transient_environment,
                                        EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS | EXEC_DIR_SET_SYSTEMD_EXEC_PID);
        return r;
}

static int build_generator_environment(Manager *m, char ***ret) {
        _cleanup_strv_free_ char **nl = NULL;
        Virtualization v;
        ConfidentialVirtualization cv;
        int r;

        assert(m);
        assert(ret);

        /* Generators oftentimes want to know some basic facts about the environment they run in, in order to
         * adjust generated units to that. Let's pass down some bits of information that are easy for us to
         * determine (but a bit harder for generator scripts to determine), as environment variables. */

        nl = strv_copy(m->transient_environment);
        if (!nl)
                return -ENOMEM;

        r = strv_env_assign(&nl, "SYSTEMD_SCOPE", runtime_scope_to_string(m->runtime_scope));
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(m)) {
                /* Note that $SYSTEMD_IN_INITRD may be used to override the initrd detection in much of our
                 * codebase. This is hence more than purely informational. It will shortcut detection of the
                 * initrd state if generators invoke our own tools. But that's OK, as it would come to the
                 * same results (hopefully). */
                r = strv_env_assign(&nl, "SYSTEMD_IN_INITRD", one_zero(in_initrd()));
                if (r < 0)
                        return r;

                if (m->first_boot >= 0) {
                        r = strv_env_assign(&nl, "SYSTEMD_FIRST_BOOT", one_zero(m->first_boot));
                        if (r < 0)
                                return r;
                }
        }

        v = detect_virtualization();
        if (v < 0)
                log_debug_errno(v, "Failed to detect virtualization, ignoring: %m");
        else if (v > 0) {
                const char *s;

                s = strjoina(VIRTUALIZATION_IS_VM(v) ? "vm:" :
                             VIRTUALIZATION_IS_CONTAINER(v) ? "container:" : ":",
                             virtualization_to_string(v));

                r = strv_env_assign(&nl, "SYSTEMD_VIRTUALIZATION", s);
                if (r < 0)
                        return r;
        }

        cv = detect_confidential_virtualization();
        if (cv < 0)
                log_debug_errno(cv, "Failed to detect confidential virtualization, ignoring: %m");
        else if (cv > 0) {
                r = strv_env_assign(&nl, "SYSTEMD_CONFIDENTIAL_VIRTUALIZATION", confidential_virtualization_to_string(cv));
                if (r < 0)
                        return r;
        }

        r = strv_env_assign(&nl, "SYSTEMD_ARCHITECTURE", architecture_to_string(uname_architecture()));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nl);
        return 0;
}

static int manager_execute_generators(Manager *m, char **paths, bool remount_ro) {
        _cleanup_strv_free_ char **ge = NULL;
        const char *argv[] = {
                NULL, /* Leave this empty, execute_directory() will fill something in */
                m->lookup_paths.generator,
                m->lookup_paths.generator_early,
                m->lookup_paths.generator_late,
                NULL,
        };
        int r;

        r = build_generator_environment(m, &ge);
        if (r < 0)
                return log_error_errno(r, "Failed to build generator environment: %m");

        if (remount_ro) {
                /* Remount most of the filesystem tree read-only. We leave /sys/ as-is, because our code
                 * checks whether it is read-only to detect containerized execution environments. We leave
                 * /run/ as-is too, because that's where our output goes. We also leave /proc/ and /dev/shm/
                 * because they're API, and /tmp/ that safe_fork() mounted for us.
                 */
                r = bind_remount_recursive("/", MS_RDONLY, MS_RDONLY,
                                           STRV_MAKE("/sys", "/run", "/proc", "/dev/shm", "/tmp"));
                if (r < 0)
                        log_warning_errno(r, "Read-only bind remount failed, ignoring: %m");
        }

        BLOCK_WITH_UMASK(0022);
        return execute_directories(
                        (const char* const*) paths,
                        DEFAULT_TIMEOUT_USEC,
                        /* callbacks= */ NULL, /* callback_args= */ NULL,
                        (char**) argv,
                        ge,
                        EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS | EXEC_DIR_SET_SYSTEMD_EXEC_PID);
}

static int manager_run_generators(Manager *m) {
        ForkFlags flags = FORK_RESET_SIGNALS | FORK_WAIT | FORK_NEW_MOUNTNS | FORK_MOUNTNS_SLAVE;
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m) && !(m->test_run_flags & MANAGER_TEST_RUN_GENERATORS))
                return 0;

        paths = generator_binary_paths(m->runtime_scope);
        if (!paths)
                return log_oom();

        if (!generator_path_any((const char* const*) paths))
                return 0;

        r = lookup_paths_mkdir_generator(&m->lookup_paths);
        if (r < 0) {
                log_error_errno(r, "Failed to create generator directories: %m");
                goto finish;
        }

        /* If we are the system manager, we fork and invoke the generators in a sanitized mount namespace. If
         * we are the user manager, let's just execute the generators directly. We might not have the
         * necessary privileges, and the system manager has already mounted /tmp/ and everything else for us.
         */
        if (MANAGER_IS_USER(m)) {
                r = manager_execute_generators(m, paths, /* remount_ro= */ false);
                goto finish;
        }

        /* On some systems /tmp/ doesn't exist, and on some other systems we cannot create it at all. Avoid
         * trying to mount a private tmpfs on it as there's no one size fits all. */
        if (is_dir("/tmp", /* follow= */ false) > 0)
                flags |= FORK_PRIVATE_TMP;

        r = safe_fork("(sd-gens)", flags, NULL);
        if (r == 0) {
                r = manager_execute_generators(m, paths, /* remount_ro= */ true);
                _exit(r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE);
        }
        if (r < 0) {
                if (!ERRNO_IS_PRIVILEGE(r) && r != -EINVAL) {
                        log_error_errno(r, "Failed to fork off sandboxing environment for executing generators: %m");
                        goto finish;
                }

                /* Failed to fork with new mount namespace? Maybe, running in a container environment with
                 * seccomp or without capability.
                 *
                 * We also allow -EINVAL to allow running without CLONE_NEWNS.
                 *
                 * Also, when running on non-native userland architecture via systemd-nspawn and
                 * qemu-user-static QEMU-emulator, clone() with CLONE_NEWNS fails with EINVAL, see
                 * https://github.com/systemd/systemd/issues/28901.
                 */
                log_debug_errno(r,
                                "Failed to fork off sandboxing environment for executing generators. "
                                "Falling back to execute generators without sandboxing: %m");
                r = manager_execute_generators(m, paths, /* remount_ro= */ false);
        }

finish:
        lookup_paths_trim_generator(&m->lookup_paths);
        return r;
}

int manager_transient_environment_add(Manager *m, char **plus) {
        char **a;

        assert(m);

        if (strv_isempty(plus))
                return 0;

        a = strv_env_merge(m->transient_environment, plus);
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
                b = strv_env_merge(l, plus);
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

        l = strv_env_merge(m->transient_environment, m->client_environment);
        if (!l)
                return -ENOMEM;

        *ret = l;
        return 0;
}

int manager_set_unit_defaults(Manager *m, const UnitDefaults *defaults) {
        _cleanup_free_ char *label = NULL;
        struct rlimit *rlimit[_RLIMIT_MAX];
        int r;

        assert(m);
        assert(defaults);

        if (streq_ptr(defaults->smack_process_label, "/"))
                label = NULL;
        else  {
                const char *l = defaults->smack_process_label;
#ifdef SMACK_DEFAULT_PROCESS_LABEL
                if (!l)
                        l = SMACK_DEFAULT_PROCESS_LABEL;
#endif
                if (l) {
                        label = strdup(l);
                        if (!label)
                                return -ENOMEM;
                } else
                        label = NULL;
        }

        r = rlimit_copy_all(rlimit, defaults->rlimit);
        if (r < 0)
                return r;

        m->defaults.std_output = defaults->std_output;
        m->defaults.std_error = defaults->std_error;

        m->defaults.restart_usec = defaults->restart_usec;
        m->defaults.timeout_start_usec = defaults->timeout_start_usec;
        m->defaults.timeout_stop_usec = defaults->timeout_stop_usec;
        m->defaults.timeout_abort_usec = defaults->timeout_abort_usec;
        m->defaults.timeout_abort_set = defaults->timeout_abort_set;
        m->defaults.device_timeout_usec = defaults->device_timeout_usec;

        m->defaults.start_limit_interval = defaults->start_limit_interval;
        m->defaults.start_limit_burst = defaults->start_limit_burst;

        m->defaults.cpu_accounting = defaults->cpu_accounting;
        m->defaults.memory_accounting = defaults->memory_accounting;
        m->defaults.io_accounting = defaults->io_accounting;
        m->defaults.blockio_accounting = defaults->blockio_accounting;
        m->defaults.tasks_accounting = defaults->tasks_accounting;
        m->defaults.ip_accounting = defaults->ip_accounting;

        m->defaults.tasks_max = defaults->tasks_max;
        m->defaults.timer_accuracy_usec = defaults->timer_accuracy_usec;

        m->defaults.oom_policy = defaults->oom_policy;
        m->defaults.oom_score_adjust = defaults->oom_score_adjust;
        m->defaults.oom_score_adjust_set = defaults->oom_score_adjust_set;

        m->defaults.memory_pressure_watch = defaults->memory_pressure_watch;
        m->defaults.memory_pressure_threshold_usec = defaults->memory_pressure_threshold_usec;

        free_and_replace(m->defaults.smack_process_label, label);
        rlimit_free_all(m->defaults.rlimit);
        memcpy(m->defaults.rlimit, rlimit, sizeof(struct rlimit*) * _RLIMIT_MAX);

        return 0;
}

void manager_recheck_dbus(Manager *m) {
        assert(m);

        /* Connects to the bus if the dbus service and socket are running. If we are running in user mode
         * this is all it does. In system mode we'll also connect to the system bus (which will most likely
         * just reuse the connection of the API bus). That's because the system bus after all runs as service
         * of the system instance, while in the user instance we can assume it's already there. */

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

void disable_printk_ratelimit(void) {
        /* Disable kernel's printk ratelimit.
         *
         * Logging to /dev/kmsg is most useful during early boot and shutdown, where normal logging
         * mechanisms are not available. The semantics of this sysctl are such that any kernel command-line
         * setting takes precedence. */
        int r;

        r = sysctl_write("kernel/printk_devkmsg", "on");
        if (r < 0)
                log_debug_errno(r, "Failed to set sysctl kernel.printk_devkmsg=on: %m");
}

void manager_recheck_journal(Manager *m) {

        assert(m);

        /* Don't bother with this unless we are in the special situation of being PID 1 */
        if (getpid_cached() != 1)
                return;

        /* Don't check this while we are reloading, things might still change */
        if (MANAGER_IS_RELOADING(m))
                return;

        /* The journal is fully and entirely up? If so, let's permit logging to it, if that's configured. If
         * the journal is down, don't ever log to it, otherwise we might end up deadlocking ourselves as we
         * might trigger an activation ourselves we can't fulfill. */
        log_set_prohibit_ipc(!manager_journal_is_running(m));
        log_open();
}

static ShowStatus manager_get_show_status(Manager *m) {
        assert(m);

        if (MANAGER_IS_USER(m))
                return _SHOW_STATUS_INVALID;

        if (m->show_status_overridden != _SHOW_STATUS_INVALID)
                return m->show_status_overridden;

        return m->show_status;
}

bool manager_get_show_status_on(Manager *m) {
        assert(m);

        return show_status_on(manager_get_show_status(m));
}

static void set_show_status_marker(bool b) {
        if (b)
                (void) touch("/run/systemd/show-status");
        else
                (void) unlink("/run/systemd/show-status");
}

void manager_set_show_status(Manager *m, ShowStatus mode, const char *reason) {
        assert(m);
        assert(reason);
        assert(mode >= 0 && mode < _SHOW_STATUS_MAX);

        if (MANAGER_IS_USER(m))
                return;

        if (mode == m->show_status)
                return;

        if (m->show_status_overridden == _SHOW_STATUS_INVALID) {
                bool enabled;

                enabled = show_status_on(mode);
                log_debug("%s (%s) showing of status (%s).",
                          enabled ? "Enabling" : "Disabling",
                          strna(show_status_to_string(mode)),
                          reason);

                set_show_status_marker(enabled);
        }

        m->show_status = mode;
}

void manager_override_show_status(Manager *m, ShowStatus mode, const char *reason) {
        assert(m);
        assert(mode < _SHOW_STATUS_MAX);

        if (MANAGER_IS_USER(m))
                return;

        if (mode == m->show_status_overridden)
                return;

        m->show_status_overridden = mode;

        if (mode == _SHOW_STATUS_INVALID)
                mode = m->show_status;

        log_debug("%s (%s) showing of status (%s).",
                  m->show_status_overridden != _SHOW_STATUS_INVALID ? "Overriding" : "Restoring",
                  strna(show_status_to_string(mode)),
                  reason);

        set_show_status_marker(show_status_on(mode));
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
         * assumed. New children will fall back to /dev/console though.
         *
         * Note: TTYs are devices that can come and go any time, and frequently aren't
         * available yet during early boot (consider a USB rs232 dongle...). If for any
         * reason the configured console is not ready, we fall back to the default
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

static bool manager_should_show_status(Manager *m, StatusType type) {
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

        if (type == STATUS_TYPE_NOTICE && m->show_status != SHOW_STATUS_NO)
                return true;

        return manager_get_show_status_on(m);
}

void manager_status_printf(Manager *m, StatusType type, const char *status, const char *format, ...) {
        va_list ap;

        /* If m is NULL, assume we're after shutdown and let the messages through. */

        if (m && !manager_should_show_status(m, type))
                return;

        /* XXX We should totally drop the check for ephemeral here
         * and thus effectively make 'Type=idle' pointless. */
        if (type == STATUS_TYPE_EPHEMERAL && m && m->n_on_console > 0)
                return;

        va_start(ap, format);
        status_vprintf(status, SHOW_STATUS_ELLIPSIZE|(type == STATUS_TYPE_EPHEMERAL ? SHOW_STATUS_EPHEMERAL : 0), format, ap);
        va_end(ap);
}

Set* manager_get_units_needing_mounts_for(Manager *m, const char *path, UnitMountDependencyType t) {
        assert(m);
        assert(path);
        assert(t >= 0 && t < _UNIT_MOUNT_DEPENDENCY_TYPE_MAX);

        if (path_equal(path, "/"))
                path = "";

        return hashmap_get(m->units_needing_mounts_for[t], path);
}

int manager_update_failed_units(Manager *m, Unit *u, bool failed) {
        unsigned size;
        int r;

        assert(m);
        assert(u->manager == m);

        size = set_size(m->failed_units);

        if (failed) {
                r = set_ensure_put(&m->failed_units, NULL, u);
                if (r < 0)
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

        /* Is the special shutdown target active or queued? If so, we are in shutdown state */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u && unit_active_or_pending(u))
                return MANAGER_STOPPING;

        /* Did we ever finish booting? If not then we are still starting up */
        if (!MANAGER_IS_FINISHED(m)) {

                u = manager_get_unit(m, SPECIAL_BASIC_TARGET);
                if (!u || !UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u)))
                        return MANAGER_INITIALIZING;

                return MANAGER_STARTING;
        }

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

static void manager_unref_uid_internal(
                Hashmap *uid_refs,
                uid_t uid,
                bool destroy_now,
                int (*_clean_ipc)(uid_t uid)) {

        uint32_t c, n;

        assert(uid_is_valid(uid));
        assert(_clean_ipc);

        /* A generic implementation, covering both manager_unref_uid() and manager_unref_gid(), under the
         * assumption that uid_t and gid_t are actually defined the same way, with the same validity rules.
         *
         * We store a hashmap where the key is the UID/GID and the value is a 32-bit reference counter, whose
         * highest bit is used as flag for marking UIDs/GIDs whose IPC objects to remove when the last
         * reference to the UID/GID is dropped. The flag is set to on, once at least one reference from a
         * unit where RemoveIPC= is set is added on a UID/GID. It is reset when the UID's/GID's reference
         * counter drops to 0 again. */

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        assert_cc(UID_INVALID == (uid_t) GID_INVALID);

        if (uid == 0) /* We don't keep track of root, and will never destroy it */
                return;

        c = PTR_TO_UINT32(hashmap_get(uid_refs, UID_TO_PTR(uid)));

        n = c & ~DESTROY_IPC_FLAG;
        assert(n > 0);
        n--;

        if (destroy_now && n == 0) {
                hashmap_remove(uid_refs, UID_TO_PTR(uid));

                if (c & DESTROY_IPC_FLAG) {
                        log_debug("%s " UID_FMT " is no longer referenced, cleaning up its IPC.",
                                  _clean_ipc == clean_ipc_by_uid ? "UID" : "GID",
                                  uid);
                        (void) _clean_ipc(uid);
                }
        } else {
                c = n | (c & DESTROY_IPC_FLAG);
                assert_se(hashmap_update(uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c)) >= 0);
        }
}

void manager_unref_uid(Manager *m, uid_t uid, bool destroy_now) {
        manager_unref_uid_internal(m->uid_refs, uid, destroy_now, clean_ipc_by_uid);
}

void manager_unref_gid(Manager *m, gid_t gid, bool destroy_now) {
        manager_unref_uid_internal(m->gid_refs, (uid_t) gid, destroy_now, clean_ipc_by_gid);
}

static int manager_ref_uid_internal(
                Hashmap **uid_refs,
                uid_t uid,
                bool clean_ipc) {

        uint32_t c, n;
        int r;

        assert(uid_refs);
        assert(uid_is_valid(uid));

        /* A generic implementation, covering both manager_ref_uid() and manager_ref_gid(), under the
         * assumption that uid_t and gid_t are actually defined the same way, with the same validity
         * rules. */

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
        return manager_ref_uid_internal(&m->uid_refs, uid, clean_ipc);
}

int manager_ref_gid(Manager *m, gid_t gid, bool clean_ipc) {
        return manager_ref_uid_internal(&m->gid_refs, (uid_t) gid, clean_ipc);
}

static void manager_vacuum_uid_refs_internal(
                Hashmap *uid_refs,
                int (*_clean_ipc)(uid_t uid)) {

        void *p, *k;

        assert(_clean_ipc);

        HASHMAP_FOREACH_KEY(p, k, uid_refs) {
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

                assert_se(hashmap_remove(uid_refs, k) == p);
        }
}

static void manager_vacuum_uid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m->uid_refs, clean_ipc_by_uid);
}

static void manager_vacuum_gid_refs(Manager *m) {
        manager_vacuum_uid_refs_internal(m->gid_refs, clean_ipc_by_gid);
}

static void manager_vacuum(Manager *m) {
        assert(m);

        /* Release any dynamic users no longer referenced */
        dynamic_user_vacuum(m, true);

        /* Release any references to UIDs/GIDs no longer referenced, and destroy any IPC owned by them */
        manager_vacuum_uid_refs(m);
        manager_vacuum_gid_refs(m);

        /* Release any runtimes no longer referenced */
        exec_shared_runtime_vacuum(m);
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

        /* Invoked whenever a child process succeeded resolving its user/group to use and sent us the
         * resulting UID/GID in a datagram. We parse the datagram here and pass it off to the unit, so that
         * it can add a reference to the UID/GID so that it can destroy the UID/GID's IPC objects when the
         * reference counter drops to 0. */

        l = recv(fd, &buffer, sizeof(buffer), MSG_DONTWAIT);
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
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

static int short_uid_range(const char *path) {
        _cleanup_(uid_range_freep) UidRange *p = NULL;
        int r;

        assert(path);

        /* Taint systemd if we the UID range assigned to this environment doesn't at least cover 0…65534,
         * i.e. from root to nobody. */

        r = uid_range_load_userns(&p, path);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to load %s: %m", path);

        return !uid_range_covers(p, 0, 65535);
}

char* manager_taint_string(const Manager *m) {
        /* Returns a "taint string", e.g. "local-hwclock:var-run-bad". Only things that are detected at
         * runtime should be tagged here. For stuff that is known during compilation, emit a warning in the
         * configuration phase. */

        assert(m);

        const char* stage[12] = {};
        size_t n = 0;

        _cleanup_free_ char *usrbin = NULL;
        if (readlink_malloc("/bin", &usrbin) < 0 || !PATH_IN_SET(usrbin, "usr/bin", "/usr/bin"))
                stage[n++] = "unmerged-usr";

        if (access("/proc/cgroups", F_OK) < 0)
                stage[n++] = "cgroups-missing";

        if (cg_all_unified() == 0)
                stage[n++] = "cgroupsv1";

        if (clock_is_localtime(NULL) > 0)
                stage[n++] = "local-hwclock";

        if (os_release_support_ended(NULL, /* quiet= */ true, NULL) > 0)
                stage[n++] = "support-ended";

        _cleanup_free_ char *destination = NULL;
        if (readlink_malloc("/var/run", &destination) < 0 ||
            !PATH_IN_SET(destination, "../run", "/run"))
                stage[n++] = "var-run-bad";

        _cleanup_free_ char *overflowuid = NULL, *overflowgid = NULL;
        if (read_one_line_file("/proc/sys/kernel/overflowuid", &overflowuid) >= 0 &&
            !streq(overflowuid, "65534"))
                stage[n++] = "overflowuid-not-65534";
        if (read_one_line_file("/proc/sys/kernel/overflowgid", &overflowgid) >= 0 &&
            !streq(overflowgid, "65534"))
                stage[n++] = "overflowgid-not-65534";

        struct utsname uts;
        assert_se(uname(&uts) >= 0);
        if (strverscmp_improved(uts.release, KERNEL_BASELINE_VERSION) < 0)
                stage[n++] = "old-kernel";

        if (short_uid_range("/proc/self/uid_map") > 0)
                stage[n++] = "short-uid-range";
        if (short_uid_range("/proc/self/gid_map") > 0)
                stage[n++] = "short-gid-range";

        assert(n < ELEMENTSOF(stage) - 1);  /* One extra for NULL terminator */

        return strv_join((char**) stage, ":");
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

int manager_allocate_idle_pipe(Manager *m) {
        int r;

        assert(m);

        if (m->idle_pipe[0] >= 0) {
                assert(m->idle_pipe[1] >= 0);
                assert(m->idle_pipe[2] >= 0);
                assert(m->idle_pipe[3] >= 0);
                return 0;
        }

        assert(m->idle_pipe[1] < 0);
        assert(m->idle_pipe[2] < 0);
        assert(m->idle_pipe[3] < 0);

        r = RET_NERRNO(pipe2(m->idle_pipe + 0, O_NONBLOCK|O_CLOEXEC));
        if (r < 0)
                return r;

        r = RET_NERRNO(pipe2(m->idle_pipe + 2, O_NONBLOCK|O_CLOEXEC));
        if (r < 0) {
                safe_close_pair(m->idle_pipe + 0);
                return r;
        }

        return 1;
}

void unit_defaults_init(UnitDefaults *defaults, RuntimeScope scope) {
        assert(defaults);
        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        *defaults = (UnitDefaults) {
                .std_output = EXEC_OUTPUT_JOURNAL,
                .std_error = EXEC_OUTPUT_INHERIT,
                .restart_usec = DEFAULT_RESTART_USEC,
                .timeout_start_usec = manager_default_timeout(scope),
                .timeout_stop_usec = manager_default_timeout(scope),
                .timeout_abort_usec = manager_default_timeout(scope),
                .timeout_abort_set = false,
                .device_timeout_usec = manager_default_timeout(scope),
                .start_limit_interval = DEFAULT_START_LIMIT_INTERVAL,
                .start_limit_burst = DEFAULT_START_LIMIT_BURST,

                /* On 4.15+ with unified hierarchy, CPU accounting is essentially free as it doesn't require the CPU
                 * controller to be enabled, so the default is to enable it unless we got told otherwise. */
                .cpu_accounting = cpu_accounting_is_cheap(),
                .memory_accounting = MEMORY_ACCOUNTING_DEFAULT,
                .io_accounting = false,
                .blockio_accounting = false,
                .tasks_accounting = true,
                .ip_accounting = false,

                .tasks_max = DEFAULT_TASKS_MAX,
                .timer_accuracy_usec = 1 * USEC_PER_MINUTE,

                .memory_pressure_watch = CGROUP_PRESSURE_WATCH_AUTO,
                .memory_pressure_threshold_usec = MEMORY_PRESSURE_DEFAULT_THRESHOLD_USEC,

                .oom_policy = OOM_STOP,
                .oom_score_adjust_set = false,
        };
}

void unit_defaults_done(UnitDefaults *defaults) {
        assert(defaults);

        defaults->smack_process_label = mfree(defaults->smack_process_label);
        rlimit_free_all(defaults->rlimit);
}

LogTarget manager_get_executor_log_target(Manager *m) {
        assert(m);

        /* If journald is not available tell sd-executor to go to kmsg, as it might be starting journald */

        if (manager_journal_is_running(m))
                return log_get_target();

        return LOG_TARGET_KMSG;
}

static const char *const manager_state_table[_MANAGER_STATE_MAX] = {
        [MANAGER_INITIALIZING] = "initializing",
        [MANAGER_STARTING]     = "starting",
        [MANAGER_RUNNING]      = "running",
        [MANAGER_DEGRADED]     = "degraded",
        [MANAGER_MAINTENANCE]  = "maintenance",
        [MANAGER_STOPPING]     = "stopping",
};

DEFINE_STRING_TABLE_LOOKUP(manager_state, ManagerState);

static const char *const manager_timestamp_table[_MANAGER_TIMESTAMP_MAX] = {
        [MANAGER_TIMESTAMP_FIRMWARE]                 = "firmware",
        [MANAGER_TIMESTAMP_LOADER]                   = "loader",
        [MANAGER_TIMESTAMP_KERNEL]                   = "kernel",
        [MANAGER_TIMESTAMP_INITRD]                   = "initrd",
        [MANAGER_TIMESTAMP_USERSPACE]                = "userspace",
        [MANAGER_TIMESTAMP_FINISH]                   = "finish",
        [MANAGER_TIMESTAMP_SECURITY_START]           = "security-start",
        [MANAGER_TIMESTAMP_SECURITY_FINISH]          = "security-finish",
        [MANAGER_TIMESTAMP_GENERATORS_START]         = "generators-start",
        [MANAGER_TIMESTAMP_GENERATORS_FINISH]        = "generators-finish",
        [MANAGER_TIMESTAMP_UNITS_LOAD_START]         = "units-load-start",
        [MANAGER_TIMESTAMP_UNITS_LOAD_FINISH]        = "units-load-finish",
        [MANAGER_TIMESTAMP_UNITS_LOAD]               = "units-load",
        [MANAGER_TIMESTAMP_INITRD_SECURITY_START]    = "initrd-security-start",
        [MANAGER_TIMESTAMP_INITRD_SECURITY_FINISH]   = "initrd-security-finish",
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_START]  = "initrd-generators-start",
        [MANAGER_TIMESTAMP_INITRD_GENERATORS_FINISH] = "initrd-generators-finish",
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_START]  = "initrd-units-load-start",
        [MANAGER_TIMESTAMP_INITRD_UNITS_LOAD_FINISH] = "initrd-units-load-finish",
};

DEFINE_STRING_TABLE_LOOKUP(manager_timestamp, ManagerTimestamp);

static const char* const oom_policy_table[_OOM_POLICY_MAX] = {
        [OOM_CONTINUE] = "continue",
        [OOM_STOP]     = "stop",
        [OOM_KILL]     = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(oom_policy, OOMPolicy);
