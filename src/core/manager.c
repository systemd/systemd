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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/timerfd.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "systemd/sd-daemon.h"
#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"

#include "manager.h"
#include "transaction.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "ratelimit.h"
#include "cgroup.h"
#include "mount-setup.h"
#include "unit-name.h"
#include "dbus-unit.h"
#include "dbus-job.h"
#include "missing.h"
#include "path-lookup.h"
#include "special.h"
#include "bus-errors.h"
#include "exit-status.h"
#include "virt.h"
#include "watchdog.h"
#include "cgroup-util.h"
#include "path-util.h"
#include "audit-fd.h"
#include "env-util.h"

/* As soon as 16 units are in our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_ENTRIES_MAX 16

/* As soon as 5s passed since a unit was added to our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_USEC_MAX (10*USEC_PER_SEC)

/* Initial delay and the interval for printing status messages about running jobs */
#define JOBS_IN_PROGRESS_WAIT_SEC 5
#define JOBS_IN_PROGRESS_PERIOD_SEC 1
#define JOBS_IN_PROGRESS_PERIOD_DIVISOR 3

/* Where clients shall send notification messages to */
#define NOTIFY_SOCKET "@/org/freedesktop/systemd1/notify"

#define TIME_T_MAX (time_t)((1UL << ((sizeof(time_t) << 3) - 1)) - 1)

static int manager_setup_notify(Manager *m) {
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .sa.sa_family = AF_UNIX,
        };
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = &m->notify_watch,
        };
        int one = 1, r;

        m->notify_watch.type = WATCH_NOTIFY;
        m->notify_watch.fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->notify_watch.fd < 0) {
                log_error("Failed to allocate notification socket: %m");
                return -errno;
        }

        if (getpid() != 1 || detect_container(NULL) > 0)
                snprintf(sa.un.sun_path, sizeof(sa.un.sun_path), NOTIFY_SOCKET "/%llu", random_ull());
        else
                strncpy(sa.un.sun_path, NOTIFY_SOCKET, sizeof(sa.un.sun_path));

        sa.un.sun_path[0] = 0;

        r = bind(m->notify_watch.fd, &sa.sa,
                 offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1));
        if (r < 0) {
                log_error("bind() failed: %m");
                return -errno;
        }

        r = setsockopt(m->notify_watch.fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

        r = epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->notify_watch.fd, &ev);
        if (r < 0) {
                log_error("Failed to add notification socket fd to epoll: %m");
                return -errno;
        }

        sa.un.sun_path[0] = '@';
        m->notify_socket = strdup(sa.un.sun_path);
        if (!m->notify_socket)
                return log_oom();

        log_debug("Using notification socket %s", m->notify_socket);

        return 0;
}

static int manager_jobs_in_progress_mod_timer(Manager *m) {
        struct itimerspec its = {
                .it_value.tv_sec = JOBS_IN_PROGRESS_WAIT_SEC,
                .it_interval.tv_sec = JOBS_IN_PROGRESS_PERIOD_SEC,
        };

        if (m->jobs_in_progress_watch.type != WATCH_JOBS_IN_PROGRESS)
                return 0;

        if (timerfd_settime(m->jobs_in_progress_watch.fd, 0, &its, NULL) < 0)
                return -errno;

        return 0;
}

static int manager_watch_jobs_in_progress(Manager *m) {
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = &m->jobs_in_progress_watch,
        };
        int r;

        if (m->jobs_in_progress_watch.type != WATCH_INVALID)
                return 0;

        m->jobs_in_progress_watch.type = WATCH_JOBS_IN_PROGRESS;
        m->jobs_in_progress_watch.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
        if (m->jobs_in_progress_watch.fd < 0) {
                log_error("Failed to create timerfd: %m");
                r = -errno;
                goto err;
        }

        r = manager_jobs_in_progress_mod_timer(m);
        if (r < 0) {
                log_error("Failed to set up timer for jobs progress watch: %s", strerror(-r));
                goto err;
        }

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->jobs_in_progress_watch.fd, &ev) < 0) {
                log_error("Failed to add jobs progress timer fd to epoll: %m");
                r = -errno;
                goto err;
        }

        log_debug("Set up jobs progress timerfd.");

        return 0;

err:
        if (m->jobs_in_progress_watch.fd >= 0)
                close_nointr_nofail(m->jobs_in_progress_watch.fd);
        watch_init(&m->jobs_in_progress_watch);
        return r;
}

static void manager_unwatch_jobs_in_progress(Manager *m) {
        if (m->jobs_in_progress_watch.type != WATCH_JOBS_IN_PROGRESS)
                return;

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, m->jobs_in_progress_watch.fd, NULL) >= 0);
        close_nointr_nofail(m->jobs_in_progress_watch.fd);
        watch_init(&m->jobs_in_progress_watch);
        m->jobs_in_progress_iteration = 0;

        log_debug("Closed jobs progress timerfd.");
}

#define CYLON_BUFFER_EXTRA (2*strlen(ANSI_RED_ON) + strlen(ANSI_HIGHLIGHT_RED_ON) + 2*strlen(ANSI_HIGHLIGHT_OFF))
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
                p = stpcpy(p, ANSI_HIGHLIGHT_OFF);
        }
}

static void manager_print_jobs_in_progress(Manager *m) {
        Iterator i;
        Job *j;
        char *job_of_n = NULL;
        unsigned counter = 0, print_nr;
        char cylon[6 + CYLON_BUFFER_EXTRA + 1];
        unsigned cylon_pos;

        print_nr = (m->jobs_in_progress_iteration / JOBS_IN_PROGRESS_PERIOD_DIVISOR) % m->n_running_jobs;

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->state == JOB_RUNNING && counter++ == print_nr)
                        break;

        /* m->n_running_jobs must be consistent with the contents of m->jobs,
         * so the above loop must have succeeded in finding j. */
        assert(counter == print_nr + 1);

        cylon_pos = m->jobs_in_progress_iteration % 14;
        if (cylon_pos >= 8)
                cylon_pos = 14 - cylon_pos;
        draw_cylon(cylon, sizeof(cylon), 6, cylon_pos);

        if (m->n_running_jobs > 1)
                if (asprintf(&job_of_n, "(%u of %u) ", counter, m->n_running_jobs) < 0)
                        job_of_n = NULL;

        manager_status_printf(m, true, cylon, "%sA %s job is running for %s",
                              strempty(job_of_n), job_type_to_string(j->type), unit_description(j->unit));
        free(job_of_n);

        m->jobs_in_progress_iteration++;
}

static int manager_setup_time_change(Manager *m) {
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = &m->time_change_watch,
        };

        /* We only care for the cancellation event, hence we set the
         * timeout to the latest possible value. */
        struct itimerspec its = {
                .it_value.tv_sec = TIME_T_MAX,
        };
        assert_cc(sizeof(time_t) == sizeof(TIME_T_MAX));

        assert(m->time_change_watch.type == WATCH_INVALID);

        /* Uses TFD_TIMER_CANCEL_ON_SET to get notifications whenever
         * CLOCK_REALTIME makes a jump relative to CLOCK_MONOTONIC */

        m->time_change_watch.type = WATCH_TIME_CHANGE;
        m->time_change_watch.fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC);
        if (m->time_change_watch.fd < 0) {
                log_error("Failed to create timerfd: %m");
                return -errno;
        }

        if (timerfd_settime(m->time_change_watch.fd, TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET, &its, NULL) < 0) {
                log_debug("Failed to set up TFD_TIMER_CANCEL_ON_SET, ignoring: %m");
                close_nointr_nofail(m->time_change_watch.fd);
                watch_init(&m->time_change_watch);
                return 0;
        }

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->time_change_watch.fd, &ev) < 0) {
                log_error("Failed to add timer change fd to epoll: %m");
                return -errno;
        }

        log_debug("Set up TFD_TIMER_CANCEL_ON_SET timerfd.");

        return 0;
}

static int enable_special_signals(Manager *m) {
        int fd;

        assert(m);

        /* Enable that we get SIGINT on control-alt-del. In containers
         * this will fail with EPERM (older) or EINVAL (newer), so
         * ignore that. */
        if (reboot(RB_DISABLE_CAD) < 0 && errno != EPERM && errno != EINVAL)
                log_warning("Failed to enable ctrl-alt-del handling: %m");

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                /* Support systems without virtual console */
                if (fd != -ENOENT)
                        log_warning("Failed to open /dev/tty0: %m");
        } else {
                /* Enable that we get SIGWINCH on kbrequest */
                if (ioctl(fd, KDSIGACCEPT, SIGWINCH) < 0)
                        log_warning("Failed to enable kbrequest handling: %s", strerror(errno));

                close_nointr_nofail(fd);
        }

        return 0;
}

static int manager_setup_signals(Manager *m) {
        sigset_t mask;
        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = &m->signal_watch,
        };
        struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_NOCLDSTOP|SA_RESTART,
        };

        assert(m);

        /* We are not interested in SIGSTOP and friends. */
        assert_se(sigaction(SIGCHLD, &sa, NULL) == 0);

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
                        SIGRTMIN+13, /* systemd: Immediate halt */
                        SIGRTMIN+14, /* systemd: Immediate poweroff */
                        SIGRTMIN+15, /* systemd: Immediate reboot */
                        SIGRTMIN+16, /* systemd: Immediate kexec */
                        SIGRTMIN+20, /* systemd: enable status messages */
                        SIGRTMIN+21, /* systemd: disable status messages */
                        SIGRTMIN+22, /* systemd: set log level to LOG_DEBUG */
                        SIGRTMIN+23, /* systemd: set log level to LOG_INFO */
                        SIGRTMIN+24, /* systemd: Immediate exit (--user only) */
                        SIGRTMIN+26, /* systemd: set log target to journal-or-kmsg */
                        SIGRTMIN+27, /* systemd: set log target to console */
                        SIGRTMIN+28, /* systemd: set log target to kmsg */
                        SIGRTMIN+29, /* systemd: set log target to syslog-or-kmsg */
                        -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_watch.type = WATCH_SIGNAL;
        m->signal_watch.fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (m->signal_watch.fd < 0)
                return -errno;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->signal_watch.fd, &ev) < 0)
                return -errno;

        if (m->running_as == SYSTEMD_SYSTEM)
                return enable_special_signals(m);

        return 0;
}

static void manager_strip_environment(Manager *m) {
        assert(m);

        /* Remove variables from the inherited set that are part of
         * the container interface:
         * http://www.freedesktop.org/wiki/Software/systemd/ContainerInterface */
        strv_remove_prefix(m->environment, "container=");
        strv_remove_prefix(m->environment, "container_");

        /* Remove variables from the inherited set that are part of
         * the initrd interface:
         * http://www.freedesktop.org/wiki/Software/systemd/InitrdInterface */
        strv_remove_prefix(m->environment, "RD_");

        /* Drop invalid entries */
        strv_env_clean(m->environment);
}

int manager_new(SystemdRunningAs running_as, Manager **_m) {
        Manager *m;
        int r = -ENOMEM;

        assert(_m);
        assert(running_as >= 0);
        assert(running_as < _SYSTEMD_RUNNING_AS_MAX);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->running_as = running_as;
        m->name_data_slot = m->conn_data_slot = m->subscribed_data_slot = -1;
        m->exit_code = _MANAGER_EXIT_CODE_INVALID;
        m->pin_cgroupfs_fd = -1;
        m->idle_pipe[0] = m->idle_pipe[1] = -1;

        watch_init(&m->signal_watch);
        watch_init(&m->mount_watch);
        watch_init(&m->swap_watch);
        watch_init(&m->udev_watch);
        watch_init(&m->time_change_watch);
        watch_init(&m->jobs_in_progress_watch);

        m->epoll_fd = m->dev_autofs_fd = -1;
        m->current_job_id = 1; /* start as id #1, so that we can leave #0 around as "null-like" value */

        m->environment = strv_copy(environ);
        if (!m->environment)
                goto fail;

        manager_strip_environment(m);

        if (running_as == SYSTEMD_SYSTEM) {
                m->default_controllers = strv_new("cpu", NULL);
                if (!m->default_controllers)
                        goto fail;
        }

        if (!(m->units = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->watch_pids = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->cgroup_bondings = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->watch_bus = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        m->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m->epoll_fd < 0)
                goto fail;

        r = manager_setup_signals(m);
        if (r < 0)
                goto fail;

        r = manager_setup_cgroup(m);
        if (r < 0)
                goto fail;

        r = manager_setup_notify(m);
        if (r < 0)
                goto fail;

        r = manager_setup_time_change(m);
        if (r < 0)
                goto fail;

        /* Try to connect to the busses, if possible. */
        r = bus_init(m, running_as != SYSTEMD_SYSTEM);
        if (r < 0)
                goto fail;

        m->taint_usr = dir_is_empty("/usr") > 0;

        *_m = m;
        return 0;

fail:
        manager_free(m);
        return r;
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

        if ((m->n_in_gc_queue < GC_QUEUE_ENTRIES_MAX) &&
            (m->gc_queue_timestamp <= 0 ||
             (m->gc_queue_timestamp + GC_QUEUE_USEC_MAX) > now(CLOCK_MONOTONIC)))
                return 0;

        log_debug("Running GC...");

        m->gc_marker += _GC_OFFSET_MAX;
        if (m->gc_marker + _GC_OFFSET_MAX <= _GC_OFFSET_MAX)
                m->gc_marker = 1;

        gc_marker = m->gc_marker;

        while ((u = m->gc_queue)) {
                assert(u->in_gc_queue);

                unit_gc_sweep(u, gc_marker);

                LIST_REMOVE(Unit, gc_queue, m->gc_queue, u);
                u->in_gc_queue = false;

                n++;

                if (u->gc_marker == gc_marker + GC_OFFSET_BAD ||
                    u->gc_marker == gc_marker + GC_OFFSET_UNSURE) {
                        log_debug_unit(u->id, "Collecting %s", u->id);
                        u->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(u);
                }
        }

        m->n_in_gc_queue = 0;
        m->gc_queue_timestamp = 0;

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

void manager_free(Manager *m) {
        UnitType c;
        int i;

        assert(m);

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
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_bus);

        if (m->epoll_fd >= 0)
                close_nointr_nofail(m->epoll_fd);
        if (m->signal_watch.fd >= 0)
                close_nointr_nofail(m->signal_watch.fd);
        if (m->notify_watch.fd >= 0)
                close_nointr_nofail(m->notify_watch.fd);
        if (m->time_change_watch.fd >= 0)
                close_nointr_nofail(m->time_change_watch.fd);
        if (m->jobs_in_progress_watch.fd >= 0)
                close_nointr_nofail(m->jobs_in_progress_watch.fd);

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->environment);

        strv_free(m->default_controllers);

        hashmap_free(m->cgroup_bondings);
        set_free_free(m->unit_path_cache);

        close_pipe(m->idle_pipe);

        free(m->switch_root);
        free(m->switch_root_init);

        for (i = 0; i < RLIMIT_NLIMITS; i++)
                free(m->rlimit[i]);

        free(m);
}

int manager_enumerate(Manager *m) {
        int r = 0, q;
        UnitType c;

        assert(m);

        /* Let's ask every type to load all units from disk/kernel
         * that it might know */
        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->enumerate)
                        if ((q = unit_vtable[c]->enumerate(m)) < 0)
                                r = q;

        manager_dispatch_load_queue(m);
        return r;
}

int manager_coldplug(Manager *m) {
        int r = 0, q;
        Iterator i;
        Unit *u;
        char *k;

        assert(m);

        /* Then, let's set up their initial state. */
        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->id != k)
                        continue;

                if ((q = unit_coldplug(u)) < 0)
                        r = q;
        }

        return r;
}

static void manager_build_unit_path_cache(Manager *m) {
        char **i;
        _cleanup_free_ DIR *d = NULL;
        int r;

        assert(m);

        set_free_free(m->unit_path_cache);

        m->unit_path_cache = set_new(string_hash_func, string_compare_func);
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
                                log_error("Failed to open directory %s: %m", *i);
                        continue;
                }

                while ((de = readdir(d))) {
                        char *p;

                        if (ignore_file(de->d_name))
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
        log_error("Failed to build unit path cache: %s", strerror(-r));

        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r, q;

        assert(m);

        manager_run_generators(m);

        r = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
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
        r = manager_enumerate(m);

        /* Second, deserialize if there is something to deserialize */
        if (serialization) {
                q = manager_deserialize(m, serialization, fds);
                if (q < 0)
                        r = q;
        }

        /* Any fds left? Find some unit which wants them. This is
         * useful to allow container managers to pass some file
         * descriptors to us pre-initialized. This enables
         * socket-based activation of entire containers. */
        if (fdset_size(fds) > 0) {
                q = manager_distribute_fds(m, fds);
                if (q < 0)
                        r = q;
        }

        /* Third, fire things up! */
        q = manager_coldplug(m);
        if (q < 0)
                r = q;

        if (serialization) {
                assert(m->n_reloading > 0);
                m->n_reloading --;
        }

        return r;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool override, DBusError *e, Job **_ret) {
        int r;
        Transaction *tr;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START) {
                dbus_set_error(e, BUS_ERROR_INVALID_JOB_MODE, "Isolate is only valid for start.");
                return -EINVAL;
        }

        if (mode == JOB_ISOLATE && !unit->allow_isolate) {
                dbus_set_error(e, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");
                return -EPERM;
        }

        log_debug_unit(unit->id,
                       "Trying to enqueue job %s/%s/%s", unit->id,
                       job_type_to_string(type), job_mode_to_string(mode));

        job_type_collapse(&type, unit);

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

        log_debug_unit(unit->id,
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

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool override, DBusError *e, Job **_ret) {
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

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret) {
        Unit *ret;
        UnitType t;
        int r;

        assert(m);
        assert(name || path);

        /* This will prepare the unit for loading, but not actually
         * load anything from disk. */

        if (path && !is_path(path)) {
                dbus_set_error(e, BUS_ERROR_INVALID_PATH, "Path %s is not absolute.", path);
                return -EINVAL;
        }

        if (!name)
                name = path_get_file_name(path);

        t = unit_name_to_type(name);

        if (t == _UNIT_TYPE_INVALID || !unit_name_is_valid(name, false)) {
                dbus_set_error(e, BUS_ERROR_INVALID_NAME, "Unit name %s is not valid.", name);
                return -EINVAL;
        }

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

        if ((r = unit_add_name(ret, name)) < 0) {
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

int manager_load_unit(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret) {
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

unsigned manager_dispatch_run_queue(Manager *m) {
        Job *j;
        unsigned n = 0;

        if (m->dispatching_run_queue)
                return 0;

        m->dispatching_run_queue = true;

        while ((j = m->run_queue)) {
                assert(j->installed);
                assert(j->in_run_queue);

                job_run_and_invalidate(j);
                n++;
        }

        m->dispatching_run_queue = false;

        if (m->n_running_jobs > 0)
                manager_watch_jobs_in_progress(m);

        return n;
}

unsigned manager_dispatch_dbus_queue(Manager *m) {
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
        return n;
}

static int manager_process_notify_fd(Manager *m) {
        ssize_t n;

        assert(m);

        for (;;) {
                char buf[4096];
                struct iovec iovec = {
                        .iov_base = buf,
                        .iov_len = sizeof(buf)-1,
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
                struct ucred *ucred;
                Unit *u;
                _cleanup_strv_free_ char **tags = NULL;

                n = recvmsg(m->notify_watch.fd, &msghdr, MSG_DONTWAIT);
                if (n <= 0) {
                        if (n == 0)
                                return -EIO;

                        if (errno == EAGAIN || errno == EINTR)
                                break;

                        return -errno;
                }

                if (msghdr.msg_controllen < CMSG_LEN(sizeof(struct ucred)) ||
                    control.cmsghdr.cmsg_level != SOL_SOCKET ||
                    control.cmsghdr.cmsg_type != SCM_CREDENTIALS ||
                    control.cmsghdr.cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                        log_warning("Received notify message without credentials. Ignoring.");
                        continue;
                }

                ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);

                u = hashmap_get(m->watch_pids, LONG_TO_PTR(ucred->pid));
                if (!u) {
                        u = cgroup_unit_by_pid(m, ucred->pid);
                        if (!u) {
                                log_warning("Cannot find unit for notify message of PID %lu.", (unsigned long) ucred->pid);
                                continue;
                        }
                }

                assert((size_t) n < sizeof(buf));
                buf[n] = 0;
                tags = strv_split(buf, "\n\r");
                if (!tags)
                        return log_oom();

                log_debug_unit(u->id, "Got notification message for unit %s", u->id);

                if (UNIT_VTABLE(u)->notify_message)
                        UNIT_VTABLE(u)->notify_message(u, ucred->pid, tags);
        }

        return 0;
}

static int manager_dispatch_sigchld(Manager *m) {
        assert(m);

        for (;;) {
                siginfo_t si = {};
                Unit *u;
                int r;

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

                        get_process_comm(si.si_pid, &name);
                        log_debug("Got SIGCHLD for process %lu (%s)", (unsigned long) si.si_pid, strna(name));
                }

                /* Let's flush any message the dying child might still
                 * have queued for us. This ensures that the process
                 * still exists in /proc so that we can figure out
                 * which cgroup and hence unit it belongs to. */
                r = manager_process_notify_fd(m);
                if (r < 0)
                        return r;

                /* And now figure out the unit this belongs to */
                u = hashmap_get(m->watch_pids, LONG_TO_PTR(si.si_pid));
                if (!u)
                        u = cgroup_unit_by_pid(m, si.si_pid);

                /* And now, we actually reap the zombie. */
                if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (si.si_code != CLD_EXITED && si.si_code != CLD_KILLED && si.si_code != CLD_DUMPED)
                        continue;

                log_debug("Child %lu died (code=%s, status=%i/%s)",
                          (long unsigned) si.si_pid,
                          sigchld_code_to_string(si.si_code),
                          si.si_status,
                          strna(si.si_code == CLD_EXITED
                                ? exit_status_to_string(si.si_status, EXIT_STATUS_FULL)
                                : signal_to_string(si.si_status)));

                if (!u)
                        continue;

                log_debug_unit(u->id,
                               "Child %lu belongs to %s", (long unsigned) si.si_pid, u->id);

                hashmap_remove(m->watch_pids, LONG_TO_PTR(si.si_pid));
                UNIT_VTABLE(u)->sigchld_event(u, si.si_pid, si.si_code, si.si_status);
        }

        return 0;
}

static int manager_start_target(Manager *m, const char *name, JobMode mode) {
        int r;
        DBusError error;

        dbus_error_init(&error);

        log_debug_unit(name, "Activating special unit %s", name);

        r = manager_add_job_by_name(m, JOB_START, name, mode, true, &error, NULL);
        if (r < 0)
                log_error_unit(name,
                               "Failed to enqueue %s job: %s", name, bus_error(&error, r));

        dbus_error_free(&error);

        return r;
}

static int manager_process_signal_fd(Manager *m) {
        ssize_t n;
        struct signalfd_siginfo sfsi;
        bool sigchld = false;

        assert(m);

        for (;;) {
                n = read(m->signal_watch.fd, &sfsi, sizeof(sfsi));
                if (n != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                break;

                        return -errno;
                }

                if (sfsi.ssi_pid > 0) {
                        char *p = NULL;

                        get_process_comm(sfsi.ssi_pid, &p);

                        log_debug("Received SIG%s from PID %lu (%s).",
                                  signal_to_string(sfsi.ssi_signo),
                                  (unsigned long) sfsi.ssi_pid, strna(p));
                        free(p);
                } else
                        log_debug("Received SIG%s.", signal_to_string(sfsi.ssi_signo));

                switch (sfsi.ssi_signo) {

                case SIGCHLD:
                        sigchld = true;
                        break;

                case SIGTERM:
                        if (m->running_as == SYSTEMD_SYSTEM) {
                                /* This is for compatibility with the
                                 * original sysvinit */
                                m->exit_code = MANAGER_REEXECUTE;
                                break;
                        }

                        /* Fall through */

                case SIGINT:
                        if (m->running_as == SYSTEMD_SYSTEM) {
                                manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET, JOB_REPLACE);
                                break;
                        }

                        /* Run the exit target if there is one, if not, just exit. */
                        if (manager_start_target(m, SPECIAL_EXIT_TARGET, JOB_REPLACE) < 0) {
                                m->exit_code = MANAGER_EXIT;
                                return 0;
                        }

                        break;

                case SIGWINCH:
                        if (m->running_as == SYSTEMD_SYSTEM)
                                manager_start_target(m, SPECIAL_KBREQUEST_TARGET, JOB_REPLACE);

                        /* This is a nop on non-init */
                        break;

                case SIGPWR:
                        if (m->running_as == SYSTEMD_SYSTEM)
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
                        FILE *f;
                        char *dump = NULL;
                        size_t size;

                        if (!(f = open_memstream(&dump, &size))) {
                                log_warning("Failed to allocate memory stream.");
                                break;
                        }

                        manager_dump_units(m, f, "\t");
                        manager_dump_jobs(m, f, "\t");

                        if (ferror(f)) {
                                fclose(f);
                                free(dump);
                                log_warning("Failed to write status stream");
                                break;
                        }

                        fclose(f);
                        log_dump(LOG_INFO, dump);
                        free(dump);

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
                                manager_set_show_status(m, true);
                                break;

                        case 21:
                                log_debug("Disabling showing of status.");
                                manager_set_show_status(m, false);
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
                                if (m->running_as == SYSTEMD_USER) {
                                        m->exit_code = MANAGER_EXIT;
                                        return 0;
                                }

                                /* This is a nop on init */
                                break;

                        case 26:
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

                        case 29:
                                log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
                                log_notice("Setting log target to syslog-or-kmsg.");
                                break;

                        default:
                                log_warning("Got unhandled signal <%s>.", signal_to_string(sfsi.ssi_signo));
                        }
                }
                }
        }

        if (sigchld)
                return manager_dispatch_sigchld(m);

        return 0;
}

static int process_event(Manager *m, struct epoll_event *ev) {
        int r;
        Watch *w;

        assert(m);
        assert(ev);

        assert_se(w = ev->data.ptr);

        if (w->type == WATCH_INVALID)
                return 0;

        switch (w->type) {

        case WATCH_SIGNAL:

                /* An incoming signal? */
                if (ev->events != EPOLLIN)
                        return -EINVAL;

                if ((r = manager_process_signal_fd(m)) < 0)
                        return r;

                break;

        case WATCH_NOTIFY:

                /* An incoming daemon notification event? */
                if (ev->events != EPOLLIN)
                        return -EINVAL;

                if ((r = manager_process_notify_fd(m)) < 0)
                        return r;

                break;

        case WATCH_FD:

                /* Some fd event, to be dispatched to the units */
                UNIT_VTABLE(w->data.unit)->fd_event(w->data.unit, w->fd, ev->events, w);
                break;

        case WATCH_UNIT_TIMER:
        case WATCH_JOB_TIMER: {
                uint64_t v;
                ssize_t k;

                /* Some timer event, to be dispatched to the units */
                k = read(w->fd, &v, sizeof(v));
                if (k != sizeof(v)) {

                        if (k < 0 && (errno == EINTR || errno == EAGAIN))
                                break;

                        log_error("Failed to read timer event counter: %s", k < 0 ? strerror(-k) : "Short read");
                        return k < 0 ? -errno : -EIO;
                }

                if (w->type == WATCH_UNIT_TIMER)
                        UNIT_VTABLE(w->data.unit)->timer_event(w->data.unit, v, w);
                else
                        job_timer_event(w->data.job, v, w);
                break;
        }

        case WATCH_MOUNT:
                /* Some mount table change, intended for the mount subsystem */
                mount_fd_event(m, ev->events);
                break;

        case WATCH_SWAP:
                /* Some swap table change, intended for the swap subsystem */
                swap_fd_event(m, ev->events);
                break;

        case WATCH_UDEV:
                /* Some notification from udev, intended for the device subsystem */
                device_fd_event(m, ev->events);
                break;

        case WATCH_DBUS_WATCH:
                bus_watch_event(m, w, ev->events);
                break;

        case WATCH_DBUS_TIMEOUT:
                bus_timeout_event(m, w, ev->events);
                break;

        case WATCH_TIME_CHANGE: {
                Unit *u;
                Iterator i;

                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_TIME_CHANGE),
                           "MESSAGE=Time has been changed",
                           NULL);

                /* Restart the watch */
                epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, m->time_change_watch.fd,
                          NULL);
                close_nointr_nofail(m->time_change_watch.fd);
                watch_init(&m->time_change_watch);
                manager_setup_time_change(m);

                HASHMAP_FOREACH(u, m->units, i) {
                        if (UNIT_VTABLE(u)->time_change)
                                UNIT_VTABLE(u)->time_change(u);
                }

                break;
        }

        case WATCH_JOBS_IN_PROGRESS: {
                uint64_t v;

                /* not interested in the data */
                read(w->fd, &v, sizeof(v));

                manager_print_jobs_in_progress(m);
                break;
        }

        default:
                log_error("event type=%i", w->type);
                assert_not_reached("Unknown epoll event type.");
        }

        return 0;
}

int manager_loop(Manager *m) {
        int r;

        RATELIMIT_DEFINE(rl, 1*USEC_PER_SEC, 50000);

        assert(m);
        m->exit_code = MANAGER_RUNNING;

        /* Release the path cache */
        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;

        manager_check_finished(m);

        /* There might still be some zombies hanging around from
         * before we were exec()'ed. Leat's reap them */
        r = manager_dispatch_sigchld(m);
        if (r < 0)
                return r;

        while (m->exit_code == MANAGER_RUNNING) {
                struct epoll_event event;
                int n;
                int wait_msec = -1;

                if (m->runtime_watchdog > 0 && m->running_as == SYSTEMD_SYSTEM)
                        watchdog_ping();

                if (!ratelimit_test(&rl)) {
                        /* Yay, something is going seriously wrong, pause a little */
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
                        continue;
                }

                if (manager_dispatch_load_queue(m) > 0)
                        continue;

                if (manager_dispatch_run_queue(m) > 0)
                        continue;

                if (bus_dispatch(m) > 0)
                        continue;

                if (manager_dispatch_cleanup_queue(m) > 0)
                        continue;

                if (manager_dispatch_gc_queue(m) > 0)
                        continue;

                if (manager_dispatch_dbus_queue(m) > 0)
                        continue;

                if (swap_dispatch_reload(m) > 0)
                        continue;

                /* Sleep for half the watchdog time */
                if (m->runtime_watchdog > 0 && m->running_as == SYSTEMD_SYSTEM) {
                        wait_msec = (int) (m->runtime_watchdog / 2 / USEC_PER_MSEC);
                        if (wait_msec <= 0)
                                wait_msec = 1;
                } else
                        wait_msec = -1;

                n = epoll_wait(m->epoll_fd, &event, 1, wait_msec);
                if (n < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                } else if (n == 0)
                        continue;

                assert(n == 1);

                r = process_event(m, &event);
                if (r < 0)
                        return r;
        }

        return m->exit_code;
}

int manager_load_unit_from_dbus_path(Manager *m, const char *s, DBusError *e, Unit **_u) {
        char *n;
        Unit *u;
        int r;

        assert(m);
        assert(s);
        assert(_u);

        if (!startswith(s, "/org/freedesktop/systemd1/unit/"))
                return -EINVAL;

        n = bus_path_unescape(s+31);
        if (!n)
                return -ENOMEM;

        r = manager_load_unit(m, n, NULL, e, &u);
        free(n);

        if (r < 0)
                return r;

        *_u = u;

        return 0;
}

int manager_get_job_from_dbus_path(Manager *m, const char *s, Job **_j) {
        Job *j;
        unsigned id;
        int r;

        assert(m);
        assert(s);
        assert(_j);

        if (!startswith(s, "/org/freedesktop/systemd1/job/"))
                return -EINVAL;

        r = safe_atou(s + 30, &id);
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
        char *p;
        int audit_fd;

        audit_fd = get_audit_fd();
        if (audit_fd < 0)
                return;

        /* Don't generate audit events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        if (u->type != UNIT_SERVICE)
                return;

        p = unit_name_to_prefix_and_instance(u->id);
        if (!p) {
                log_error_unit(u->id,
                               "Failed to allocate unit name for audit message: %s", strerror(ENOMEM));
                return;
        }

        if (audit_log_user_comm_message(audit_fd, type, "", p, NULL, NULL, NULL, success) < 0) {
                if (errno == EPERM) {
                        /* We aren't allowed to send audit messages?
                         * Then let's not retry again. */
                        close_audit_fd();
                } else
                        log_warning("Failed to send audit message: %m");
        }

        free(p);
#endif

}

void manager_send_unit_plymouth(Manager *m, Unit *u) {
        int fd = -1;
        union sockaddr_union sa;
        int n = 0;
        char *message = NULL;

        /* Don't generate plymouth events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        if (u->type != UNIT_SERVICE &&
            u->type != UNIT_MOUNT &&
            u->type != UNIT_SWAP)
                return;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message then wait for plymouth */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error("socket() failed: %m");
                return;
        }

        zero(sa);
        sa.sa.sa_family = AF_UNIX;
        strncpy(sa.un.sun_path+1, "/org/freedesktop/plymouthd", sizeof(sa.un.sun_path)-1);
        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1)) < 0) {

                if (errno != EPIPE &&
                    errno != EAGAIN &&
                    errno != ENOENT &&
                    errno != ECONNREFUSED &&
                    errno != ECONNRESET &&
                    errno != ECONNABORTED)
                        log_error("connect() failed: %m");

                goto finish;
        }

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->id) + 1), u->id, &n) < 0) {
                log_oom();
                goto finish;
        }

        errno = 0;
        if (write(fd, message, n + 1) != n + 1) {

                if (errno != EPIPE &&
                    errno != EAGAIN &&
                    errno != ENOENT &&
                    errno != ECONNREFUSED &&
                    errno != ECONNRESET &&
                    errno != ECONNABORTED)
                        log_error("Failed to write Plymouth message: %m");

                goto finish;
        }

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        free(message);
}

void manager_dispatch_bus_name_owner_changed(
                Manager *m,
                const char *name,
                const char* old_owner,
                const char *new_owner) {

        Unit *u;

        assert(m);
        assert(name);

        if (!(u = hashmap_get(m->watch_bus, name)))
                return;

        UNIT_VTABLE(u)->bus_name_owner_change(u, name, old_owner, new_owner);
}

void manager_dispatch_bus_query_pid_done(
                Manager *m,
                const char *name,
                pid_t pid) {

        Unit *u;

        assert(m);
        assert(name);
        assert(pid >= 1);

        if (!(u = hashmap_get(m->watch_bus, name)))
                return;

        UNIT_VTABLE(u)->bus_query_pid_done(u, name, pid);
}

int manager_open_serialization(Manager *m, FILE **_f) {
        char *path = NULL;
        int fd;
        FILE *f;

        assert(_f);

        if (m->running_as == SYSTEMD_SYSTEM)
                asprintf(&path, "/run/systemd/dump-%lu-XXXXXX", (unsigned long) getpid());
        else
                asprintf(&path, "/tmp/systemd-dump-%lu-XXXXXX", (unsigned long) getpid());

        if (!path)
                return -ENOMEM;

        RUN_WITH_UMASK(0077) {
                fd = mkostemp(path, O_RDWR|O_CLOEXEC);
        }

        if (fd < 0) {
                free(path);
                return -errno;
        }

        unlink(path);

        log_debug("Serializing state to %s", path);
        free(path);

        f = fdopen(fd, "w+");
        if (!f)
                return -errno;

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

        fprintf(f, "current-job-id=%i\n", m->current_job_id);
        fprintf(f, "taint-usr=%s\n", yes_no(m->taint_usr));
        fprintf(f, "n-installed-jobs=%u\n", m->n_installed_jobs);
        fprintf(f, "n-failed-jobs=%u\n", m->n_failed_jobs);

        dual_timestamp_serialize(f, "firmware-timestamp", &m->firmware_timestamp);
        dual_timestamp_serialize(f, "kernel-timestamp", &m->kernel_timestamp);
        dual_timestamp_serialize(f, "loader-timestamp", &m->loader_timestamp);
        dual_timestamp_serialize(f, "initrd-timestamp", &m->initrd_timestamp);

        if (!in_initrd()) {
                dual_timestamp_serialize(f, "userspace-timestamp", &m->userspace_timestamp);
                dual_timestamp_serialize(f, "finish-timestamp", &m->finish_timestamp);
        }

        if (!switching_root) {
                STRV_FOREACH(e, m->environment) {
                        _cleanup_free_ char *ce;

                        ce = cescape(*e);
                        if (ce)
                                fprintf(f, "env=%s\n", *e);
                }
        }

        fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->id != t)
                        continue;

                if (!unit_can_serialize(u))
                        continue;

                /* Start marker */
                fputs(u->id, f);
                fputc('\n', f);

                if ((r = unit_serialize(u, f, fds, !switching_root)) < 0) {
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

                        if ((b = parse_boolean(l+10)) < 0)
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
                else if (startswith(l, "env=")) {
                        _cleanup_free_ char *uce = NULL;
                        char **e;

                        uce = cunescape(l+4);
                        if (!uce) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        e = strv_env_set(m->environment, uce);
                        if (!e) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        strv_free(m->environment);
                        m->environment = e;
                } else
                        log_debug("Unknown serialization item '%s'", l);
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
        if (ferror(f)) {
                r = -EIO;
                goto finish;
        }

        assert(m->n_reloading > 0);
        m->n_reloading --;

        return r;
}

int manager_distribute_fds(Manager *m, FDSet *fds) {
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

int manager_reload(Manager *m) {
        int r, q;
        FILE *f;
        FDSet *fds;

        assert(m);

        r = manager_open_serialization(m, &f);
        if (r < 0)
                return r;

        m->n_reloading ++;

        fds = fdset_new();
        if (!fds) {
                m->n_reloading --;
                r = -ENOMEM;
                goto finish;
        }

        r = manager_serialize(m, f, fds, false);
        if (r < 0) {
                m->n_reloading --;
                goto finish;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                m->n_reloading --;
                r = -errno;
                goto finish;
        }

        /* From here on there is no way back. */
        manager_clear_jobs_and_units(m);
        manager_undo_generators(m);
        lookup_paths_free(&m->lookup_paths);

        /* Find new unit paths */
        manager_run_generators(m);

        q = lookup_paths_init(
                        &m->lookup_paths, m->running_as, true,
                        m->generator_unit_path,
                        m->generator_unit_path_early,
                        m->generator_unit_path_late);
        if (q < 0)
                r = q;

        manager_build_unit_path_cache(m);

        /* First, enumerate what we can from all config files */
        q = manager_enumerate(m);
        if (q < 0)
                r = q;

        /* Second, deserialize our stored data */
        q = manager_deserialize(m, f, fds);
        if (q < 0)
                r = q;

        fclose(f);
        f = NULL;

        /* Third, fire things up! */
        q = manager_coldplug(m);
        if (q < 0)
                r = q;

        assert(m->n_reloading > 0);
        m->n_reloading--;

finish:
        if (f)
                fclose(f);

        if (fds)
                fdset_free(fds);

        return r;
}

static bool manager_is_booting_or_shutting_down(Manager *m) {
        Unit *u;

        assert(m);

        /* Is the initial job still around? */
        if (manager_get_job(m, m->default_unit_job_id))
                return true;

        /* Is there a job for the shutdown target? */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u)
                return !!u->job;

        return false;
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

void manager_check_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec;

        assert(m);

        if (m->n_running_jobs == 0)
                manager_unwatch_jobs_in_progress(m);

        if (hashmap_size(m->jobs) > 0) {
                manager_jobs_in_progress_mod_timer(m);
                return;
        }

        /* Notify Type=idle units that we are done now */
        close_pipe(m->idle_pipe);

        /* Turn off confirm spawn now */
        m->confirm_spawn = false;

        if (dual_timestamp_is_set(&m->finish_timestamp))
                return;

        dual_timestamp_get(&m->finish_timestamp);

        if (m->running_as == SYSTEMD_SYSTEM && detect_container(NULL) <= 0) {

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

                        if (!log_on_console())
                                log_struct(LOG_INFO,
                                           MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                           "KERNEL_USEC=%llu", (unsigned long long) kernel_usec,
                                           "INITRD_USEC=%llu", (unsigned long long) initrd_usec,
                                           "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                           "MESSAGE=Startup finished in %s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                           format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                           format_timespan(initrd, sizeof(initrd), initrd_usec, USEC_PER_MSEC),
                                           format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                           format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                           NULL);
                } else {
                        kernel_usec = m->userspace_timestamp.monotonic - m->kernel_timestamp.monotonic;
                        initrd_usec = 0;

                        if (!log_on_console())
                                log_struct(LOG_INFO,
                                           MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                           "KERNEL_USEC=%llu", (unsigned long long) kernel_usec,
                                           "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                           "MESSAGE=Startup finished in %s (kernel) + %s (userspace) = %s.",
                                           format_timespan(kernel, sizeof(kernel), kernel_usec, USEC_PER_MSEC),
                                           format_timespan(userspace, sizeof(userspace), userspace_usec, USEC_PER_MSEC),
                                           format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                           NULL);
                }
        } else {
                firmware_usec = loader_usec = initrd_usec = kernel_usec = 0;
                total_usec = userspace_usec = m->finish_timestamp.monotonic - m->userspace_timestamp.monotonic;

                if (!log_on_console())
                        log_struct(LOG_INFO,
                                   MESSAGE_ID(SD_MESSAGE_STARTUP_FINISHED),
                                   "USERSPACE_USEC=%llu", (unsigned long long) userspace_usec,
                                   "MESSAGE=Startup finished in %s.",
                                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC),
                                   NULL);
        }

        bus_broadcast_finished(m, firmware_usec, loader_usec, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false,
                   "READY=1\nSTATUS=Startup finished in %s.",
                   format_timespan(sum, sizeof(sum), total_usec, USEC_PER_MSEC));
}

static int create_generator_dir(Manager *m, char **generator, const char *name) {
        char *p;
        int r;

        assert(m);
        assert(generator);
        assert(name);

        if (*generator)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM && getpid() == 1) {

                p = strappend("/run/systemd/", name);
                if (!p)
                        return log_oom();

                r = mkdir_p_label(p, 0755);
                if (r < 0) {
                        log_error("Failed to create generator directory %s: %s",
                                  p, strerror(-r));
                        free(p);
                        return r;
                }
        } else {
                p = strjoin("/tmp/systemd-", name, ".XXXXXX", NULL);
                if (!p)
                        return log_oom();

                if (!mkdtemp(p)) {
                        log_error("Failed to create generator directory %s: %m",
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

void manager_run_generators(Manager *m) {
        DIR *d = NULL;
        const char *generator_path;
        const char *argv[5];
        int r;

        assert(m);

        generator_path = m->running_as == SYSTEMD_SYSTEM ? SYSTEM_GENERATOR_PATH : USER_GENERATOR_PATH;
        d = opendir(generator_path);
        if (!d) {
                if (errno == ENOENT)
                        return;

                log_error("Failed to enumerate generator directory %s: %m",
                          generator_path);
                return;
        }

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

        RUN_WITH_UMASK(0022) {
                execute_directory(generator_path, d, (char**) argv);
        }

        trim_generator_dir(m, &m->generator_unit_path);
        trim_generator_dir(m, &m->generator_unit_path_early);
        trim_generator_dir(m, &m->generator_unit_path_late);

finish:
        if (d)
                closedir(d);
}

static void remove_generator_dir(Manager *m, char **generator) {
        assert(m);
        assert(generator);

        if (!*generator)
                return;

        strv_remove(m->lookup_paths.unit_path, *generator);
        rm_rf(*generator, false, true, false);

        free(*generator);
        *generator = NULL;
}

void manager_undo_generators(Manager *m) {
        assert(m);

        remove_generator_dir(m, &m->generator_unit_path);
        remove_generator_dir(m, &m->generator_unit_path_early);
        remove_generator_dir(m, &m->generator_unit_path_late);
}

int manager_set_default_controllers(Manager *m, char **controllers) {
        char **l;

        assert(m);

        l = strv_copy(controllers);
        if (!l)
                return -ENOMEM;

        strv_free(m->default_controllers);
        m->default_controllers = l;

        cg_shorten_controllers(m->default_controllers);

        return 0;
}

int manager_set_default_rlimits(Manager *m, struct rlimit **default_rlimit) {
        int i;

        assert(m);

        for (i = 0; i < RLIMIT_NLIMITS; i++) {
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

        if (m->running_as != SYSTEMD_SYSTEM)
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

void manager_set_show_status(Manager *m, bool b) {
        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return;

        m->show_status = b;

        if (b)
                touch("/run/systemd/show-status");
        else
                unlink("/run/systemd/show-status");
}

static bool manager_get_show_status(Manager *m) {
        assert(m);

        if (m->running_as != SYSTEMD_SYSTEM)
                return false;

        if (m->show_status)
                return true;

        /* If Plymouth is running make sure we show the status, so
         * that there's something nice to see when people press Esc */

        return plymouth_running();
}

void manager_status_printf(Manager *m, bool ephemeral, const char *status, const char *format, ...) {
        va_list ap;

        if (!manager_get_show_status(m))
                return;

        /* XXX We should totally drop the check for ephemeral here
         * and thus effectively make 'Type=idle' pointless. */
        if (ephemeral && m->n_on_console > 0)
                return;

        if (!manager_is_booting_or_shutting_down(m))
                return;

        va_start(ap, format);
        status_vprintf(status, true, ephemeral, format, ap);
        va_end(ap);
}

void watch_init(Watch *w) {
        assert(w);

        w->type = WATCH_INVALID;
        w->fd = -1;
}
