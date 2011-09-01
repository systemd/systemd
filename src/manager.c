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

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "manager.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "util.h"
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
#include "sd-daemon.h"

/* As soon as 16 units are in our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_ENTRIES_MAX 16

/* As soon as 5s passed since a unit was added to our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_USEC_MAX (10*USEC_PER_SEC)

/* Where clients shall send notification messages to */
#define NOTIFY_SOCKET_SYSTEM "/run/systemd/notify"
#define NOTIFY_SOCKET_USER "@/org/freedesktop/systemd1/notify"

static int manager_setup_notify(Manager *m) {
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa;
        struct epoll_event ev;
        int one = 1, r;
        mode_t u;

        assert(m);

        m->notify_watch.type = WATCH_NOTIFY;
        if ((m->notify_watch.fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)) < 0) {
                log_error("Failed to allocate notification socket: %m");
                return -errno;
        }

        zero(sa);
        sa.sa.sa_family = AF_UNIX;

        if (getpid() != 1)
                snprintf(sa.un.sun_path, sizeof(sa.un.sun_path), NOTIFY_SOCKET_USER "/%llu", random_ull());
        else {
                unlink(NOTIFY_SOCKET_SYSTEM);
                strncpy(sa.un.sun_path, NOTIFY_SOCKET_SYSTEM, sizeof(sa.un.sun_path));
        }

        if (sa.un.sun_path[0] == '@')
                sa.un.sun_path[0] = 0;

        u = umask(0111);
        r = bind(m->notify_watch.fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.un.sun_path+1));
        umask(u);

        if (r < 0) {
                log_error("bind() failed: %m");
                return -errno;
        }

        if (setsockopt(m->notify_watch.fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = &m->notify_watch;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->notify_watch.fd, &ev) < 0)
                return -errno;

        if (sa.un.sun_path[0] == 0)
                sa.un.sun_path[0] = '@';

        if (!(m->notify_socket = strdup(sa.un.sun_path)))
                return -ENOMEM;

        log_debug("Using notification socket %s", m->notify_socket);

        return 0;
}

static int enable_special_signals(Manager *m) {
        int fd;

        assert(m);

        /* Enable that we get SIGINT on control-alt-del */
        if (reboot(RB_DISABLE_CAD) < 0)
                log_warning("Failed to enable ctrl-alt-del handling: %m");

        if ((fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC)) < 0)
                log_warning("Failed to open /dev/tty0: %m");
        else {
                /* Enable that we get SIGWINCH on kbrequest */
                if (ioctl(fd, KDSIGACCEPT, SIGWINCH) < 0)
                        log_warning("Failed to enable kbrequest handling: %s", strerror(errno));

                close_nointr_nofail(fd);
        }

        return 0;
}

static int manager_setup_signals(Manager *m) {
        sigset_t mask;
        struct epoll_event ev;
        struct sigaction sa;

        assert(m);

        /* We are not interested in SIGSTOP and friends. */
        zero(sa);
        sa.sa_handler = SIG_DFL;
        sa.sa_flags = SA_NOCLDSTOP|SA_RESTART;
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
                        SIGRTMIN+27, /* systemd: set log target to console */
                        SIGRTMIN+28, /* systemd: set log target to kmsg */
                        SIGRTMIN+29, /* systemd: set log target to syslog-or-kmsg */
                        -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_watch.type = WATCH_SIGNAL;
        if ((m->signal_watch.fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0)
                return -errno;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = &m->signal_watch;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->signal_watch.fd, &ev) < 0)
                return -errno;

        if (m->running_as == MANAGER_SYSTEM)
                return enable_special_signals(m);

        return 0;
}

int manager_new(ManagerRunningAs running_as, Manager **_m) {
        Manager *m;
        int r = -ENOMEM;

        assert(_m);
        assert(running_as >= 0);
        assert(running_as < _MANAGER_RUNNING_AS_MAX);

        if (!(m = new0(Manager, 1)))
                return -ENOMEM;

        dual_timestamp_get(&m->startup_timestamp);

        m->running_as = running_as;
        m->name_data_slot = m->subscribed_data_slot = -1;
        m->exit_code = _MANAGER_EXIT_CODE_INVALID;
        m->pin_cgroupfs_fd = -1;

#ifdef HAVE_AUDIT
        m->audit_fd = -1;
#endif

        m->signal_watch.fd = m->mount_watch.fd = m->udev_watch.fd = m->epoll_fd = m->dev_autofs_fd = m->swap_watch.fd = -1;
        m->current_job_id = 1; /* start as id #1, so that we can leave #0 around as "null-like" value */

        if (!(m->environment = strv_copy(environ)))
                goto fail;

        if (!(m->default_controllers = strv_new("cpu", NULL)))
                goto fail;

        if (!(m->units = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->transaction_jobs = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->watch_pids = hashmap_new(trivial_hash_func, trivial_compare_func)))
                goto fail;

        if (!(m->cgroup_bondings = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if (!(m->watch_bus = hashmap_new(string_hash_func, string_compare_func)))
                goto fail;

        if ((m->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0)
                goto fail;

        if ((r = lookup_paths_init(&m->lookup_paths, m->running_as, true)) < 0)
                goto fail;

        if ((r = manager_setup_signals(m)) < 0)
                goto fail;

        if ((r = manager_setup_cgroup(m)) < 0)
                goto fail;

        if ((r = manager_setup_notify(m)) < 0)
                goto fail;

        /* Try to connect to the busses, if possible. */
        if ((r = bus_init(m, running_as != MANAGER_SYSTEM)) < 0)
                goto fail;

#ifdef HAVE_AUDIT
        if ((m->audit_fd = audit_open()) < 0)
                log_error("Failed to connect to audit log: %m");
#endif

        m->taint_usr = dir_is_empty("/usr") > 0;

        *_m = m;
        return 0;

fail:
        manager_free(m);
        return r;
}

static unsigned manager_dispatch_cleanup_queue(Manager *m) {
        Meta *meta;
        unsigned n = 0;

        assert(m);

        while ((meta = m->cleanup_queue)) {
                assert(meta->in_cleanup_queue);

                unit_free((Unit*) meta);
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

        if (u->meta.gc_marker == gc_marker + GC_OFFSET_GOOD ||
            u->meta.gc_marker == gc_marker + GC_OFFSET_BAD ||
            u->meta.gc_marker == gc_marker + GC_OFFSET_IN_PATH)
                return;

        if (u->meta.in_cleanup_queue)
                goto bad;

        if (unit_check_gc(u))
                goto good;

        u->meta.gc_marker = gc_marker + GC_OFFSET_IN_PATH;

        is_bad = true;

        SET_FOREACH(other, u->meta.dependencies[UNIT_REFERENCED_BY], i) {
                unit_gc_sweep(other, gc_marker);

                if (other->meta.gc_marker == gc_marker + GC_OFFSET_GOOD)
                        goto good;

                if (other->meta.gc_marker != gc_marker + GC_OFFSET_BAD)
                        is_bad = false;
        }

        if (is_bad)
                goto bad;

        /* We were unable to find anything out about this entry, so
         * let's investigate it later */
        u->meta.gc_marker = gc_marker + GC_OFFSET_UNSURE;
        unit_add_to_gc_queue(u);
        return;

bad:
        /* We definitely know that this one is not useful anymore, so
         * let's mark it for deletion */
        u->meta.gc_marker = gc_marker + GC_OFFSET_BAD;
        unit_add_to_cleanup_queue(u);
        return;

good:
        u->meta.gc_marker = gc_marker + GC_OFFSET_GOOD;
}

static unsigned manager_dispatch_gc_queue(Manager *m) {
        Meta *meta;
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

        while ((meta = m->gc_queue)) {
                assert(meta->in_gc_queue);

                unit_gc_sweep((Unit*) meta, gc_marker);

                LIST_REMOVE(Meta, gc_queue, m->gc_queue, meta);
                meta->in_gc_queue = false;

                n++;

                if (meta->gc_marker == gc_marker + GC_OFFSET_BAD ||
                    meta->gc_marker == gc_marker + GC_OFFSET_UNSURE) {
                        log_debug("Collecting %s", meta->id);
                        meta->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue((Unit*) meta);
                }
        }

        m->n_in_gc_queue = 0;
        m->gc_queue_timestamp = 0;

        return n;
}

static void manager_clear_jobs_and_units(Manager *m) {
        Job *j;
        Unit *u;

        assert(m);

        while ((j = hashmap_first(m->transaction_jobs)))
                job_free(j);

        while ((u = hashmap_first(m->units)))
                unit_free(u);

        manager_dispatch_cleanup_queue(m);

        assert(!m->load_queue);
        assert(!m->run_queue);
        assert(!m->dbus_unit_queue);
        assert(!m->dbus_job_queue);
        assert(!m->cleanup_queue);
        assert(!m->gc_queue);

        assert(hashmap_isempty(m->transaction_jobs));
        assert(hashmap_isempty(m->jobs));
        assert(hashmap_isempty(m->units));
}

void manager_free(Manager *m) {
        UnitType c;

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
        hashmap_free(m->transaction_jobs);
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_bus);

        if (m->epoll_fd >= 0)
                close_nointr_nofail(m->epoll_fd);
        if (m->signal_watch.fd >= 0)
                close_nointr_nofail(m->signal_watch.fd);
        if (m->notify_watch.fd >= 0)
                close_nointr_nofail(m->notify_watch.fd);

#ifdef HAVE_AUDIT
        if (m->audit_fd >= 0)
                audit_close(m->audit_fd);
#endif

        free(m->notify_socket);

        lookup_paths_free(&m->lookup_paths);
        strv_free(m->environment);

        strv_free(m->default_controllers);

        hashmap_free(m->cgroup_bondings);
        set_free_free(m->unit_path_cache);

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
                if (u->meta.id != k)
                        continue;

                if ((q = unit_coldplug(u)) < 0)
                        r = q;
        }

        return r;
}

static void manager_build_unit_path_cache(Manager *m) {
        char **i;
        DIR *d = NULL;
        int r;

        assert(m);

        set_free_free(m->unit_path_cache);

        if (!(m->unit_path_cache = set_new(string_hash_func, string_compare_func))) {
                log_error("Failed to allocate unit path cache.");
                return;
        }

        /* This simply builds a list of files we know exist, so that
         * we don't always have to go to disk */

        STRV_FOREACH(i, m->lookup_paths.unit_path) {
                struct dirent *de;

                if (!(d = opendir(*i))) {
                        log_error("Failed to open directory: %m");
                        continue;
                }

                while ((de = readdir(d))) {
                        char *p;

                        if (ignore_file(de->d_name))
                                continue;

                        p = join(streq(*i, "/") ? "" : *i, "/", de->d_name, NULL);
                        if (!p) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        if ((r = set_put(m->unit_path_cache, p)) < 0) {
                                free(p);
                                goto fail;
                        }
                }

                closedir(d);
                d = NULL;
        }

        return;

fail:
        log_error("Failed to build unit path cache: %s", strerror(-r));

        set_free_free(m->unit_path_cache);
        m->unit_path_cache = NULL;

        if (d)
                closedir(d);
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r, q;

        assert(m);

        manager_run_generators(m);

        manager_build_unit_path_cache(m);

        /* If we will deserialize make sure that during enumeration
         * this is already known, so we increase the counter here
         * already */
        if (serialization)
                m->n_reloading ++;

        /* First, enumerate what we can from all config files */
        r = manager_enumerate(m);

        /* Second, deserialize if there is something to deserialize */
        if (serialization)
                if ((q = manager_deserialize(m, serialization, fds)) < 0)
                        r = q;

        /* Third, fire things up! */
        if ((q = manager_coldplug(m)) < 0)
                r = q;

        if (serialization) {
                assert(m->n_reloading > 0);
                m->n_reloading --;
        }

        return r;
}

static void transaction_delete_job(Manager *m, Job *j, bool delete_dependencies) {
        assert(m);
        assert(j);

        /* Deletes one job from the transaction */

        manager_transaction_unlink_job(m, j, delete_dependencies);

        if (!j->installed)
                job_free(j);
}

static void transaction_delete_unit(Manager *m, Unit *u) {
        Job *j;

        /* Deletes all jobs associated with a certain unit from the
         * transaction */

        while ((j = hashmap_get(m->transaction_jobs, u)))
                transaction_delete_job(m, j, true);
}

static void transaction_clean_dependencies(Manager *m) {
        Iterator i;
        Job *j;

        assert(m);

        /* Drops all dependencies of all installed jobs */

        HASHMAP_FOREACH(j, m->jobs, i) {
                while (j->subject_list)
                        job_dependency_free(j->subject_list);
                while (j->object_list)
                        job_dependency_free(j->object_list);
        }

        assert(!m->transaction_anchor);
}

static void transaction_abort(Manager *m) {
        Job *j;

        assert(m);

        while ((j = hashmap_first(m->transaction_jobs)))
                if (j->installed)
                        transaction_delete_job(m, j, true);
                else
                        job_free(j);

        assert(hashmap_isempty(m->transaction_jobs));

        transaction_clean_dependencies(m);
}

static void transaction_find_jobs_that_matter_to_anchor(Manager *m, Job *j, unsigned generation) {
        JobDependency *l;

        assert(m);

        /* A recursive sweep through the graph that marks all units
         * that matter to the anchor job, i.e. are directly or
         * indirectly a dependency of the anchor job via paths that
         * are fully marked as mattering. */

        if (j)
                l = j->subject_list;
        else
                l = m->transaction_anchor;

        LIST_FOREACH(subject, l, l) {

                /* This link does not matter */
                if (!l->matters)
                        continue;

                /* This unit has already been marked */
                if (l->object->generation == generation)
                        continue;

                l->object->matters_to_anchor = true;
                l->object->generation = generation;

                transaction_find_jobs_that_matter_to_anchor(m, l->object, generation);
        }
}

static void transaction_merge_and_delete_job(Manager *m, Job *j, Job *other, JobType t) {
        JobDependency *l, *last;

        assert(j);
        assert(other);
        assert(j->unit == other->unit);
        assert(!j->installed);

        /* Merges 'other' into 'j' and then deletes j. */

        j->type = t;
        j->state = JOB_WAITING;
        j->override = j->override || other->override;

        j->matters_to_anchor = j->matters_to_anchor || other->matters_to_anchor;

        /* Patch us in as new owner of the JobDependency objects */
        last = NULL;
        LIST_FOREACH(subject, l, other->subject_list) {
                assert(l->subject == other);
                l->subject = j;
                last = l;
        }

        /* Merge both lists */
        if (last) {
                last->subject_next = j->subject_list;
                if (j->subject_list)
                        j->subject_list->subject_prev = last;
                j->subject_list = other->subject_list;
        }

        /* Patch us in as new owner of the JobDependency objects */
        last = NULL;
        LIST_FOREACH(object, l, other->object_list) {
                assert(l->object == other);
                l->object = j;
                last = l;
        }

        /* Merge both lists */
        if (last) {
                last->object_next = j->object_list;
                if (j->object_list)
                        j->object_list->object_prev = last;
                j->object_list = other->object_list;
        }

        /* Kill the other job */
        other->subject_list = NULL;
        other->object_list = NULL;
        transaction_delete_job(m, other, true);
}
static bool job_is_conflicted_by(Job *j) {
        JobDependency *l;

        assert(j);

        /* Returns true if this job is pulled in by a least one
         * ConflictedBy dependency. */

        LIST_FOREACH(object, l, j->object_list)
                if (l->conflicts)
                        return true;

        return false;
}

static int delete_one_unmergeable_job(Manager *m, Job *j) {
        Job *k;

        assert(j);

        /* Tries to delete one item in the linked list
         * j->transaction_next->transaction_next->... that conflicts
         * with another one, in an attempt to make an inconsistent
         * transaction work. */

        /* We rely here on the fact that if a merged with b does not
         * merge with c, either a or b merge with c neither */
        LIST_FOREACH(transaction, j, j)
                LIST_FOREACH(transaction, k, j->transaction_next) {
                        Job *d;

                        /* Is this one mergeable? Then skip it */
                        if (job_type_is_mergeable(j->type, k->type))
                                continue;

                        /* Ok, we found two that conflict, let's see if we can
                         * drop one of them */
                        if (!j->matters_to_anchor && !k->matters_to_anchor) {

                                /* Both jobs don't matter, so let's
                                 * find the one that is smarter to
                                 * remove. Let's think positive and
                                 * rather remove stops then starts --
                                 * except if something is being
                                 * stopped because it is conflicted by
                                 * another unit in which case we
                                 * rather remove the start. */

                                log_debug("Looking at job %s/%s conflicted_by=%s", j->unit->meta.id, job_type_to_string(j->type), yes_no(j->type == JOB_STOP && job_is_conflicted_by(j)));
                                log_debug("Looking at job %s/%s conflicted_by=%s", k->unit->meta.id, job_type_to_string(k->type), yes_no(k->type == JOB_STOP && job_is_conflicted_by(k)));

                                if (j->type == JOB_STOP) {

                                        if (job_is_conflicted_by(j))
                                                d = k;
                                        else
                                                d = j;

                                } else if (k->type == JOB_STOP) {

                                        if (job_is_conflicted_by(k))
                                                d = j;
                                        else
                                                d = k;
                                } else
                                        d = j;

                        } else if (!j->matters_to_anchor)
                                d = j;
                        else if (!k->matters_to_anchor)
                                d = k;
                        else
                                return -ENOEXEC;

                        /* Ok, we can drop one, so let's do so. */
                        log_debug("Fixing conflicting jobs by deleting job %s/%s", d->unit->meta.id, job_type_to_string(d->type));
                        transaction_delete_job(m, d, true);
                        return 0;
                }

        return -EINVAL;
}

static int transaction_merge_jobs(Manager *m, DBusError *e) {
        Job *j;
        Iterator i;
        int r;

        assert(m);

        /* First step, check whether any of the jobs for one specific
         * task conflict. If so, try to drop one of them. */
        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                JobType t;
                Job *k;

                t = j->type;
                LIST_FOREACH(transaction, k, j->transaction_next) {
                        if (job_type_merge(&t, k->type) >= 0)
                                continue;

                        /* OK, we could not merge all jobs for this
                         * action. Let's see if we can get rid of one
                         * of them */

                        if ((r = delete_one_unmergeable_job(m, j)) >= 0)
                                /* Ok, we managed to drop one, now
                                 * let's ask our callers to call us
                                 * again after garbage collecting */
                                return -EAGAIN;

                        /* We couldn't merge anything. Failure */
                        dbus_set_error(e, BUS_ERROR_TRANSACTION_JOBS_CONFLICTING, "Transaction contains conflicting jobs '%s' and '%s' for %s. Probably contradicting requirement dependencies configured.",
                                       job_type_to_string(t), job_type_to_string(k->type), k->unit->meta.id);
                        return r;
                }
        }

        /* Second step, merge the jobs. */
        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                JobType t = j->type;
                Job *k;

                /* Merge all transactions */
                LIST_FOREACH(transaction, k, j->transaction_next)
                        assert_se(job_type_merge(&t, k->type) == 0);

                /* If an active job is mergeable, merge it too */
                if (j->unit->meta.job)
                        job_type_merge(&t, j->unit->meta.job->type); /* Might fail. Which is OK */

                while ((k = j->transaction_next)) {
                        if (j->installed) {
                                transaction_merge_and_delete_job(m, k, j, t);
                                j = k;
                        } else
                                transaction_merge_and_delete_job(m, j, k, t);
                }

                if (j->unit->meta.job && !j->installed)
                        transaction_merge_and_delete_job(m, j, j->unit->meta.job, t);

                assert(!j->transaction_next);
                assert(!j->transaction_prev);
        }

        return 0;
}

static void transaction_drop_redundant(Manager *m) {
        bool again;

        assert(m);

        /* Goes through the transaction and removes all jobs that are
         * a noop */

        do {
                Job *j;
                Iterator i;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                        bool changes_something = false;
                        Job *k;

                        LIST_FOREACH(transaction, k, j) {

                                if (!job_is_anchor(k) &&
                                    (k->installed || job_type_is_redundant(k->type, unit_active_state(k->unit))) &&
                                    (!k->unit->meta.job || !job_type_is_conflicting(k->type, k->unit->meta.job->type)))
                                        continue;

                                changes_something = true;
                                break;
                        }

                        if (changes_something)
                                continue;

                        /* log_debug("Found redundant job %s/%s, dropping.", j->unit->meta.id, job_type_to_string(j->type)); */
                        transaction_delete_job(m, j, false);
                        again = true;
                        break;
                }

        } while (again);
}

static bool unit_matters_to_anchor(Unit *u, Job *j) {
        assert(u);
        assert(!j->transaction_prev);

        /* Checks whether at least one of the jobs for this unit
         * matters to the anchor. */

        LIST_FOREACH(transaction, j, j)
                if (j->matters_to_anchor)
                        return true;

        return false;
}

static int transaction_verify_order_one(Manager *m, Job *j, Job *from, unsigned generation, DBusError *e) {
        Iterator i;
        Unit *u;
        int r;

        assert(m);
        assert(j);
        assert(!j->transaction_prev);

        /* Does a recursive sweep through the ordering graph, looking
         * for a cycle. If we find cycle we try to break it. */

        /* Have we seen this before? */
        if (j->generation == generation) {
                Job *k, *delete;

                /* If the marker is NULL we have been here already and
                 * decided the job was loop-free from here. Hence
                 * shortcut things and return right-away. */
                if (!j->marker)
                        return 0;

                /* So, the marker is not NULL and we already have been
                 * here. We have a cycle. Let's try to break it. We go
                 * backwards in our path and try to find a suitable
                 * job to remove. We use the marker to find our way
                 * back, since smart how we are we stored our way back
                 * in there. */
                log_warning("Found ordering cycle on %s/%s", j->unit->meta.id, job_type_to_string(j->type));

                delete = NULL;
                for (k = from; k; k = ((k->generation == generation && k->marker != k) ? k->marker : NULL)) {

                        log_info("Walked on cycle path to %s/%s", k->unit->meta.id, job_type_to_string(k->type));

                        if (!delete &&
                            !k->installed &&
                            !unit_matters_to_anchor(k->unit, k)) {
                                /* Ok, we can drop this one, so let's
                                 * do so. */
                                delete = k;
                        }

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }


                if (delete) {
                        log_warning("Breaking ordering cycle by deleting job %s/%s", delete->unit->meta.id, job_type_to_string(delete->type));
                        transaction_delete_unit(m, delete->unit);
                        return -EAGAIN;
                }

                log_error("Unable to break cycle");

                dbus_set_error(e, BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC, "Transaction order is cyclic. See system logs for details.");
                return -ENOEXEC;
        }

        /* Make the marker point to where we come from, so that we can
         * find our way backwards if we want to break a cycle. We use
         * a special marker for the beginning: we point to
         * ourselves. */
        j->marker = from ? from : j;
        j->generation = generation;

        /* We assume that the the dependencies are bidirectional, and
         * hence can ignore UNIT_AFTER */
        SET_FOREACH(u, j->unit->meta.dependencies[UNIT_BEFORE], i) {
                Job *o;

                /* Is there a job for this unit? */
                if (!(o = hashmap_get(m->transaction_jobs, u)))

                        /* Ok, there is no job for this in the
                         * transaction, but maybe there is already one
                         * running? */
                        if (!(o = u->meta.job))
                                continue;

                if ((r = transaction_verify_order_one(m, o, j, generation, e)) < 0)
                        return r;
        }

        /* Ok, let's backtrack, and remember that this entry is not on
         * our path anymore. */
        j->marker = NULL;

        return 0;
}

static int transaction_verify_order(Manager *m, unsigned *generation, DBusError *e) {
        Job *j;
        int r;
        Iterator i;
        unsigned g;

        assert(m);
        assert(generation);

        /* Check if the ordering graph is cyclic. If it is, try to fix
         * that up by dropping one of the jobs. */

        g = (*generation)++;

        HASHMAP_FOREACH(j, m->transaction_jobs, i)
                if ((r = transaction_verify_order_one(m, j, NULL, g, e)) < 0)
                        return r;

        return 0;
}

static void transaction_collect_garbage(Manager *m) {
        bool again;

        assert(m);

        /* Drop jobs that are not required by any other job */

        do {
                Iterator i;
                Job *j;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                        if (j->object_list) {
                                /* log_debug("Keeping job %s/%s because of %s/%s", */
                                /*           j->unit->meta.id, job_type_to_string(j->type), */
                                /*           j->object_list->subject ? j->object_list->subject->unit->meta.id : "root", */
                                /*           j->object_list->subject ? job_type_to_string(j->object_list->subject->type) : "root"); */
                                continue;
                        }

                        /* log_debug("Garbage collecting job %s/%s", j->unit->meta.id, job_type_to_string(j->type)); */
                        transaction_delete_job(m, j, true);
                        again = true;
                        break;
                }

        } while (again);
}

static int transaction_is_destructive(Manager *m, DBusError *e) {
        Iterator i;
        Job *j;

        assert(m);

        /* Checks whether applying this transaction means that
         * existing jobs would be replaced */

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {

                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->unit->meta.job &&
                    j->unit->meta.job != j &&
                    !job_type_is_superset(j->type, j->unit->meta.job->type)) {

                        dbus_set_error(e, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE, "Transaction is destructive.");
                        return -EEXIST;
                }
        }

        return 0;
}

static void transaction_minimize_impact(Manager *m) {
        bool again;
        assert(m);

        /* Drops all unnecessary jobs that reverse already active jobs
         * or that stop a running service. */

        do {
                Job *j;
                Iterator i;

                again = false;

                HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                        LIST_FOREACH(transaction, j, j) {
                                bool stops_running_service, changes_existing_job;

                                /* If it matters, we shouldn't drop it */
                                if (j->matters_to_anchor)
                                        continue;

                                /* Would this stop a running service?
                                 * Would this change an existing job?
                                 * If so, let's drop this entry */

                                stops_running_service =
                                        j->type == JOB_STOP && UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(j->unit));

                                changes_existing_job =
                                        j->unit->meta.job &&
                                        job_type_is_conflicting(j->type, j->unit->meta.job->type);

                                if (!stops_running_service && !changes_existing_job)
                                        continue;

                                if (stops_running_service)
                                        log_debug("%s/%s would stop a running service.", j->unit->meta.id, job_type_to_string(j->type));

                                if (changes_existing_job)
                                        log_debug("%s/%s would change existing job.", j->unit->meta.id, job_type_to_string(j->type));

                                /* Ok, let's get rid of this */
                                log_debug("Deleting %s/%s to minimize impact.", j->unit->meta.id, job_type_to_string(j->type));

                                transaction_delete_job(m, j, true);
                                again = true;
                                break;
                        }

                        if (again)
                                break;
                }

        } while (again);
}

static int transaction_apply(Manager *m, JobMode mode) {
        Iterator i;
        Job *j;
        int r;

        /* Moves the transaction jobs to the set of active jobs */

        if (mode == JOB_ISOLATE) {

                /* When isolating first kill all installed jobs which
                 * aren't part of the new transaction */
                HASHMAP_FOREACH(j, m->jobs, i) {
                        assert(j->installed);

                        if (hashmap_get(m->transaction_jobs, j->unit))
                                continue;

                        job_finish_and_invalidate(j, JOB_CANCELED);
                }
        }

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                /* Assume merged */
                assert(!j->transaction_prev);
                assert(!j->transaction_next);

                if (j->installed)
                        continue;

                if ((r = hashmap_put(m->jobs, UINT32_TO_PTR(j->id), j)) < 0)
                        goto rollback;
        }

        while ((j = hashmap_steal_first(m->transaction_jobs))) {
                if (j->installed) {
                        /* log_debug("Skipping already installed job %s/%s as %u", j->unit->meta.id, job_type_to_string(j->type), (unsigned) j->id); */
                        continue;
                }

                if (j->unit->meta.job)
                        job_free(j->unit->meta.job);

                j->unit->meta.job = j;
                j->installed = true;
                m->n_installed_jobs ++;

                /* We're fully installed. Now let's free data we don't
                 * need anymore. */

                assert(!j->transaction_next);
                assert(!j->transaction_prev);

                job_add_to_run_queue(j);
                job_add_to_dbus_queue(j);
                job_start_timer(j);

                log_debug("Installed new job %s/%s as %u", j->unit->meta.id, job_type_to_string(j->type), (unsigned) j->id);
        }

        /* As last step, kill all remaining job dependencies. */
        transaction_clean_dependencies(m);

        return 0;

rollback:

        HASHMAP_FOREACH(j, m->transaction_jobs, i) {
                if (j->installed)
                        continue;

                hashmap_remove(m->jobs, UINT32_TO_PTR(j->id));
        }

        return r;
}

static int transaction_activate(Manager *m, JobMode mode, DBusError *e) {
        int r;
        unsigned generation = 1;

        assert(m);

        /* This applies the changes recorded in transaction_jobs to
         * the actual list of jobs, if possible. */

        /* First step: figure out which jobs matter */
        transaction_find_jobs_that_matter_to_anchor(m, NULL, generation++);

        /* Second step: Try not to stop any running services if
         * we don't have to. Don't try to reverse running
         * jobs if we don't have to. */
        if (mode == JOB_FAIL)
                transaction_minimize_impact(m);

        /* Third step: Drop redundant jobs */
        transaction_drop_redundant(m);

        for (;;) {
                /* Fourth step: Let's remove unneeded jobs that might
                 * be lurking. */
                if (mode != JOB_ISOLATE)
                        transaction_collect_garbage(m);

                /* Fifth step: verify order makes sense and correct
                 * cycles if necessary and possible */
                if ((r = transaction_verify_order(m, &generation, e)) >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_warning("Requested transaction contains an unfixable cyclic ordering dependency: %s", bus_error(e, r));
                        goto rollback;
                }

                /* Let's see if the resulting transaction ordering
                 * graph is still cyclic... */
        }

        for (;;) {
                /* Sixth step: let's drop unmergeable entries if
                 * necessary and possible, merge entries we can
                 * merge */
                if ((r = transaction_merge_jobs(m, e)) >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_warning("Requested transaction contains unmergeable jobs: %s", bus_error(e, r));
                        goto rollback;
                }

                /* Seventh step: an entry got dropped, let's garbage
                 * collect its dependencies. */
                if (mode != JOB_ISOLATE)
                        transaction_collect_garbage(m);

                /* Let's see if the resulting transaction still has
                 * unmergeable entries ... */
        }

        /* Eights step: Drop redundant jobs again, if the merging now allows us to drop more. */
        transaction_drop_redundant(m);

        /* Ninth step: check whether we can actually apply this */
        if (mode == JOB_FAIL)
                if ((r = transaction_is_destructive(m, e)) < 0) {
                        log_notice("Requested transaction contradicts existing jobs: %s", bus_error(e, r));
                        goto rollback;
                }

        /* Tenth step: apply changes */
        if ((r = transaction_apply(m, mode)) < 0) {
                log_warning("Failed to apply transaction: %s", strerror(-r));
                goto rollback;
        }

        assert(hashmap_isempty(m->transaction_jobs));
        assert(!m->transaction_anchor);

        return 0;

rollback:
        transaction_abort(m);
        return r;
}

static Job* transaction_add_one_job(Manager *m, JobType type, Unit *unit, bool override, bool *is_new) {
        Job *j, *f;

        assert(m);
        assert(unit);

        /* Looks for an existing prospective job and returns that. If
         * it doesn't exist it is created and added to the prospective
         * jobs list. */

        f = hashmap_get(m->transaction_jobs, unit);

        LIST_FOREACH(transaction, j, f) {
                assert(j->unit == unit);

                if (j->type == type) {
                        if (is_new)
                                *is_new = false;
                        return j;
                }
        }

        if (unit->meta.job && unit->meta.job->type == type)
                j = unit->meta.job;
        else if (!(j = job_new(m, type, unit)))
                return NULL;

        j->generation = 0;
        j->marker = NULL;
        j->matters_to_anchor = false;
        j->override = override;

        LIST_PREPEND(Job, transaction, f, j);

        if (hashmap_replace(m->transaction_jobs, unit, f) < 0) {
                job_free(j);
                return NULL;
        }

        if (is_new)
                *is_new = true;

        /* log_debug("Added job %s/%s to transaction.", unit->meta.id, job_type_to_string(type)); */

        return j;
}

void manager_transaction_unlink_job(Manager *m, Job *j, bool delete_dependencies) {
        assert(m);
        assert(j);

        if (j->transaction_prev)
                j->transaction_prev->transaction_next = j->transaction_next;
        else if (j->transaction_next)
                hashmap_replace(m->transaction_jobs, j->unit, j->transaction_next);
        else
                hashmap_remove_value(m->transaction_jobs, j->unit, j);

        if (j->transaction_next)
                j->transaction_next->transaction_prev = j->transaction_prev;

        j->transaction_prev = j->transaction_next = NULL;

        while (j->subject_list)
                job_dependency_free(j->subject_list);

        while (j->object_list) {
                Job *other = j->object_list->matters ? j->object_list->subject : NULL;

                job_dependency_free(j->object_list);

                if (other && delete_dependencies) {
                        log_debug("Deleting job %s/%s as dependency of job %s/%s",
                                  other->unit->meta.id, job_type_to_string(other->type),
                                  j->unit->meta.id, job_type_to_string(j->type));
                        transaction_delete_job(m, other, delete_dependencies);
                }
        }
}

static int transaction_add_job_and_dependencies(
                Manager *m,
                JobType type,
                Unit *unit,
                Job *by,
                bool matters,
                bool override,
                bool conflicts,
                bool ignore_requirements,
                bool ignore_order,
                DBusError *e,
                Job **_ret) {
        Job *ret;
        Iterator i;
        Unit *dep;
        int r;
        bool is_new;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);

        /* log_debug("Pulling in %s/%s from %s/%s", */
        /*           unit->meta.id, job_type_to_string(type), */
        /*           by ? by->unit->meta.id : "NA", */
        /*           by ? job_type_to_string(by->type) : "NA"); */

        if (unit->meta.load_state != UNIT_LOADED &&
            unit->meta.load_state != UNIT_ERROR &&
            unit->meta.load_state != UNIT_MASKED) {
                dbus_set_error(e, BUS_ERROR_LOAD_FAILED, "Unit %s is not loaded properly.", unit->meta.id);
                return -EINVAL;
        }

        if (type != JOB_STOP && unit->meta.load_state == UNIT_ERROR) {
                dbus_set_error(e, BUS_ERROR_LOAD_FAILED,
                               "Unit %s failed to load: %s. "
                               "See system logs and 'systemctl status %s' for details.",
                               unit->meta.id,
                               strerror(-unit->meta.load_error),
                               unit->meta.id);
                return -EINVAL;
        }

        if (type != JOB_STOP && unit->meta.load_state == UNIT_MASKED) {
                dbus_set_error(e, BUS_ERROR_MASKED, "Unit %s is masked.", unit->meta.id);
                return -EINVAL;
        }

        if (!unit_job_is_applicable(unit, type)) {
                dbus_set_error(e, BUS_ERROR_JOB_TYPE_NOT_APPLICABLE, "Job type %s is not applicable for unit %s.", job_type_to_string(type), unit->meta.id);
                return -EBADR;
        }

        /* First add the job. */
        if (!(ret = transaction_add_one_job(m, type, unit, override, &is_new)))
                return -ENOMEM;

        ret->ignore_order = ret->ignore_order || ignore_order;

        /* Then, add a link to the job. */
        if (!job_dependency_new(by, ret, matters, conflicts))
                return -ENOMEM;

        if (is_new && !ignore_requirements) {
                Set *following;

                /* If we are following some other unit, make sure we
                 * add all dependencies of everybody following. */
                if (unit_following_set(ret->unit, &following) > 0) {
                        SET_FOREACH(dep, following, i)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, false, override, false, false, ignore_order, e, NULL)) < 0) {
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, bus_error(e, r));

                                        if (e)
                                                dbus_error_free(e);
                                }

                        set_free(following);
                }

                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RELOAD_OR_START) {
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRES], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, override, false, false, ignore_order, e, NULL)) < 0) {
                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_BIND_TO], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, override, false, false, ignore_order, e, NULL)) < 0) {

                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, !override, override, false, false, ignore_order, e, NULL)) < 0) {
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, bus_error(e, r));

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_WANTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, false, false, false, false, ignore_order, e, NULL)) < 0) {
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, bus_error(e, r));

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUISITE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, true, override, false, false, ignore_order, e, NULL)) < 0) {

                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUISITE_OVERRIDABLE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, !override, override, false, false, ignore_order, e, NULL)) < 0) {
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, bus_error(e, r));

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_CONFLICTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, true, override, true, false, ignore_order, e, NULL)) < 0) {

                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_CONFLICTED_BY], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, false, override, false, false, ignore_order, e, NULL)) < 0) {
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, bus_error(e, r));

                                        if (e)
                                                dbus_error_free(e);
                                }

                } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRED_BY], i)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, override, false, false, ignore_order, e, NULL)) < 0) {

                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_BOUND_BY], i)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, override, false, false, ignore_order, e, NULL)) < 0) {

                                        if (r != -EBADR)
                                                goto fail;

                                        if (e)
                                                dbus_error_free(e);
                                }
                }

                /* JOB_VERIFY_STARTED, JOB_RELOAD require no dependency handling */
        }

        if (_ret)
                *_ret = ret;

        return 0;

fail:
        return r;
}

static int transaction_add_isolate_jobs(Manager *m) {
        Iterator i;
        Unit *u;
        char *k;
        int r;

        assert(m);

        HASHMAP_FOREACH_KEY(u, k, m->units, i) {

                /* ignore aliases */
                if (u->meta.id != k)
                        continue;

                if (u->meta.ignore_on_isolate)
                        continue;

                /* No need to stop inactive jobs */
                if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)) && !u->meta.job)
                        continue;

                /* Is there already something listed for this? */
                if (hashmap_get(m->transaction_jobs, u))
                        continue;

                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, u, NULL, true, false, false, false, false, NULL, NULL)) < 0)
                        log_warning("Cannot add isolate job for unit %s, ignoring: %s", u->meta.id, strerror(-r));
        }

        return 0;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool override, DBusError *e, Job **_ret) {
        int r;
        Job *ret;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START) {
                dbus_set_error(e, BUS_ERROR_INVALID_JOB_MODE, "Isolate is only valid for start.");
                return -EINVAL;
        }

        if (mode == JOB_ISOLATE && !unit->meta.allow_isolate) {
                dbus_set_error(e, BUS_ERROR_NO_ISOLATION, "Operation refused, unit may not be isolated.");
                return -EPERM;
        }

        log_debug("Trying to enqueue job %s/%s/%s", unit->meta.id, job_type_to_string(type), job_mode_to_string(mode));

        if ((r = transaction_add_job_and_dependencies(m, type, unit, NULL, true, override, false,
                                                      mode == JOB_IGNORE_DEPENDENCIES || mode == JOB_IGNORE_REQUIREMENTS,
                                                      mode == JOB_IGNORE_DEPENDENCIES, e, &ret)) < 0) {
                transaction_abort(m);
                return r;
        }

        if (mode == JOB_ISOLATE)
                if ((r = transaction_add_isolate_jobs(m)) < 0) {
                        transaction_abort(m);
                        return r;
                }

        if ((r = transaction_activate(m, mode, e)) < 0)
                return r;

        log_debug("Enqueued job %s/%s as %u", unit->meta.id, job_type_to_string(type), (unsigned) ret->id);

        if (_ret)
                *_ret = ret;

        return 0;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool override, DBusError *e, Job **_ret) {
        Unit *unit;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        if ((r = manager_load_unit(m, name, NULL, NULL, &unit)) < 0)
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
        Meta *meta;
        unsigned n = 0;

        assert(m);

        /* Make sure we are not run recursively */
        if (m->dispatching_load_queue)
                return 0;

        m->dispatching_load_queue = true;

        /* Dispatches the load queue. Takes a unit from the queue and
         * tries to load its data until the queue is empty */

        while ((meta = m->load_queue)) {
                assert(meta->in_load_queue);

                unit_load((Unit*) meta);
                n++;
        }

        m->dispatching_load_queue = false;
        return n;
}

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, DBusError *e, Unit **_ret) {
        Unit *ret;
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
                name = file_name_from_path(path);

        if (!unit_name_is_valid(name, false)) {
                dbus_set_error(e, BUS_ERROR_INVALID_NAME, "Unit name %s is not valid.", name);
                return -EINVAL;
        }

        if ((ret = manager_get_unit(m, name))) {
                *_ret = ret;
                return 1;
        }

        if (!(ret = unit_new(m)))
                return -ENOMEM;

        if (path)
                if (!(ret->meta.fragment_path = strdup(path))) {
                        unit_free(ret);
                        return -ENOMEM;
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

        if ((r = manager_load_unit_prepare(m, name, path, e, _ret)) != 0)
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
                if (u->meta.id == t)
                        unit_dump(u, f, prefix);
}

void manager_clear_jobs(Manager *m) {
        Job *j;

        assert(m);

        transaction_abort(m);

        while ((j = hashmap_first(m->jobs)))
                job_finish_and_invalidate(j, JOB_CANCELED);
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
        return n;
}

unsigned manager_dispatch_dbus_queue(Manager *m) {
        Job *j;
        Meta *meta;
        unsigned n = 0;

        assert(m);

        if (m->dispatching_dbus_queue)
                return 0;

        m->dispatching_dbus_queue = true;

        while ((meta = m->dbus_unit_queue)) {
                assert(meta->in_dbus_queue);

                bus_unit_send_change_signal((Unit*) meta);
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
                struct msghdr msghdr;
                struct iovec iovec;
                struct ucred *ucred;
                union {
                        struct cmsghdr cmsghdr;
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
                } control;
                Unit *u;
                char **tags;

                zero(iovec);
                iovec.iov_base = buf;
                iovec.iov_len = sizeof(buf)-1;

                zero(control);
                zero(msghdr);
                msghdr.msg_iov = &iovec;
                msghdr.msg_iovlen = 1;
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                if ((n = recvmsg(m->notify_watch.fd, &msghdr, MSG_DONTWAIT)) <= 0) {
                        if (n >= 0)
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

                if (!(u = hashmap_get(m->watch_pids, LONG_TO_PTR(ucred->pid))))
                        if (!(u = cgroup_unit_by_pid(m, ucred->pid))) {
                                log_warning("Cannot find unit for notify message of PID %lu.", (unsigned long) ucred->pid);
                                continue;
                        }

                assert((size_t) n < sizeof(buf));
                buf[n] = 0;
                if (!(tags = strv_split(buf, "\n\r")))
                        return -ENOMEM;

                log_debug("Got notification message for unit %s", u->meta.id);

                if (UNIT_VTABLE(u)->notify_message)
                        UNIT_VTABLE(u)->notify_message(u, ucred->pid, tags);

                strv_free(tags);
        }

        return 0;
}

static int manager_dispatch_sigchld(Manager *m) {
        assert(m);

        for (;;) {
                siginfo_t si;
                Unit *u;
                int r;

                zero(si);

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
                        char *name = NULL;

                        get_process_name(si.si_pid, &name);
                        log_debug("Got SIGCHLD for process %lu (%s)", (unsigned long) si.si_pid, strna(name));
                        free(name);
                }

                /* Let's flush any message the dying child might still
                 * have queued for us. This ensures that the process
                 * still exists in /proc so that we can figure out
                 * which cgroup and hence unit it belongs to. */
                if ((r = manager_process_notify_fd(m)) < 0)
                        return r;

                /* And now figure out the unit this belongs to */
                if (!(u = hashmap_get(m->watch_pids, LONG_TO_PTR(si.si_pid))))
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

                log_debug("Child %lu belongs to %s", (long unsigned) si.si_pid, u->meta.id);

                hashmap_remove(m->watch_pids, LONG_TO_PTR(si.si_pid));
                UNIT_VTABLE(u)->sigchld_event(u, si.si_pid, si.si_code, si.si_status);
        }

        return 0;
}

static int manager_start_target(Manager *m, const char *name, JobMode mode) {
        int r;
        DBusError error;

        dbus_error_init(&error);

        log_debug("Activating special unit %s", name);

        if ((r = manager_add_job_by_name(m, JOB_START, name, mode, true, &error, NULL)) < 0)
                log_error("Failed to enqueue %s job: %s", name, bus_error(&error, r));

        dbus_error_free(&error);

        return r;
}

static int manager_process_signal_fd(Manager *m) {
        ssize_t n;
        struct signalfd_siginfo sfsi;
        bool sigchld = false;

        assert(m);

        for (;;) {
                if ((n = read(m->signal_watch.fd, &sfsi, sizeof(sfsi))) != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                break;

                        return -errno;
                }

                if (sfsi.ssi_pid > 0) {
                        char *p = NULL;

                        get_process_name(sfsi.ssi_pid, &p);

                        log_debug("Received SIG%s from PID %lu (%s).",
                                  strna(signal_to_string(sfsi.ssi_signo)),
                                  (unsigned long) sfsi.ssi_pid, strna(p));
                        free(p);
                } else
                        log_debug("Received SIG%s.", strna(signal_to_string(sfsi.ssi_signo)));

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
                                manager_start_target(m, target_table[sfsi.ssi_signo - SIGRTMIN],
                                                     (sfsi.ssi_signo == 1 || sfsi.ssi_signo == 2) ? JOB_ISOLATE : JOB_REPLACE);
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
                                log_warning("Got unhandled signal <%s>.", strna(signal_to_string(sfsi.ssi_signo)));
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
                if ((k = read(w->fd, &v, sizeof(v))) != sizeof(v)) {

                        if (k < 0 && (errno == EINTR || errno == EAGAIN))
                                break;

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
        if ((r = manager_dispatch_sigchld(m)) < 0)
                return r;

        while (m->exit_code == MANAGER_RUNNING) {
                struct epoll_event event;
                int n;

                if (!ratelimit_test(&rl)) {
                        /* Yay, something is going seriously wrong, pause a little */
                        log_warning("Looping too fast. Throttling execution a little.");
                        sleep(1);
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

                if ((n = epoll_wait(m->epoll_fd, &event, 1, -1)) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                assert(n == 1);

                if ((r = process_event(m, &event)) < 0)
                        return r;
        }

        return m->exit_code;
}

int manager_get_unit_from_dbus_path(Manager *m, const char *s, Unit **_u) {
        char *n;
        Unit *u;

        assert(m);
        assert(s);
        assert(_u);

        if (!startswith(s, "/org/freedesktop/systemd1/unit/"))
                return -EINVAL;

        if (!(n = bus_path_unescape(s+31)))
                return -ENOMEM;

        u = manager_get_unit(m, n);
        free(n);

        if (!u)
                return -ENOENT;

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

        if ((r = safe_atou(s + 30, &id)) < 0)
                return r;

        if (!(j = manager_get_job(m, id)))
                return -ENOENT;

        *_j = j;

        return 0;
}

void manager_send_unit_audit(Manager *m, Unit *u, int type, bool success) {

#ifdef HAVE_AUDIT
        char *p;

        if (m->audit_fd < 0)
                return;

        /* Don't generate audit events if the service was already
         * started and we're just deserializing */
        if (m->n_reloading > 0)
                return;

        if (m->running_as != MANAGER_SYSTEM)
                return;

        if (u->meta.type != UNIT_SERVICE)
                return;

        if (!(p = unit_name_to_prefix_and_instance(u->meta.id))) {
                log_error("Failed to allocate unit name for audit message: %s", strerror(ENOMEM));
                return;
        }

        if (audit_log_user_comm_message(m->audit_fd, type, "", p, NULL, NULL, NULL, success) < 0) {
                log_warning("Failed to send audit message: %m");

                if (errno == EPERM) {
                        /* We aren't allowed to send audit messages?
                         * Then let's not retry again, to avoid
                         * spamming the user with the same and same
                         * messages over and over. */

                        audit_close(m->audit_fd);
                        m->audit_fd = -1;
                }
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

        if (m->running_as != MANAGER_SYSTEM)
                return;

        if (u->meta.type != UNIT_SERVICE &&
            u->meta.type != UNIT_MOUNT &&
            u->meta.type != UNIT_SWAP)
                return;

        /* We set SOCK_NONBLOCK here so that we rather drop the
         * message then wait for plymouth */
        if ((fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)) < 0) {
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

        if (asprintf(&message, "U\002%c%s%n", (int) (strlen(u->meta.id) + 1), u->meta.id, &n) < 0) {
                log_error("Out of memory");
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
        mode_t saved_umask;
        int fd;
        FILE *f;

        assert(_f);

        if (m->running_as == MANAGER_SYSTEM)
                asprintf(&path, "/run/systemd/dump-%lu-XXXXXX", (unsigned long) getpid());
        else
                asprintf(&path, "/tmp/systemd-dump-%lu-XXXXXX", (unsigned long) getpid());

        if (!path)
                return -ENOMEM;

        saved_umask = umask(0077);
        fd = mkostemp(path, O_RDWR|O_CLOEXEC);
        umask(saved_umask);

        if (fd < 0) {
                free(path);
                return -errno;
        }

        unlink(path);

        log_debug("Serializing state to %s", path);
        free(path);

        if (!(f = fdopen(fd, "w+")))
                return -errno;

        *_f = f;

        return 0;
}

int manager_serialize(Manager *m, FILE *f, FDSet *fds) {
        Iterator i;
        Unit *u;
        const char *t;
        int r;

        assert(m);
        assert(f);
        assert(fds);

        m->n_reloading ++;

        fprintf(f, "current-job-id=%i\n", m->current_job_id);
        fprintf(f, "taint-usr=%s\n", yes_no(m->taint_usr));

        dual_timestamp_serialize(f, "initrd-timestamp", &m->initrd_timestamp);
        dual_timestamp_serialize(f, "startup-timestamp", &m->startup_timestamp);
        dual_timestamp_serialize(f, "finish-timestamp", &m->finish_timestamp);

        fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->meta.id != t)
                        continue;

                if (!unit_can_serialize(u))
                        continue;

                /* Start marker */
                fputs(u->meta.id, f);
                fputc('\n', f);

                if ((r = unit_serialize(u, f, fds)) < 0) {
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
                } else if (startswith(l, "taint-usr=")) {
                        int b;

                        if ((b = parse_boolean(l+10)) < 0)
                                log_debug("Failed to parse taint /usr flag %s", l+10);
                        else
                                m->taint_usr = m->taint_usr || b;
                } else if (startswith(l, "initrd-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->initrd_timestamp);
                else if (startswith(l, "startup-timestamp="))
                        dual_timestamp_deserialize(l+18, &m->startup_timestamp);
                else if (startswith(l, "finish-timestamp="))
                        dual_timestamp_deserialize(l+17, &m->finish_timestamp);
                else
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

                if ((r = manager_load_unit(m, strstrip(name), NULL, NULL, &u)) < 0)
                        goto finish;

                if ((r = unit_deserialize(u, f, fds)) < 0)
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

int manager_reload(Manager *m) {
        int r, q;
        FILE *f;
        FDSet *fds;

        assert(m);

        if ((r = manager_open_serialization(m, &f)) < 0)
                return r;

        m->n_reloading ++;

        if (!(fds = fdset_new())) {
                m->n_reloading --;
                r = -ENOMEM;
                goto finish;
        }

        if ((r = manager_serialize(m, f, fds)) < 0) {
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

        /* Find new unit paths */
        lookup_paths_free(&m->lookup_paths);
        if ((q = lookup_paths_init(&m->lookup_paths, m->running_as, true)) < 0)
                r = q;

        manager_run_generators(m);

        manager_build_unit_path_cache(m);

        /* First, enumerate what we can from all config files */
        if ((q = manager_enumerate(m)) < 0)
                r = q;

        /* Second, deserialize our stored data */
        if ((q = manager_deserialize(m, f, fds)) < 0)
                r = q;

        fclose(f);
        f = NULL;

        /* Third, fire things up! */
        if ((q = manager_coldplug(m)) < 0)
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

bool manager_is_booting_or_shutting_down(Manager *m) {
        Unit *u;

        assert(m);

        /* Is the initial job still around? */
        if (manager_get_job(m, 1))
                return true;

        /* Is there a job for the shutdown target? */
        u = manager_get_unit(m, SPECIAL_SHUTDOWN_TARGET);
        if (u)
                return !!u->meta.job;

        return false;
}

void manager_reset_failed(Manager *m) {
        Unit *u;
        Iterator i;

        assert(m);

        HASHMAP_FOREACH(u, m->units, i)
                unit_reset_failed(u);
}

bool manager_unit_pending_inactive(Manager *m, const char *name) {
        Unit *u;

        assert(m);
        assert(name);

        /* Returns true if the unit is inactive or going down */
        if (!(u = manager_get_unit(m, name)))
                return true;

        return unit_pending_inactive(u);
}

void manager_check_finished(Manager *m) {
        char userspace[FORMAT_TIMESPAN_MAX], initrd[FORMAT_TIMESPAN_MAX], kernel[FORMAT_TIMESPAN_MAX], sum[FORMAT_TIMESPAN_MAX];
        usec_t kernel_usec = 0, initrd_usec = 0, userspace_usec = 0, total_usec = 0;

        assert(m);

        if (dual_timestamp_is_set(&m->finish_timestamp))
                return;

        if (hashmap_size(m->jobs) > 0)
                return;

        dual_timestamp_get(&m->finish_timestamp);

        if (m->running_as == MANAGER_SYSTEM && detect_container(NULL) <= 0) {

                userspace_usec = m->finish_timestamp.monotonic - m->startup_timestamp.monotonic;
                total_usec = m->finish_timestamp.monotonic;

                if (dual_timestamp_is_set(&m->initrd_timestamp)) {

                        kernel_usec = m->initrd_timestamp.monotonic;
                        initrd_usec = m->startup_timestamp.monotonic - m->initrd_timestamp.monotonic;

                        log_info("Startup finished in %s (kernel) + %s (initrd) + %s (userspace) = %s.",
                                 format_timespan(kernel, sizeof(kernel), kernel_usec),
                                 format_timespan(initrd, sizeof(initrd), initrd_usec),
                                 format_timespan(userspace, sizeof(userspace), userspace_usec),
                                 format_timespan(sum, sizeof(sum), total_usec));
                } else {
                        kernel_usec = m->startup_timestamp.monotonic;
                        initrd_usec = 0;

                        log_info("Startup finished in %s (kernel) + %s (userspace) = %s.",
                                 format_timespan(kernel, sizeof(kernel), kernel_usec),
                                 format_timespan(userspace, sizeof(userspace), userspace_usec),
                                 format_timespan(sum, sizeof(sum), total_usec));
                }
        } else {
                userspace_usec = initrd_usec = kernel_usec = 0;
                total_usec = m->finish_timestamp.monotonic - m->startup_timestamp.monotonic;

                log_debug("Startup finished in %s.",
                          format_timespan(sum, sizeof(sum), total_usec));
        }

        bus_broadcast_finished(m, kernel_usec, initrd_usec, userspace_usec, total_usec);

        sd_notifyf(false,
                   "READY=1\nSTATUS=Startup finished in %s.",
                   format_timespan(sum, sizeof(sum), total_usec));
}

void manager_run_generators(Manager *m) {
        DIR *d = NULL;
        const char *generator_path;
        const char *argv[3];
        mode_t u;

        assert(m);

        generator_path = m->running_as == MANAGER_SYSTEM ? SYSTEM_GENERATOR_PATH : USER_GENERATOR_PATH;
        if (!(d = opendir(generator_path))) {

                if (errno == ENOENT)
                        return;

                log_error("Failed to enumerate generator directory: %m");
                return;
        }

        if (!m->generator_unit_path) {
                const char *p;
                char user_path[] = "/tmp/systemd-generator-XXXXXX";

                if (m->running_as == MANAGER_SYSTEM && getpid() == 1) {
                        p = "/run/systemd/generator";

                        if (mkdir_p(p, 0755) < 0) {
                                log_error("Failed to create generator directory: %m");
                                goto finish;
                        }

                } else {
                        if (!(p = mkdtemp(user_path))) {
                                log_error("Failed to create generator directory: %m");
                                goto finish;
                        }
                }

                if (!(m->generator_unit_path = strdup(p))) {
                        log_error("Failed to allocate generator unit path.");
                        goto finish;
                }
        }

        argv[0] = NULL; /* Leave this empty, execute_directory() will fill something in */
        argv[1] = m->generator_unit_path;
        argv[2] = NULL;

        u = umask(0022);
        execute_directory(generator_path, d, (char**) argv);
        umask(u);

        if (rmdir(m->generator_unit_path) >= 0) {
                /* Uh? we were able to remove this dir? I guess that
                 * means the directory was empty, hence let's shortcut
                 * this */

                free(m->generator_unit_path);
                m->generator_unit_path = NULL;
                goto finish;
        }

        if (!strv_find(m->lookup_paths.unit_path, m->generator_unit_path)) {
                char **l;

                if (!(l = strv_append(m->lookup_paths.unit_path, m->generator_unit_path))) {
                        log_error("Failed to add generator directory to unit search path: %m");
                        goto finish;
                }

                strv_free(m->lookup_paths.unit_path);
                m->lookup_paths.unit_path = l;

                log_debug("Added generator unit path %s to search path.", m->generator_unit_path);
        }

finish:
        if (d)
                closedir(d);
}

void manager_undo_generators(Manager *m) {
        assert(m);

        if (!m->generator_unit_path)
                return;

        strv_remove(m->lookup_paths.unit_path, m->generator_unit_path);
        rm_rf(m->generator_unit_path, false, true, false);

        free(m->generator_unit_path);
        m->generator_unit_path = NULL;
}

int manager_set_default_controllers(Manager *m, char **controllers) {
        char **l;

        assert(m);

        if (!(l = strv_copy(controllers)))
                return -ENOMEM;

        strv_free(m->default_controllers);
        m->default_controllers = l;

        return 0;
}

void manager_recheck_syslog(Manager *m) {
        Unit *u;

        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return;

        if ((u = manager_get_unit(m, SPECIAL_SYSLOG_SOCKET))) {
                SocketState state;

                state = SOCKET(u)->state;

                if (state != SOCKET_DEAD &&
                    state != SOCKET_FAILED &&
                    state != SOCKET_RUNNING) {

                        /* Hmm, the socket is not set up, or is still
                         * listening, let's better not try to use
                         * it. Note that we have no problem if the
                         * socket is completely down, since there
                         * might be a foreign /dev/log socket around
                         * and we want to make use of that.
                         */

                        log_close_syslog();
                        return;
                }
        }

        if ((u = manager_get_unit(m, SPECIAL_SYSLOG_TARGET)))
                if (TARGET(u)->state != TARGET_ACTIVE) {
                        log_close_syslog();
                        return;
                }

        /* Hmm, OK, so the socket is either fully up, or fully down,
         * and the target is up, then let's make use of the socket */
        log_open();
}

void manager_set_show_status(Manager *m, bool b) {
        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return;

        m->show_status = b;

        if (b)
                touch("/run/systemd/show-status");
        else
                unlink("/run/systemd/show-status");
}

bool manager_get_show_status(Manager *m) {
        assert(m);

        if (m->running_as != MANAGER_SYSTEM)
                return false;

        if (m->show_status)
                return true;

        /* If Plymouth is running make sure we show the status, so
         * that there's something nice to see when people press Esc */

        return plymouth_running();
}

static const char* const manager_running_as_table[_MANAGER_RUNNING_AS_MAX] = {
        [MANAGER_SYSTEM] = "system",
        [MANAGER_USER] = "user"
};

DEFINE_STRING_TABLE_LOOKUP(manager_running_as, ManagerRunningAs);
