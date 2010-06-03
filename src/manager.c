/*-*- Mode: C; c-basic-offset: 8 -*-*/

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
#include <utmpx.h>
#include <sys/poll.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <libcgroup.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "manager.h"
#include "hashmap.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "util.h"
#include "ratelimit.h"
#include "cgroup.h"
#include "mount-setup.h"
#include "utmp-wtmp.h"
#include "unit-name.h"
#include "dbus-unit.h"
#include "dbus-job.h"
#include "missing.h"

/* As soon as 16 units are in our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_ENTRIES_MAX 16

/* As soon as 5s passed since a unit was added to our GC queue, make sure to run a gc sweep */
#define GC_QUEUE_USEC_MAX (10*USEC_PER_SEC)

static int enable_special_signals(Manager *m) {
        char fd;

        assert(m);

        /* Enable that we get SIGINT on control-alt-del */
        if (reboot(RB_DISABLE_CAD) < 0)
                log_warning("Failed to enable ctrl-alt-del handling: %m");

        if ((fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY)) < 0)
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
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigaddset(&mask, SIGTERM) == 0);
        assert_se(sigaddset(&mask, SIGHUP) == 0);
        assert_se(sigaddset(&mask, SIGUSR1) == 0);
        assert_se(sigaddset(&mask, SIGUSR2) == 0);
        assert_se(sigaddset(&mask, SIGINT) == 0);   /* Kernel sends us this on control-alt-del */
        assert_se(sigaddset(&mask, SIGWINCH) == 0); /* Kernel sends us this on kbrequest (alt-arrowup) */
        assert_se(sigaddset(&mask, SIGPWR) == 0);   /* Some kernel drivers and upsd send us this on power failure */
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        m->signal_watch.type = WATCH_SIGNAL;
        if ((m->signal_watch.fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0)
                return -errno;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = &m->signal_watch;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->signal_watch.fd, &ev) < 0)
                return -errno;

        if (m->running_as == MANAGER_INIT)
                return enable_special_signals(m);

        return 0;
}

static char** session_dirs(void) {
        const char *home, *e;
        char *config_home = NULL, *data_home = NULL;
        char **config_dirs = NULL, **data_dirs = NULL;
        char **r = NULL, **t;

        /* Implement the mechanisms defined in
         *
         * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */

        home = getenv("HOME");

        if ((e = getenv("XDG_CONFIG_HOME"))) {
                if (asprintf(&config_home, "%s/systemd/session", e) < 0)
                        goto fail;

        } else if (home) {
                if (asprintf(&config_home, "%s/.config/systemd/session", home) < 0)
                        goto fail;
        }

        if ((e = getenv("XDG_CONFIG_DIRS")))
                if (!(config_dirs = strv_split(e, ":")))
                        goto fail;

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that that is a link to
         * /etc/systemd/ anyway. */

        if ((e = getenv("XDG_DATA_HOME"))) {
                if (asprintf(&data_home, "%s/systemd/session", e) < 0)
                        goto fail;

        } else if (home) {
                if (asprintf(&data_home, "%s/.local/share/systemd/session", home) < 0)
                        goto fail;

                /* There is really no need for two unit dirs in $HOME,
                 * except to be fully compliant with the XDG spec. We
                 * now try to link the two dirs, so that we can
                 * minimize disk seeks a little. Further down we'll
                 * then filter out this link, if it is actually is
                 * one. */

                mkdir_parents(data_home, 0777);
                symlink("../../../.config/systemd/session", data_home);
        }

        if ((e = getenv("XDG_DATA_DIRS")))
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share", "/usr/share", NULL);

        if (!data_dirs)
                goto fail;

        /* Now merge everything we found. */
        if (config_home) {
                if (!(t = strv_append(r, config_home)))
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!(t = strv_merge_concat(r, config_dirs, "/systemd/session")))
                goto finish;
        strv_free(r);
        r = t;

        if (!(t = strv_append(r, SESSION_CONFIG_UNIT_PATH)))
                goto fail;
        strv_free(r);
        r = t;

        if (data_home) {
                if (!(t = strv_append(r, data_home)))
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!(t = strv_merge_concat(r, data_dirs, "/systemd/session")))
                goto fail;
        strv_free(r);
        r = t;

        if (!(t = strv_append(r, SESSION_DATA_UNIT_PATH)))
                goto fail;
        strv_free(r);
        r = t;

        if (!strv_path_make_absolute_cwd(r))
            goto fail;

finish:
        free(config_home);
        strv_free(config_dirs);
        free(data_home);
        strv_free(data_dirs);

        return r;

fail:
        strv_free(r);
        r = NULL;
        goto finish;
}

static int manager_find_paths(Manager *m) {
        const char *e;
        char *t;

        assert(m);

        /* First priority is whatever has been passed to us via env
         * vars */
        if ((e = getenv("SYSTEMD_UNIT_PATH")))
                if (!(m->unit_path = split_path_and_make_absolute(e)))
                        return -ENOMEM;

        if (strv_isempty(m->unit_path)) {

                /* Nothing is set, so let's figure something out. */
                strv_free(m->unit_path);

                if (m->running_as == MANAGER_SESSION) {
                        if (!(m->unit_path = session_dirs()))
                                return -ENOMEM;
                } else
                        if (!(m->unit_path = strv_new(
                                              SYSTEM_CONFIG_UNIT_PATH,  /* /etc/systemd/system/ */
                                              SYSTEM_DATA_UNIT_PATH,    /* /lib/systemd/system/ */
                                              NULL)))
                                return -ENOMEM;
        }

        if (m->running_as == MANAGER_INIT) {
                /* /etc/init.d/ compatibility does not matter to users */

                if ((e = getenv("SYSTEMD_SYSVINIT_PATH")))
                        if (!(m->sysvinit_path = split_path_and_make_absolute(e)))
                                return -ENOMEM;

                if (strv_isempty(m->sysvinit_path)) {
                        strv_free(m->sysvinit_path);

                        if (!(m->sysvinit_path = strv_new(
                                              SYSTEM_SYSVINIT_PATH,     /* /etc/init.d/ */
                                              NULL)))
                                return -ENOMEM;
                }

                if ((e = getenv("SYSTEMD_SYSVRCND_PATH")))
                        if (!(m->sysvrcnd_path = split_path_and_make_absolute(e)))
                                return -ENOMEM;

                if (strv_isempty(m->sysvrcnd_path)) {
                        strv_free(m->sysvrcnd_path);

                        if (!(m->sysvrcnd_path = strv_new(
                                              SYSTEM_SYSVRCND_PATH,     /* /etc/rcN.d/ */
                                              NULL)))
                                return -ENOMEM;
                }
        }

        if (m->unit_path)
                if (!strv_path_canonicalize(m->unit_path))
                        return -ENOMEM;

        if (m->sysvinit_path)
                if (!strv_path_canonicalize(m->sysvinit_path))
                        return -ENOMEM;

        if (m->sysvrcnd_path)
                if (!strv_path_canonicalize(m->sysvrcnd_path))
                        return -ENOMEM;

        strv_uniq(m->unit_path);
        strv_uniq(m->sysvinit_path);
        strv_uniq(m->sysvrcnd_path);

        if (!strv_isempty(m->unit_path)) {

                if (!(t = strv_join(m->unit_path, "\n\t")))
                        return -ENOMEM;
                log_debug("Looking for unit files in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring unit files.");
                strv_free(m->unit_path);
                m->unit_path = NULL;
        }

        if (!strv_isempty(m->sysvinit_path)) {

                if (!(t = strv_join(m->sysvinit_path, "\n\t")))
                        return -ENOMEM;

                log_debug("Looking for SysV init scripts in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring SysV init scripts.");
                strv_free(m->sysvinit_path);
                m->sysvinit_path = NULL;
        }

        if (!strv_isempty(m->sysvrcnd_path)) {

                if (!(t = strv_join(m->sysvrcnd_path, "\n\t")))
                        return -ENOMEM;

                log_debug("Looking for SysV rcN.d links in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring SysV rcN.d links.");
                strv_free(m->sysvrcnd_path);
                m->sysvrcnd_path = NULL;
        }

        return 0;
}

int manager_new(ManagerRunningAs running_as, bool confirm_spawn, Manager **_m) {
        Manager *m;
        int r = -ENOMEM;

        assert(_m);
        assert(running_as >= 0);
        assert(running_as < _MANAGER_RUNNING_AS_MAX);

        if (!(m = new0(Manager, 1)))
                return -ENOMEM;

        timestamp_get(&m->startup_timestamp);

        m->running_as = running_as;
        m->confirm_spawn = confirm_spawn;
        m->name_data_slot = -1;
        m->exit_code = _MANAGER_EXIT_CODE_INVALID;

        m->signal_watch.fd = m->mount_watch.fd = m->udev_watch.fd = m->epoll_fd = m->dev_autofs_fd = -1;
        m->current_job_id = 1; /* start as id #1, so that we can leave #0 around as "null-like" value */

        if (!(m->environment = strv_copy(environ)))
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

        if ((r = manager_find_paths(m)) < 0)
                goto fail;

        if ((r = manager_setup_signals(m)) < 0)
                goto fail;

        if ((r = manager_setup_cgroup(m)) < 0)
                goto fail;

        /* Try to connect to the busses, if possible. */
        if ((r = bus_init_system(m)) < 0 ||
            (r = bus_init_api(m)) < 0)
                goto fail;

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

                unit_free(UNIT(meta));
                n++;
        }

        return n;
}

enum {
        GC_OFFSET_IN_PATH,  /* This one is on the path we were travelling */
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

                unit_gc_sweep(UNIT(meta), gc_marker);

                LIST_REMOVE(Meta, gc_queue, m->gc_queue, meta);
                meta->in_gc_queue = false;

                n++;

                if (meta->gc_marker == gc_marker + GC_OFFSET_BAD ||
                    meta->gc_marker == gc_marker + GC_OFFSET_UNSURE) {
                        log_debug("Collecting %s", meta->id);
                        meta->gc_marker = gc_marker + GC_OFFSET_BAD;
                        unit_add_to_cleanup_queue(UNIT(meta));
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
}

void manager_free(Manager *m) {
        UnitType c;

        assert(m);

        manager_dispatch_cleanup_queue(m);
        manager_clear_jobs_and_units(m);

        for (c = 0; c < _UNIT_TYPE_MAX; c++)
                if (unit_vtable[c]->shutdown)
                        unit_vtable[c]->shutdown(m);

        /* If we reexecute ourselves, we keep the root cgroup
         * around */
        manager_shutdown_cgroup(m, m->exit_code != MANAGER_REEXECUTE);

        bus_done_api(m);
        bus_done_system(m);

        hashmap_free(m->units);
        hashmap_free(m->jobs);
        hashmap_free(m->transaction_jobs);
        hashmap_free(m->watch_pids);
        hashmap_free(m->watch_bus);

        if (m->epoll_fd >= 0)
                close_nointr_nofail(m->epoll_fd);
        if (m->signal_watch.fd >= 0)
                close_nointr_nofail(m->signal_watch.fd);

        strv_free(m->unit_path);
        strv_free(m->sysvinit_path);
        strv_free(m->sysvrcnd_path);
        strv_free(m->environment);

        free(m->cgroup_controller);
        free(m->cgroup_hierarchy);

        hashmap_free(m->cgroup_bondings);

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

                if (UNIT_VTABLE(u)->coldplug)
                        if ((q = UNIT_VTABLE(u)->coldplug(u)) < 0)
                                r = q;
        }

        return r;
}

int manager_startup(Manager *m, FILE *serialization, FDSet *fds) {
        int r, q;

        assert(m);

        /* First, enumerate what we can from all config files */
        r = manager_enumerate(m);

        /* Second, deserialize if there is something to deserialize */
        if (serialization)
                if ((q = manager_deserialize(m, serialization, fds)) < 0)
                        r = q;

        /* Third, fire things up! */
        if ((q = manager_coldplug(m)) < 0)
                r = q;

        /* Now that the initial devices are available, let's see if we
         * can write the utmp file */
        manager_write_utmp_reboot(m);

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

static int delete_one_unmergeable_job(Manager *m, Job *j) {
        Job *k;

        assert(j);

        /* Tries to delete one item in the linked list
         * j->transaction_next->transaction_next->... that conflicts
         * whith another one, in an attempt to make an inconsistent
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
                        if (!j->matters_to_anchor)
                                d = j;
                        else if (!k->matters_to_anchor)
                                d = k;
                        else
                                return -ENOEXEC;

                        /* Ok, we can drop one, so let's do so. */
                        log_debug("Trying to fix job merging by deleting job %s/%s", d->unit->meta.id, job_type_to_string(d->type));
                        transaction_delete_job(m, d, true);
                        return 0;
                }

        return -EINVAL;
}

static int transaction_merge_jobs(Manager *m) {
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
                        if ((r = job_type_merge(&t, k->type)) >= 0)
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
                                    job_type_is_redundant(k->type, unit_active_state(k->unit)))
                                        continue;

                                changes_something = true;
                                break;
                        }

                        if (changes_something)
                                continue;

                        log_debug("Found redundant job %s/%s, dropping.", j->unit->meta.id, job_type_to_string(j->type));
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

static int transaction_verify_order_one(Manager *m, Job *j, Job *from, unsigned generation) {
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
                Job *k;

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
                log_debug("Found ordering cycle on %s/%s", j->unit->meta.id, job_type_to_string(j->type));

                for (k = from; k; k = ((k->generation == generation && k->marker != k) ? k->marker : NULL)) {

                        log_debug("Walked on cycle path to %s/%s", k->unit->meta.id, job_type_to_string(k->type));

                        if (!k->installed &&
                            !unit_matters_to_anchor(k->unit, k)) {
                                /* Ok, we can drop this one, so let's
                                 * do so. */
                                log_debug("Breaking order cycle by deleting job %s/%s", k->unit->meta.id, job_type_to_string(k->type));
                                transaction_delete_unit(m, k->unit);
                                return -EAGAIN;
                        }

                        /* Check if this in fact was the beginning of
                         * the cycle */
                        if (k == j)
                                break;
                }

                log_debug("Unable to break cycle");

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

                if ((r = transaction_verify_order_one(m, o, j, generation)) < 0)
                        return r;
        }

        /* Ok, let's backtrack, and remember that this entry is not on
         * our path anymore. */
        j->marker = NULL;

        return 0;
}

static int transaction_verify_order(Manager *m, unsigned *generation) {
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
                if ((r = transaction_verify_order_one(m, j, NULL, g)) < 0)
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
                        if (j->object_list)
                                continue;

                        log_debug("Garbage collecting job %s/%s", j->unit->meta.id, job_type_to_string(j->type));
                        transaction_delete_job(m, j, true);
                        again = true;
                        break;
                }

        } while (again);
}

static int transaction_is_destructive(Manager *m) {
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
                    !job_type_is_superset(j->type, j->unit->meta.job->type))
                        return -EEXIST;
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
                                        j->unit->meta.job && job_type_is_conflicting(j->type, j->unit->meta.job->state);

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

static int transaction_apply(Manager *m) {
        Iterator i;
        Job *j;
        int r;

        /* Moves the transaction jobs to the set of active jobs */

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
                if (j->installed)
                        continue;

                if (j->unit->meta.job)
                        job_free(j->unit->meta.job);

                j->unit->meta.job = j;
                j->installed = true;

                /* We're fully installed. Now let's free data we don't
                 * need anymore. */

                assert(!j->transaction_next);
                assert(!j->transaction_prev);

                job_add_to_run_queue(j);
                job_add_to_dbus_queue(j);
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

static int transaction_activate(Manager *m, JobMode mode) {
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
        transaction_minimize_impact(m);

        /* Third step: Drop redundant jobs */
        transaction_drop_redundant(m);

        for (;;) {
                /* Fourth step: Let's remove unneeded jobs that might
                 * be lurking. */
                transaction_collect_garbage(m);

                /* Fifth step: verify order makes sense and correct
                 * cycles if necessary and possible */
                if ((r = transaction_verify_order(m, &generation)) >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_debug("Requested transaction contains an unfixable cyclic ordering dependency: %s", strerror(-r));
                        goto rollback;
                }

                /* Let's see if the resulting transaction ordering
                 * graph is still cyclic... */
        }

        for (;;) {
                /* Sixth step: let's drop unmergeable entries if
                 * necessary and possible, merge entries we can
                 * merge */
                if ((r = transaction_merge_jobs(m)) >= 0)
                        break;

                if (r != -EAGAIN) {
                        log_debug("Requested transaction contains unmergable jobs: %s", strerror(-r));
                        goto rollback;
                }

                /* Seventh step: an entry got dropped, let's garbage
                 * collect its dependencies. */
                transaction_collect_garbage(m);

                /* Let's see if the resulting transaction still has
                 * unmergeable entries ... */
        }

        /* Eights step: Drop redundant jobs again, if the merging now allows us to drop more. */
        transaction_drop_redundant(m);

        /* Ninth step: check whether we can actually apply this */
        if (mode == JOB_FAIL)
                if ((r = transaction_is_destructive(m)) < 0) {
                        log_debug("Requested transaction contradicts existing jobs: %s", strerror(-r));
                        goto rollback;
                }

        /* Tenth step: apply changes */
        if ((r = transaction_apply(m)) < 0) {
                log_debug("Failed to apply transaction: %s", strerror(-r));
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
        int r;

        assert(m);
        assert(unit);

        /* Looks for an axisting prospective job and returns that. If
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

        if ((r = hashmap_replace(m->transaction_jobs, unit, f)) < 0) {
                job_free(j);
                return NULL;
        }

        if (is_new)
                *is_new = true;

        log_debug("Added job %s/%s to transaction.", unit->meta.id, job_type_to_string(type));

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
                Job **_ret) {
        Job *ret;
        Iterator i;
        Unit *dep;
        int r;
        bool is_new;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);

        if (unit->meta.load_state != UNIT_LOADED)
                return -EINVAL;

        if (!unit_job_is_applicable(unit, type))
                return -EBADR;

        /* First add the job. */
        if (!(ret = transaction_add_one_job(m, type, unit, override, &is_new)))
                return -ENOMEM;

        /* Then, add a link to the job. */
        if (!job_dependency_new(by, ret, matters))
                return -ENOMEM;

        if (is_new) {
                /* Finally, recursively add in all dependencies. */
                if (type == JOB_START || type == JOB_RELOAD_OR_START) {
                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRES], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, true, override, NULL)) < 0 && r != -EBADR)
                                        goto fail;

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRES_OVERRIDABLE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, !override, override, NULL)) < 0 && r != -EBADR)
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, strerror(-r));

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_WANTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_START, dep, ret, false, false, NULL)) < 0)
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, strerror(-r));

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUISITE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, true, override, NULL)) < 0 && r != -EBADR)
                                        goto fail;

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUISITE_OVERRIDABLE], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_VERIFY_ACTIVE, dep, ret, !override, override, NULL)) < 0 && r != -EBADR)
                                        log_warning("Cannot add dependency job for unit %s, ignoring: %s", dep->meta.id, strerror(-r));

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_CONFLICTS], i)
                                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, dep, ret, true, override, NULL)) < 0 && r != -EBADR)
                                        goto fail;

                } else if (type == JOB_STOP || type == JOB_RESTART || type == JOB_TRY_RESTART) {

                        SET_FOREACH(dep, ret->unit->meta.dependencies[UNIT_REQUIRED_BY], i)
                                if ((r = transaction_add_job_and_dependencies(m, type, dep, ret, true, override, NULL)) < 0 && r != -EBADR)
                                        goto fail;
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

                if (UNIT_VTABLE(u)->no_isolate)
                        continue;

                /* No need to stop inactive jobs */
                if (unit_active_state(u) == UNIT_INACTIVE)
                        continue;

                /* Is there already something listed for this? */
                if (hashmap_get(m->transaction_jobs, u))
                        continue;

                if ((r = transaction_add_job_and_dependencies(m, JOB_STOP, u, NULL, true, false, NULL)) < 0)
                        log_warning("Cannot add isolate job for unit %s, ignoring: %s", u->meta.id, strerror(-r));
        }

        return 0;
}

int manager_add_job(Manager *m, JobType type, Unit *unit, JobMode mode, bool override, Job **_ret) {
        int r;
        Job *ret;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(unit);
        assert(mode < _JOB_MODE_MAX);

        if (mode == JOB_ISOLATE && type != JOB_START)
                return -EINVAL;

        log_debug("Trying to enqueue job %s/%s", unit->meta.id, job_type_to_string(type));

        if ((r = transaction_add_job_and_dependencies(m, type, unit, NULL, true, override, &ret)) < 0) {
                transaction_abort(m);
                return r;
        }

        if (mode == JOB_ISOLATE)
                if ((r = transaction_add_isolate_jobs(m)) < 0) {
                        transaction_abort(m);
                        return r;
                }

        if ((r = transaction_activate(m, mode)) < 0)
                return r;

        log_debug("Enqueued job %s/%s as %u", unit->meta.id, job_type_to_string(type), (unsigned) ret->id);

        if (_ret)
                *_ret = ret;

        return 0;
}

int manager_add_job_by_name(Manager *m, JobType type, const char *name, JobMode mode, bool override, Job **_ret) {
        Unit *unit;
        int r;

        assert(m);
        assert(type < _JOB_TYPE_MAX);
        assert(name);
        assert(mode < _JOB_MODE_MAX);

        if ((r = manager_load_unit(m, name, NULL, &unit)) < 0)
                return r;

        return manager_add_job(m, type, unit, mode, override, _ret);
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

                unit_load(UNIT(meta));
                n++;
        }

        m->dispatching_load_queue = false;
        return n;
}

int manager_load_unit_prepare(Manager *m, const char *name, const char *path, Unit **_ret) {
        Unit *ret;
        int r;

        assert(m);
        assert(name || path);

        /* This will prepare the unit for loading, but not actually
         * load anything from disk. */

        if (path && !is_path(path))
                return -EINVAL;

        if (!name)
                name = file_name_from_path(path);

        if (!unit_name_is_valid(name))
                return -EINVAL;

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

int manager_load_unit(Manager *m, const char *name, const char *path, Unit **_ret) {
        int r;

        assert(m);

        /* This will load the service information files, but not actually
         * start any services or anything. */

        if ((r = manager_load_unit_prepare(m, name, path, _ret)) != 0)
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
                job_free(j);
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

                bus_unit_send_change_signal(UNIT(meta));
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

static int manager_dispatch_sigchld(Manager *m) {
        assert(m);

        for (;;) {
                siginfo_t si;
                Unit *u;

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
                        log_debug("Got SIGCHLD for process %llu (%s)", (unsigned long long) si.si_pid, strna(name));
                        free(name);
                }

                /* And now, we actually reap the zombie. */
                if (waitid(P_PID, si.si_pid, &si, WEXITED) < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (si.si_code != CLD_EXITED && si.si_code != CLD_KILLED && si.si_code != CLD_DUMPED)
                        continue;

                log_debug("Child %llu died (code=%s, status=%i/%s)",
                          (long long unsigned) si.si_pid,
                          sigchld_code_to_string(si.si_code),
                          si.si_status,
                          strna(si.si_code == CLD_EXITED ? exit_status_to_string(si.si_status) : strsignal(si.si_status)));

                if (!(u = hashmap_remove(m->watch_pids, UINT32_TO_PTR(si.si_pid))))
                        continue;

                log_debug("Child %llu belongs to %s", (long long unsigned) si.si_pid, u->meta.id);

                UNIT_VTABLE(u)->sigchld_event(u, si.si_pid, si.si_code, si.si_status);
        }

        return 0;
}

static int manager_start_target(Manager *m, const char *name) {
        int r;

        if ((r = manager_add_job_by_name(m, JOB_START, name, JOB_REPLACE, true, NULL)) < 0)
                log_error("Failed to enqueue %s job: %s", name, strerror(-r));

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

                        if (errno == EAGAIN)
                                break;

                        return -errno;
                }

                switch (sfsi.ssi_signo) {

                case SIGCHLD:
                        sigchld = true;
                        break;

                case SIGTERM:
                        if (m->running_as == MANAGER_INIT) {
                                /* This is for compatibility with the
                                 * original sysvinit */
                                m->exit_code = MANAGER_REEXECUTE;
                                break;
                        }

                        /* Fall through */

                case SIGINT:
                        if (m->running_as == MANAGER_INIT) {
                                manager_start_target(m, SPECIAL_CTRL_ALT_DEL_TARGET);
                                break;
                        }

                        /* Run the exit target if there is one, if not, just exit. */
                        if (manager_start_target(m, SPECIAL_EXIT_SERVICE) < 0) {
                                m->exit_code = MANAGER_EXIT;
                                return 0;
                        }

                        break;

                case SIGWINCH:
                        if (m->running_as == MANAGER_INIT)
                                manager_start_target(m, SPECIAL_KBREQUEST_TARGET);

                        /* This is a nop on non-init */
                        break;

                case SIGPWR:
                        if (m->running_as == MANAGER_INIT)
                                manager_start_target(m, SPECIAL_SIGPWR_TARGET);

                        /* This is a nop on non-init */
                        break;

                case SIGUSR1: {
                        Unit *u;

                        u = manager_get_unit(m, SPECIAL_DBUS_SERVICE);

                        if (!u || UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(u))) {
                                log_info("Trying to reconnect to bus...");
                                bus_init_system(m);
                                bus_init_api(m);
                        }

                        if (!u || !UNIT_IS_ACTIVE_OR_ACTIVATING(unit_active_state(u))) {
                                log_info("Loading D-Bus service...");
                                manager_start_target(m, SPECIAL_DBUS_SERVICE);
                        }

                        break;
                }

                case SIGUSR2:
                        manager_dump_units(m, stdout, "\t");
                        manager_dump_jobs(m, stdout, "\t");
                        break;

                case SIGHUP:
                        m->exit_code = MANAGER_RELOAD;
                        break;

                default:
                        log_info("Got unhandled signal <%s>.", strsignal(sfsi.ssi_signo));
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

        assert(w = ev->data.ptr);

        switch (w->type) {

        case WATCH_SIGNAL:

                /* An incoming signal? */
                if (ev->events != EPOLLIN)
                        return -EINVAL;

                if ((r = manager_process_signal_fd(m)) < 0)
                        return r;

                break;

        case WATCH_FD:

                /* Some fd event, to be dispatched to the units */
                UNIT_VTABLE(w->data.unit)->fd_event(w->data.unit, w->fd, ev->events, w);
                break;

        case WATCH_TIMER: {
                uint64_t v;
                ssize_t k;

                /* Some timer event, to be dispatched to the units */
                if ((k = read(w->fd, &v, sizeof(v))) != sizeof(v)) {

                        if (k < 0 && (errno == EINTR || errno == EAGAIN))
                                break;

                        return k < 0 ? -errno : -EIO;
                }

                UNIT_VTABLE(w->data.unit)->timer_event(w->data.unit, v, w);
                break;
        }

        case WATCH_MOUNT:
                /* Some mount table change, intended for the mount subsystem */
                mount_fd_event(m, ev->events);
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
                assert_not_reached("Unknown epoll event type.");
        }

        return 0;
}

int manager_loop(Manager *m) {
        int r;

        RATELIMIT_DEFINE(rl, 1*USEC_PER_SEC, 1000);

        assert(m);
        m->exit_code = MANAGER_RUNNING;

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

static bool manager_utmp_good(Manager *m) {
        int r;

        assert(m);

        if ((r = mount_path_is_mounted(m, _PATH_UTMPX)) <= 0) {

                if (r < 0)
                        log_warning("Failed to determine whether " _PATH_UTMPX " is mounted: %s", strerror(-r));

                return false;
        }

        return true;
}

void manager_write_utmp_reboot(Manager *m) {
        int r;

        assert(m);

        if (m->utmp_reboot_written)
                return;

        if (m->running_as != MANAGER_INIT)
                return;

        if (!manager_utmp_good(m))
                return;

        if ((r = utmp_put_reboot(m->startup_timestamp.realtime)) < 0) {

                if (r != -ENOENT && r != -EROFS)
                        log_warning("Failed to write utmp/wtmp: %s", strerror(-r));

                return;
        }

        m->utmp_reboot_written = true;
}

void manager_write_utmp_runlevel(Manager *m, Unit *u) {
        int runlevel, r;

        assert(m);
        assert(u);

        if (u->meta.type != UNIT_TARGET)
                return;

        if (m->running_as != MANAGER_INIT)
                return;

        if (!manager_utmp_good(m))
                return;

        if ((runlevel = target_get_runlevel(TARGET(u))) <= 0)
                return;

        if ((r = utmp_put_runlevel(0, runlevel, 0)) < 0) {

                if (r != -ENOENT && r != -EROFS)
                        log_warning("Failed to write utmp/wtmp: %s", strerror(-r));
        }
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

int manager_open_serialization(FILE **_f) {
        char *path;
        mode_t saved_umask;
        int fd;
        FILE *f;

        assert(_f);

        if (asprintf(&path, "/dev/shm/systemd-%u.dump-XXXXXX", (unsigned) getpid()) < 0)
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

        if (!(f = fdopen(fd, "w+")) < 0)
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

        HASHMAP_FOREACH_KEY(u, t, m->units, i) {
                if (u->meta.id != t)
                        continue;

                if (!unit_can_serialize(u))
                        continue;

                /* Start marker */
                fputs(u->meta.id, f);
                fputc('\n', f);

                if ((r = unit_serialize(u, f, fds)) < 0)
                        return r;
        }

        if (ferror(f))
                return -EIO;

        return 0;
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r = 0;

        assert(m);
        assert(f);

        log_debug("Deserializing state...");

        for (;;) {
                Unit *u;
                char name[UNIT_NAME_MAX+2];

                /* Start marker */
                if (!fgets(name, sizeof(name), f)) {
                        if (feof(f))
                                break;

                        return -errno;
                }

                char_array_0(name);

                if ((r = manager_load_unit(m, strstrip(name), NULL, &u)) < 0)
                        return r;

                if ((r = unit_deserialize(u, f, fds)) < 0)
                        return r;
        }

        if (ferror(f))
                return -EIO;

        return 0;
}

int manager_reload(Manager *m) {
        int r, q;
        FILE *f;
        FDSet *fds;

        assert(m);

        if ((r = manager_open_serialization(&f)) < 0)
                return r;

        if (!(fds = fdset_new())) {
                r = -ENOMEM;
                goto finish;
        }

        if ((r = manager_serialize(m, f, fds)) < 0)
                goto finish;

        if (fseeko(f, 0, SEEK_SET) < 0) {
                r = -errno;
                goto finish;
        }

        /* From here on there is no way back. */
        manager_clear_jobs_and_units(m);

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

finish:
        if (f)
                fclose(f);

        if (fds)
                fdset_free(fds);

        return r;
}

static const char* const manager_running_as_table[_MANAGER_RUNNING_AS_MAX] = {
        [MANAGER_INIT] = "init",
        [MANAGER_SYSTEM] = "system",
        [MANAGER_SESSION] = "session"
};

DEFINE_STRING_TABLE_LOOKUP(manager_running_as, ManagerRunningAs);
