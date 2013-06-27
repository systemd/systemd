/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "logind-machine.h"
#include "util.h"
#include "mkdir.h"
#include "cgroup-util.h"
#include "hashmap.h"
#include "strv.h"
#include "fileio.h"
#include "special.h"
#include <systemd/sd-messages.h>

Machine* machine_new(Manager *manager, const char *name) {
        Machine *m;

        assert(manager);
        assert(name);

        m = new0(Machine, 1);
        if (!m)
                return NULL;

        m->name = strdup(name);
        if (!m->name)
                goto fail;

        m->state_file = strappend("/run/systemd/machines/", m->name);
        if (!m->state_file)
                goto fail;

        if (hashmap_put(manager->machines, m->name, m) < 0)
                goto fail;

        m->class = _MACHINE_CLASS_INVALID;
        m->manager = manager;

        return m;

fail:
        free(m->state_file);
        free(m->name);
        free(m);

        return NULL;
}

void machine_free(Machine *m) {
        assert(m);

        if (m->in_gc_queue)
                LIST_REMOVE(Machine, gc_queue, m->manager->machine_gc_queue, m);

        if (m->cgroup_path) {
                hashmap_remove(m->manager->machine_cgroups, m->cgroup_path);
                free(m->cgroup_path);
        }

        hashmap_remove(m->manager->machines, m->name);

        free(m->name);
        free(m->state_file);
        free(m->service);
        free(m->slice);
        free(m->root_directory);
        free(m);
}

int machine_save(Machine *m) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);
        assert(m->state_file);

        if (!m->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/machines", 0755, 0, 0);
        if (r < 0)
                goto finish;

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "NAME=%s\n",
                m->name);

        if (m->cgroup_path)
                fprintf(f, "CGROUP=%s\n", m->cgroup_path);

        if (m->service)
                fprintf(f, "SERVICE=%s\n", m->service);

        if (m->slice)
                fprintf(f, "SLICE=%s\n", m->slice);

        if (m->root_directory)
                fprintf(f, "ROOT=%s\n", m->root_directory);

        if (!sd_id128_equal(m->id, SD_ID128_NULL))
                fprintf(f, "ID=" SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(m->id));

        if (m->leader != 0)
                fprintf(f, "LEADER=%lu\n", (unsigned long) m->leader);

        if (m->class != _MACHINE_CLASS_INVALID)
                fprintf(f, "CLASS=%s\n", machine_class_to_string(m->class));

        if (dual_timestamp_is_set(&m->timestamp))
                fprintf(f,
                        "REALTIME=%llu\n"
                        "MONOTONIC=%llu\n",
                        (unsigned long long) m->timestamp.realtime,
                        (unsigned long long) m->timestamp.monotonic);

        fflush(f);

        if (ferror(f) || rename(temp_path, m->state_file) < 0) {
                r = -errno;
                unlink(m->state_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error("Failed to save machine data for %s: %s", m->name, strerror(-r));

        return r;
}

int machine_load(Machine *m) {
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL, *id = NULL, *leader = NULL, *class = NULL;
        int r;

        assert(m);

        r = parse_env_file(m->state_file, NEWLINE,
                           "CGROUP",    &m->cgroup_path,
                           "SERVICE",   &m->service,
                           "SLICE",     &m->slice,
                           "ROOT",      &m->root_directory,
                           "ID",        &id,
                           "LEADER",    &leader,
                           "CLASS",     &class,
                           "REALTIME",  &realtime,
                           "MONOTONIC", &monotonic,
                           NULL);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                log_error("Failed to read %s: %s", m->state_file, strerror(-r));
                return r;
        }

        if (id)
                sd_id128_from_string(id, &m->id);

        if (leader)
                parse_pid(leader, &m->leader);

        if (class) {
                MachineClass c;

                c = machine_class_from_string(class);
                if (c >= 0)
                        m->class = c;
        }

        if (realtime) {
                unsigned long long l;
                if (sscanf(realtime, "%llu", &l) > 0)
                        m->timestamp.realtime = l;
        }

        if (monotonic) {
                unsigned long long l;
                if (sscanf(monotonic, "%llu", &l) > 0)
                        m->timestamp.monotonic = l;
        }

        return r;
}

static int machine_create_one_group(Machine *m, const char *controller, const char *path) {
        int r;

        assert(m);
        assert(path);

        if (m->leader > 0)
                r = cg_create_and_attach(controller, path, m->leader);
        else
                r = -EINVAL;

        if (r < 0) {
                r = cg_create(controller, path);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int machine_create_cgroup(Machine *m) {
        char **k;
        int r;

        assert(m);

        if (!m->slice) {
                m->slice = strdup(SPECIAL_MACHINE_SLICE);
                if (!m->slice)
                        return log_oom();
        }

        if (!m->cgroup_path) {
                _cleanup_free_ char *escaped = NULL, *slice = NULL;
                char *name;

                name = strappenda(m->name, ".machine");

                escaped = cg_escape(name);
                if (!escaped)
                        return log_oom();

                r = cg_slice_to_path(m->slice, &slice);
                if (r < 0)
                        return r;

                m->cgroup_path = strjoin(m->manager->cgroup_root, "/", slice, "/", escaped, NULL);
                if (!m->cgroup_path)
                        return log_oom();
        }

        r = machine_create_one_group(m, SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path);
        if (r < 0) {
                log_error("Failed to create cgroup "SYSTEMD_CGROUP_CONTROLLER":%s: %s", m->cgroup_path, strerror(-r));
                return r;
        }

        STRV_FOREACH(k, m->manager->controllers) {

                if (strv_contains(m->manager->reset_controllers, *k))
                        continue;

                r = machine_create_one_group(m, *k, m->cgroup_path);
                if (r < 0)
                        log_warning("Failed to create cgroup %s:%s: %s", *k, m->cgroup_path, strerror(-r));
        }

        if (m->leader > 0) {
                STRV_FOREACH(k, m->manager->reset_controllers) {
                        r = cg_attach(*k, "/", m->leader);
                        if (r < 0)
                                log_warning("Failed to reset controller %s: %s", *k, strerror(-r));
                }
        }

        r = hashmap_put(m->manager->machine_cgroups, m->cgroup_path, m);
        if (r < 0)
                log_warning("Failed to create mapping between cgroup and machine");

        return 0;
}

int machine_start(Machine *m) {
        int r;

        assert(m);

        if (m->started)
                return 0;

        log_struct(LOG_INFO,
                   MESSAGE_ID(SD_MESSAGE_MACHINE_START),
                   "NAME=%s", m->name,
                   "LEADER=%lu", (unsigned long) m->leader,
                   "MESSAGE=New machine %s.", m->name,
                   NULL);

        /* Create cgroup */
        r = machine_create_cgroup(m);
        if (r < 0)
                return r;

        if (!dual_timestamp_is_set(&m->timestamp))
                dual_timestamp_get(&m->timestamp);

        m->started = true;

        /* Save new machine data */
        machine_save(m);

        machine_send_signal(m, true);

        return 0;
}

static int machine_terminate_cgroup(Machine *m) {
        int r;
        char **k;

        assert(m);

        if (!m->cgroup_path)
                return 0;

        cg_trim(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, false);

        r = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, true);
        if (r < 0)
                log_error("Failed to kill machine cgroup: %s", strerror(-r));

        STRV_FOREACH(k, m->manager->controllers)
                cg_trim(*k, m->cgroup_path, true);

        hashmap_remove(m->manager->machine_cgroups, m->cgroup_path);

        free(m->cgroup_path);
        m->cgroup_path = NULL;

        return r;
}

int machine_stop(Machine *m) {
        int r = 0, k;
        assert(m);

        if (m->started)
                log_struct(LOG_INFO,
                           MESSAGE_ID(SD_MESSAGE_MACHINE_STOP),
                           "NAME=%s", m->name,
                           "LEADER=%lu", (unsigned long) m->leader,
                           "MESSAGE=Machine %s terminated.", m->name,
                           NULL);

        /* Kill cgroup */
        k = machine_terminate_cgroup(m);
        if (k < 0)
                r = k;

        unlink(m->state_file);
        machine_add_to_gc_queue(m);

        if (m->started)
                machine_send_signal(m, false);

        m->started = false;

        return r;
}

int machine_check_gc(Machine *m, bool drop_not_started) {
        int r;

        assert(m);

        if (drop_not_started && !m->started)
                return 0;

        if (m->cgroup_path) {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, false);
                if (r < 0)
                        return r;

                if (r <= 0)
                        return 1;
        }

        return 0;
}

void machine_add_to_gc_queue(Machine *m) {
        assert(m);

        if (m->in_gc_queue)
                return;

        LIST_PREPEND(Machine, gc_queue, m->manager->machine_gc_queue, m);
        m->in_gc_queue = true;
}

int machine_kill(Machine *m, KillWho who, int signo) {
        _cleanup_set_free_ Set *pid_set = NULL;
        int r = 0;

        assert(m);

        if (!m->cgroup_path)
                return -ESRCH;

        if (m->leader <= 0 && who == KILL_LEADER)
                return -ESRCH;

        if (m->leader > 0)
                if (kill(m->leader, signo) < 0)
                        r = -errno;

        if (who == KILL_ALL) {
                int q;

                pid_set = set_new(trivial_hash_func, trivial_compare_func);
                if (!pid_set)
                        return log_oom();

                if (m->leader > 0) {
                        q = set_put(pid_set, LONG_TO_PTR(m->leader));
                        if (q < 0)
                                r = q;
                }

                q = cg_kill_recursive(SYSTEMD_CGROUP_CONTROLLER, m->cgroup_path, signo, false, true, false, pid_set);
                if (q < 0 && (q != -EAGAIN && q != -ESRCH && q != -ENOENT))
                        r = q;
        }

        return r;
}

static const char* const machine_class_table[_MACHINE_CLASS_MAX] = {
        [MACHINE_CONTAINER] = "container",
        [MACHINE_VM] = "vm"
};

DEFINE_STRING_TABLE_LOOKUP(machine_class, MachineClass);
