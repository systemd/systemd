/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "machine-dbus.h"
#include "machine.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "uid-range.h"
#include "unit-name.h"
#include "user-util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(Machine*, machine_free);

int machine_new(Manager *manager, MachineClass class, const char *name, Machine **ret) {
        _cleanup_(machine_freep) Machine *m = NULL;
        int r;

        assert(manager);
        assert(class < _MACHINE_CLASS_MAX);
        assert(name);
        assert(ret);

        /* Passing class == _MACHINE_CLASS_INVALID here is fine. It
         * means as much as "we don't know yet", and that we'll figure
         * it out later when loading the state file. */

        m = new(Machine, 1);
        if (!m)
                return -ENOMEM;

        *m = (Machine) {
                .leader = PIDREF_NULL,
        };

        m->name = strdup(name);
        if (!m->name)
                return -ENOMEM;

        if (class != MACHINE_HOST) {
                m->state_file = path_join("/run/systemd/machines", m->name);
                if (!m->state_file)
                        return -ENOMEM;
        }

        m->class = class;

        r = hashmap_put(manager->machines, m->name, m);
        if (r < 0)
                return r;

        m->manager = manager;

        *ret = TAKE_PTR(m);
        return 0;
}

Machine* machine_free(Machine *m) {
        if (!m)
                return NULL;

        while (m->operations)
                operation_free(m->operations);

        if (m->in_gc_queue)
                LIST_REMOVE(gc_queue, m->manager->machine_gc_queue, m);

        machine_release_unit(m);

        free(m->scope_job);

        (void) hashmap_remove(m->manager->machines, m->name);

        if (m->manager->host_machine == m)
                m->manager->host_machine = NULL;

        if (pidref_is_set(&m->leader)) {
                (void) hashmap_remove_value(m->manager->machine_leaders, PID_TO_PTR(m->leader.pid), m);
                pidref_done(&m->leader);
        }

        sd_bus_message_unref(m->create_message);

        free(m->name);
        free(m->state_file);
        free(m->service);
        free(m->root_directory);
        free(m->netif);
        return mfree(m);
}

int machine_save(Machine *m) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        if (!m->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/machines", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                goto fail;

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "NAME=%s\n",
                m->name);

        if (m->unit) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(m->unit);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "SCOPE=%s\n", escaped); /* We continue to call this "SCOPE=" because it is internal only, and we want to stay compatible with old files */
        }

        if (m->scope_job)
                fprintf(f, "SCOPE_JOB=%s\n", m->scope_job);

        if (m->service) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(m->service);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }
                fprintf(f, "SERVICE=%s\n", escaped);
        }

        if (m->root_directory) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(m->root_directory);
                if (!escaped) {
                        r = -ENOMEM;
                        goto fail;
                }
                fprintf(f, "ROOT=%s\n", escaped);
        }

        if (!sd_id128_is_null(m->id))
                fprintf(f, "ID=" SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(m->id));

        if (pidref_is_set(&m->leader))
                fprintf(f, "LEADER="PID_FMT"\n", m->leader.pid);

        if (m->class != _MACHINE_CLASS_INVALID)
                fprintf(f, "CLASS=%s\n", machine_class_to_string(m->class));

        if (dual_timestamp_is_set(&m->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        m->timestamp.realtime,
                        m->timestamp.monotonic);

        if (m->n_netif > 0) {
                size_t i;

                fputs("NETIF=", f);

                for (i = 0; i < m->n_netif; i++) {
                        if (i != 0)
                                fputc(' ', f);

                        fprintf(f, "%i", m->netif[i]);
                }

                fputc('\n', f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, m->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        temp_path = mfree(temp_path);

        if (m->unit) {
                char *sl;

                /* Create a symlink from the unit name to the machine
                 * name, so that we can quickly find the machine for
                 * each given unit. Ignore error. */
                sl = strjoina("/run/systemd/machines/unit:", m->unit);
                (void) symlink(m->name, sl);
        }

        return 0;

fail:
        (void) unlink(m->state_file);

        return log_error_errno(r, "Failed to save machine data %s: %m", m->state_file);
}

static void machine_unlink(Machine *m) {
        assert(m);

        if (m->unit) {
                char *sl;

                sl = strjoina("/run/systemd/machines/unit:", m->unit);
                (void) unlink(sl);
        }

        if (m->state_file)
                (void) unlink(m->state_file);
}

int machine_load(Machine *m) {
        _cleanup_free_ char *realtime = NULL, *monotonic = NULL, *id = NULL, *leader = NULL, *class = NULL, *netif = NULL;
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        r = parse_env_file(NULL, m->state_file,
                           "SCOPE",     &m->unit,
                           "SCOPE_JOB", &m->scope_job,
                           "SERVICE",   &m->service,
                           "ROOT",      &m->root_directory,
                           "ID",        &id,
                           "LEADER",    &leader,
                           "CLASS",     &class,
                           "REALTIME",  &realtime,
                           "MONOTONIC", &monotonic,
                           "NETIF",     &netif);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", m->state_file);

        if (id)
                (void) sd_id128_from_string(id, &m->id);

        if (leader) {
                pidref_done(&m->leader);
                r = pidref_set_pidstr(&m->leader, leader);
                if (r < 0)
                        log_debug_errno(r, "Failed to set leader PID to '%s', ignoring: %m", leader);
        }

        if (class) {
                MachineClass c;

                c = machine_class_from_string(class);
                if (c >= 0)
                        m->class = c;
        }

        if (realtime)
                (void) deserialize_usec(realtime, &m->timestamp.realtime);
        if (monotonic)
                (void) deserialize_usec(monotonic, &m->timestamp.monotonic);

        if (netif) {
                _cleanup_free_ int *ni = NULL;
                size_t nr = 0;
                const char *p;

                p = netif;
                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, 0);
                        if (r == 0)
                                break;
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_warning_errno(r, "Failed to parse NETIF: %s", netif);
                                break;
                        }

                        r = parse_ifindex(word);
                        if (r < 0)
                                continue;

                        if (!GREEDY_REALLOC(ni, nr + 1))
                                return log_oom();

                        ni[nr++] = r;
                }

                free_and_replace(m->netif, ni);
                m->n_netif = nr;
        }

        return r;
}

static int machine_start_scope(
                Machine *machine,
                sd_bus_message *more_properties,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *escaped = NULL, *unit = NULL;
        const char *description;
        int r;

        assert(machine);
        assert(pidref_is_set(&machine->leader));
        assert(!machine->unit);

        escaped = unit_name_escape(machine->name);
        if (!escaped)
                return log_oom();

        unit = strjoin("machine-", escaped, ".scope");
        if (!unit)
                return log_oom();

        r = bus_message_new_method_call(
                        machine->manager->bus,
                        &m,
                        bus_systemd_mgr,
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", unit, "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)", "Slice", "s", SPECIAL_MACHINE_SLICE);
        if (r < 0)
                return r;

        description = strjoina(machine->class == MACHINE_VM ? "Virtual Machine " : "Container ", machine->name);
        r = sd_bus_message_append(m, "(sv)", "Description", "s", description);
        if (r < 0)
                return r;

        r = bus_append_scope_pidref(m, &machine->leader);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "(sv)(sv)(sv)(sv)",
                                  "Delegate", "b", 1,
                                  "CollectMode", "s", "inactive-or-failed",
                                  "AddRef", "b", 1,
                                  "TasksMax", "t", UINT64_C(16384));
        if (r < 0)
                return r;

        if (more_properties) {
                r = sd_bus_message_copy(m, more_properties, true);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(NULL, m, 0, error, &reply);
        if (r < 0)
                return r;

        machine->unit = TAKE_PTR(unit);
        machine->referenced = true;

        const char *job;
        r = sd_bus_message_read(reply, "o", &job);
        if (r < 0)
                return r;

        return free_and_strdup(&machine->scope_job, job);
}

static int machine_ensure_scope(Machine *m, sd_bus_message *properties, sd_bus_error *error) {
        int r;

        assert(m);
        assert(m->class != MACHINE_HOST);

        if (!m->unit) {
                r = machine_start_scope(m, properties, error);
                if (r < 0)
                        return log_error_errno(r, "Failed to start machine scope: %s", bus_error_message(error, r));
        }

        assert(m->unit);
        hashmap_put(m->manager->machine_units, m->unit, m);

        return 0;
}

int machine_start(Machine *m, sd_bus_message *properties, sd_bus_error *error) {
        int r;

        assert(m);

        if (!IN_SET(m->class, MACHINE_CONTAINER, MACHINE_VM))
                return -EOPNOTSUPP;

        if (m->started)
                return 0;

        r = hashmap_put(m->manager->machine_leaders, PID_TO_PTR(m->leader.pid), m);
        if (r < 0)
                return r;

        /* Create cgroup */
        r = machine_ensure_scope(m, properties, error);
        if (r < 0)
                return r;

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_MACHINE_START_STR,
                   "NAME=%s", m->name,
                   "LEADER="PID_FMT, m->leader.pid,
                   LOG_MESSAGE("New machine %s.", m->name));

        if (!dual_timestamp_is_set(&m->timestamp))
                dual_timestamp_now(&m->timestamp);

        m->started = true;

        /* Save new machine data */
        machine_save(m);

        machine_send_signal(m, true);
        (void) manager_enqueue_nscd_cache_flush(m->manager);

        return 0;
}

int machine_stop(Machine *m) {
        int r;

        assert(m);

        if (!IN_SET(m->class, MACHINE_CONTAINER, MACHINE_VM))
                return -EOPNOTSUPP;

        if (m->unit) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                char *job = NULL;

                r = manager_stop_unit(m->manager, m->unit, &error, &job);
                if (r < 0)
                        return log_error_errno(r, "Failed to stop machine scope: %s", bus_error_message(&error, r));

                free_and_replace(m->scope_job, job);
        }

        m->stopping = true;

        machine_save(m);
        (void) manager_enqueue_nscd_cache_flush(m->manager);

        return 0;
}

int machine_finalize(Machine *m) {
        assert(m);

        if (m->started) {
                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_MACHINE_STOP_STR,
                           "NAME=%s", m->name,
                           "LEADER="PID_FMT, m->leader.pid,
                           LOG_MESSAGE("Machine %s terminated.", m->name));

                m->stopping = true; /* The machine is supposed to be going away. Don't try to kill it. */
        }

        machine_unlink(m);
        machine_add_to_gc_queue(m);

        if (m->started) {
                machine_send_signal(m, false);
                m->started = false;
        }

        return 0;
}

bool machine_may_gc(Machine *m, bool drop_not_started) {
        assert(m);

        if (m->class == MACHINE_HOST)
                return false;

        if (drop_not_started && !m->started)
                return true;

        if (m->scope_job && manager_job_is_active(m->manager, m->scope_job))
                return false;

        if (m->unit && manager_unit_is_active(m->manager, m->unit))
                return false;

        return true;
}

void machine_add_to_gc_queue(Machine *m) {
        assert(m);

        if (m->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, m->manager->machine_gc_queue, m);
        m->in_gc_queue = true;
}

MachineState machine_get_state(Machine *s) {
        assert(s);

        if (s->class == MACHINE_HOST)
                return MACHINE_RUNNING;

        if (s->stopping)
                return MACHINE_CLOSING;

        if (s->scope_job)
                return MACHINE_OPENING;

        return MACHINE_RUNNING;
}

int machine_kill(Machine *m, KillWho who, int signo) {
        assert(m);

        if (!IN_SET(m->class, MACHINE_VM, MACHINE_CONTAINER))
                return -EOPNOTSUPP;

        if (!m->unit)
                return -ESRCH;

        if (who == KILL_LEADER) /* If we shall simply kill the leader, do so directly */
                return pidref_kill(&m->leader, signo);

        /* Otherwise, make PID 1 do it for us, for the entire cgroup */
        return manager_kill_unit(m->manager, m->unit, signo, NULL);
}

int machine_openpt(Machine *m, int flags, char **ret_slave) {
        assert(m);

        switch (m->class) {

        case MACHINE_HOST:
                return openpt_allocate(flags, ret_slave);

        case MACHINE_CONTAINER:
                if (!pidref_is_set(&m->leader))
                        return -EINVAL;

                return openpt_allocate_in_namespace(m->leader.pid, flags, ret_slave);

        default:
                return -EOPNOTSUPP;
        }
}

int machine_open_terminal(Machine *m, const char *path, int mode) {
        assert(m);

        switch (m->class) {

        case MACHINE_HOST:
                return open_terminal(path, mode);

        case MACHINE_CONTAINER:
                if (!pidref_is_set(&m->leader))
                        return -EINVAL;

                return open_terminal_in_namespace(m->leader.pid, path, mode);

        default:
                return -EOPNOTSUPP;
        }
}

void machine_release_unit(Machine *m) {
        assert(m);

        if (!m->unit)
                return;

        if (m->referenced) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                int r;

                r = manager_unref_unit(m->manager, m->unit, &error);
                if (r < 0)
                        log_warning_errno(r, "Failed to drop reference to machine scope, ignoring: %s",
                                          bus_error_message(&error, r));

                m->referenced = false;
        }

        (void) hashmap_remove(m->manager->machine_units, m->unit);
        m->unit = mfree(m->unit);
}

int machine_get_uid_shift(Machine *m, uid_t *ret) {
        char p[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(pid_t) + 1];
        uid_t uid_base, uid_shift, uid_range;
        gid_t gid_base, gid_shift, gid_range;
        _cleanup_fclose_ FILE *f = NULL;
        int k, r;

        assert(m);
        assert(ret);

        /* Return the base UID/GID of the specified machine. Note that this only works for containers with simple
         * mappings. In most cases setups should be simple like this, and administrators should only care about the
         * basic offset a container has relative to the host. This is what this function exposes.
         *
         * If we encounter any more complex mappings we politely refuse this with ENXIO. */

        if (m->class == MACHINE_HOST) {
                *ret = 0;
                return 0;
        }

        if (m->class != MACHINE_CONTAINER)
                return -EOPNOTSUPP;

        xsprintf(p, "/proc/" PID_FMT "/uid_map", m->leader.pid);
        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT) {
                        /* If the file doesn't exist, user namespacing is off in the kernel, return a zero mapping hence. */
                        *ret = 0;
                        return 0;
                }

                return -errno;
        }

        /* Read the first line. There's at least one. */
        r = uid_map_read_one(f, &uid_base, &uid_shift, &uid_range);
        if (r < 0)
                return r;

        /* Not a mapping starting at 0? Then it's a complex mapping we can't expose here. */
        if (uid_base != 0)
                return -ENXIO;
        /* Insist that at least the nobody user is mapped, everything else is weird, and hence complex, and we don't support it */
        if (uid_range < UID_NOBODY)
                return -ENXIO;

        /* If there's more than one line, then we don't support this mapping. */
        r = safe_fgetc(f, NULL);
        if (r < 0)
                return r;
        if (r != 0) /* Insist on EOF */
                return -ENXIO;

        fclose(f);

        xsprintf(p, "/proc/" PID_FMT "/gid_map", m->leader.pid);
        f = fopen(p, "re");
        if (!f)
                return -errno;

        /* Read the first line. There's at least one. */
        errno = 0;
        k = fscanf(f, GID_FMT " " GID_FMT " " GID_FMT "\n", &gid_base, &gid_shift, &gid_range);
        if (k != 3) {
                if (ferror(f))
                        return errno_or_else(EIO);

                return -EBADMSG;
        }

        /* If there's more than one line, then we don't support this file. */
        r = safe_fgetc(f, NULL);
        if (r < 0)
                return r;
        if (r != 0) /* Insist on EOF */
                return -ENXIO;

        /* If the UID and GID mapping doesn't match, we don't support this mapping. */
        if (uid_base != (uid_t) gid_base)
                return -ENXIO;
        if (uid_shift != (uid_t) gid_shift)
                return -ENXIO;
        if (uid_range != (uid_t) gid_range)
                return -ENXIO;

        *ret = uid_shift;
        return 0;
}

static int machine_owns_uid_internal(
                Machine *machine,
                const char *map_file, /* "uid_map" or "gid_map" */
                uid_t uid,
                uid_t *ret_internal_uid) {

        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r;

        /* This is a generic implementation for both uids and gids, under the assumptions they have the same types and semantics. */
        assert_cc(sizeof(uid_t) == sizeof(gid_t));

        assert(machine);

        /* Checks if the specified host UID is owned by the machine, and returns the UID it maps to
         * internally in the machine */

        if (machine->class != MACHINE_CONTAINER)
                goto negative;

        p = procfs_file_alloca(machine->leader.pid, map_file);
        f = fopen(p, "re");
        if (!f) {
                log_debug_errno(errno, "Failed to open %s, ignoring.", p);
                goto negative;
        }

        for (;;) {
                uid_t uid_base, uid_shift, uid_range, converted;

                r = uid_map_read_one(f, &uid_base, &uid_shift, &uid_range);
                if (r == -ENOMSG)
                        break;
                if (r < 0)
                        return r;

                /* The private user namespace is disabled, ignoring. */
                if (uid_shift == 0)
                        continue;

                if (uid < uid_shift || uid >= uid_shift + uid_range)
                        continue;

                converted = (uid - uid_shift + uid_base);
                if (!uid_is_valid(converted))
                        return -EINVAL;

                if (ret_internal_uid)
                        *ret_internal_uid = converted;

                return true;
        }

negative:
        if (ret_internal_uid)
                *ret_internal_uid = UID_INVALID;

        return false;
}

int machine_owns_uid(Machine *machine, uid_t uid, uid_t *ret_internal_uid) {
        return machine_owns_uid_internal(machine, "uid_map", uid, ret_internal_uid);
}

int machine_owns_gid(Machine *machine, gid_t gid, gid_t *ret_internal_gid) {
        return machine_owns_uid_internal(machine, "gid_map", (uid_t) gid, (uid_t*) ret_internal_gid);
}

static int machine_translate_uid_internal(
                Machine *machine,
                const char *map_file, /* "uid_map" or "gid_map" */
                uid_t uid,
                uid_t *ret_host_uid) {

        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r;

        /* This is a generic implementation for both uids and gids, under the assumptions they have the same types and semantics. */
        assert_cc(sizeof(uid_t) == sizeof(gid_t));

        assert(machine);
        assert(uid_is_valid(uid));

        if (machine->class != MACHINE_CONTAINER)
                return -ESRCH;

        /* Translates a machine UID into a host UID */

        p = procfs_file_alloca(machine->leader.pid, map_file);
        f = fopen(p, "re");
        if (!f)
                return -errno;

        for (;;) {
                uid_t uid_base, uid_shift, uid_range, converted;

                r = uid_map_read_one(f, &uid_base, &uid_shift, &uid_range);
                if (r == -ENOMSG)
                        break;
                if (r < 0)
                        return r;

                if (uid < uid_base || uid >= uid_base + uid_range)
                        continue;

                converted = uid - uid_base + uid_shift;
                if (!uid_is_valid(converted))
                        return -EINVAL;

                if (ret_host_uid)
                        *ret_host_uid = converted;

                return 0;
        }

        return -ESRCH;
}

int machine_translate_uid(Machine *machine, gid_t uid, gid_t *ret_host_uid) {
        return machine_translate_uid_internal(machine, "uid_map", uid, ret_host_uid);
}

int machine_translate_gid(Machine *machine, gid_t gid, gid_t *ret_host_gid) {
        return machine_translate_uid_internal(machine, "gid_map", (uid_t) gid, (uid_t*) ret_host_gid);
}

static const char* const machine_class_table[_MACHINE_CLASS_MAX] = {
        [MACHINE_CONTAINER] = "container",
        [MACHINE_VM] = "vm",
        [MACHINE_HOST] = "host",
};

DEFINE_STRING_TABLE_LOOKUP(machine_class, MachineClass);

static const char* const machine_state_table[_MACHINE_STATE_MAX] = {
        [MACHINE_OPENING] = "opening",
        [MACHINE_RUNNING] = "running",
        [MACHINE_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(machine_state, MachineState);

static const char* const kill_who_table[_KILL_WHO_MAX] = {
        [KILL_LEADER] = "leader",
        [KILL_ALL] = "all"
};

DEFINE_STRING_TABLE_LOOKUP(kill_who, KillWho);
