/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "machine.h"
#include "machine-dbus.h"
#include "machined.h"
#include "mkdir-label.h"
#include "namespace-util.h"
#include "operation.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "uid-range.h"
#include "unit-name.h"
#include "user-util.h"

int machine_new(MachineClass class, const char *name, Machine **ret) {
        _cleanup_(machine_freep) Machine *m = NULL;

        assert(class < _MACHINE_CLASS_MAX);
        assert(ret);

        /* Passing class == _MACHINE_CLASS_INVALID here is fine. It
         * means as much as "we don't know yet", and that we'll figure
         * it out later when loading the state file. */

        m = new(Machine, 1);
        if (!m)
                return -ENOMEM;

        *m = (Machine) {
                .class = class,
                .leader = PIDREF_NULL,
                .supervisor = PIDREF_NULL,
                .vsock_cid = VMADDR_CID_ANY,
        };

        if (name) {
                m->name = strdup(name);
                if (!m->name)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(m);
        return 0;
}

int machine_link(Manager *manager, Machine *machine) {
        int r;

        assert(manager);
        assert(machine);

        if (machine->manager)
                return -EEXIST;
        if (!machine->name)
                return -EINVAL;

        if (machine->class != MACHINE_HOST) {
                char *temp = path_join(manager->state_dir, machine->name);
                if (!temp)
                        return -ENOMEM;

                free_and_replace(machine->state_file, temp);
        }

        r = hashmap_put(manager->machines, machine->name, machine);
        if (r < 0)
                return r;

        machine->manager = manager;

        return 0;
}

Machine* machine_free(Machine *m) {
        if (!m)
                return NULL;

        while (m->operations)
                operation_free(m->operations);

        if (m->in_gc_queue) {
                assert(m->manager);
                LIST_REMOVE(gc_queue, m->manager->machine_gc_queue, m);
        }

        if (m->manager) {
                machine_release_unit(m);

                (void) hashmap_remove(m->manager->machines, m->name);

                if (m->manager->host_machine == m)
                        m->manager->host_machine = NULL;
        }

        m->leader_pidfd_event_source = sd_event_source_disable_unref(m->leader_pidfd_event_source);
        if (pidref_is_set(&m->leader)) {
                if (m->manager)
                        (void) hashmap_remove_value(m->manager->machines_by_leader, &m->leader, m);
                pidref_done(&m->leader);
        }

        m->supervisor_pidfd_event_source = sd_event_source_disable_unref(m->supervisor_pidfd_event_source);
        pidref_done(&m->supervisor);

        sd_bus_message_unref(m->create_message);

        m->cgroup_empty_event_source = sd_event_source_disable_unref(m->cgroup_empty_event_source);

        free(m->name);

        free(m->state_file);
        free(m->service);
        free(m->root_directory);

        free(m->unit);
        free(m->subgroup);
        free(m->scope_job);
        free(m->cgroup);

        free(m->netif);
        free(m->ssh_address);
        free(m->ssh_private_key_path);

        return mfree(m);
}

int machine_save(Machine *m) {
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        if (!m->started)
                return 0;

        _cleanup_(unlink_and_freep) char *sl = NULL; /* auto-unlink! */
        if (m->unit && !m->subgroup) {
                sl = strjoin(m->manager->state_dir, "/unit:", m->unit);
                if (!sl)
                        return log_oom();
        }

        r = mkdir_safe_label(m->manager->state_dir, 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create '%s': %m", m->manager->state_dir);

        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable(m->state_file, O_WRONLY|O_CLOEXEC, &temp_path, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create state file '%s': %m", m->state_file);

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to set access mode for state file '%s' to 0644: %m", m->state_file);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "NAME=%s\n"
                "UID=" UID_FMT "\n",
                m->name,
                m->uid);

        /* We continue to call this "SCOPE=" because it is internal only, and we want to stay compatible with old files */
        env_file_fputs_assignment(f, "SCOPE=", m->unit);
        env_file_fputs_assignment(f, "SCOPE_JOB=", m->scope_job);

        env_file_fputs_assignment(f, "SERVICE=", m->service);
        env_file_fputs_assignment(f, "ROOT=", m->root_directory);

        if (!sd_id128_is_null(m->id))
                fprintf(f, "ID=" SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(m->id));

        if (pidref_is_set(&m->leader)) {
                fprintf(f, "LEADER="PID_FMT"\n", m->leader.pid);
                (void) pidref_acquire_pidfd_id(&m->leader);
                if (m->leader.fd_id != 0)
                        fprintf(f, "LEADER_PIDFDID=%" PRIu64 "\n", m->leader.fd_id);
        }

        if (pidref_is_set(&m->supervisor)) {
                fprintf(f, "SUPERVISOR=" PID_FMT "\n", m->supervisor.pid);
                (void) pidref_acquire_pidfd_id(&m->supervisor);
                if (m->supervisor.fd_id != 0)
                        fprintf(f, "SUPERVISOR_PIDFDID=%" PRIu64 "\n", m->supervisor.fd_id);
        }

        if (m->class != _MACHINE_CLASS_INVALID)
                fprintf(f, "CLASS=%s\n", machine_class_to_string(m->class));

        if (dual_timestamp_is_set(&m->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        m->timestamp.realtime,
                        m->timestamp.monotonic);

        if (m->n_netif > 0) {
                fputs("NETIF=\"", f);
                FOREACH_ARRAY(ifi, m->netif, m->n_netif) {
                        if (*ifi != 0)
                                fputc(' ', f);
                        fprintf(f, "%i", *ifi);
                }
                fputs("\"\n", f);
        }

        if (m->vsock_cid != 0)
                fprintf(f, "VSOCK_CID=%u\n", m->vsock_cid);

        env_file_fputs_assignment(f, "SSH_ADDRESS=", m->ssh_address);
        env_file_fputs_assignment(f, "SSH_PRIVATE_KEY_PATH=", m->ssh_private_key_path);

        r = flink_tmpfile(f, temp_path, m->state_file, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", m->state_file);

        temp_path = mfree(temp_path); /* disarm auto-destroy: temporary file does not exist anymore */

        if (sl) {
                /* Create a symlink from the unit name to the machine name, so that we can quickly find the machine
                 * for each given unit. Ignore error. */
                (void) symlink(m->name, sl);

                /* disarm auto-removal */
                sl = mfree(sl);
        }

        return 0;
}

static void machine_unlink(Machine *m) {
        assert(m);

        if (m->unit && !m->subgroup) {
                const char *sl = strjoina(m->manager->state_dir, "/unit:", m->unit);
                (void) unlink(sl);
        }

        if (m->state_file)
                (void) unlink(m->state_file);
}

static void parse_pid_and_pidfdid(
                PidRef *pidref,
                const char *pid,
                const char *pidfdid,
                const char *name) {

        int r;

        assert(pidref);
        assert(name);

        pidref_done(pidref);

        if (!pid)
                return;
        r = pidref_set_pidstr(pidref, pid);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to set %s PID to '%s', ignoring: %m", name, pid);

        if (!pidfdid)
                return;
        uint64_t fd_id;
        r = safe_atou64(pidfdid, &fd_id);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to parse %s pidfd ID, ignoring: %s", name, pidfdid);
        (void) pidref_acquire_pidfd_id(pidref);
        if (fd_id != pidref->fd_id) {
                log_debug("PID of %s got recycled, ignoring.", name);
                pidref_done(pidref);
        }
}

int machine_load(Machine *m) {
        _cleanup_free_ char *name = NULL, *realtime = NULL, *monotonic = NULL, *id = NULL,
                *leader = NULL, *leader_pidfdid = NULL, *supervisor = NULL, *supervisor_pidfdid = NULL,
                *class = NULL, *netif = NULL, *vsock_cid = NULL, *uid = NULL;
        int r;

        assert(m);

        if (!m->state_file)
                return 0;

        r = parse_env_file(NULL, m->state_file,
                           "NAME",                 &name,
                           "SCOPE",                &m->unit,
                           "SUBGROUP",             &m->subgroup,
                           "SCOPE_JOB",            &m->scope_job,
                           "SERVICE",              &m->service,
                           "ROOT",                 &m->root_directory,
                           "ID",                   &id,
                           "LEADER",               &leader,
                           "LEADER_PIDFDID",       &leader_pidfdid,
                           "SUPERVISOR",           &supervisor,
                           "SUPERVISOR_PIDFDID",   &supervisor_pidfdid,
                           "CLASS",                &class,
                           "REALTIME",             &realtime,
                           "MONOTONIC",            &monotonic,
                           "NETIF",                &netif,
                           "VSOCK_CID",            &vsock_cid,
                           "SSH_ADDRESS",          &m->ssh_address,
                           "SSH_PRIVATE_KEY_PATH", &m->ssh_private_key_path,
                           "UID",                  &uid);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", m->state_file);

        if (!streq_ptr(name, m->name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "State file '%s' for machine '%s' reports a different name '%s', refusing", m->state_file, m->name, name);

        if (id)
                (void) sd_id128_from_string(id, &m->id);

        parse_pid_and_pidfdid(&m->leader, leader, leader_pidfdid, "leader");
        parse_pid_and_pidfdid(&m->supervisor, supervisor, supervisor_pidfdid, "supervisor");

        if (class) {
                MachineClass c = machine_class_from_string(class);
                if (c >= 0)
                        m->class = c;
        }

        if (realtime)
                (void) deserialize_usec(realtime, &m->timestamp.realtime);
        if (monotonic)
                (void) deserialize_usec(monotonic, &m->timestamp.monotonic);

        m->netif = mfree(m->netif);
        m->n_netif = 0;
        if (netif) {
                _cleanup_free_ int *ni = NULL;
                size_t nr = 0;

                for (const char *p = netif;;) {
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

                m->netif = TAKE_PTR(ni);
                m->n_netif = nr;
        }

        m->vsock_cid = 0;
        if (vsock_cid) {
                r = safe_atou(vsock_cid, &m->vsock_cid);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse AF_VSOCK CID, ignoring: %s", vsock_cid);
        }

        if (uid) {
                r = parse_uid(uid, &m->uid);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse owning UID, ignoring: %s", uid);
        }

        return r;
}

static int machine_start_scope(
                Machine *machine,
                bool allow_pidfd,
                sd_bus_message *more_properties,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *escaped = NULL, *unit = NULL;
        const char *description;
        int r;

        assert(machine);
        assert(pidref_is_set(&machine->leader));
        assert(!machine->unit);
        assert(!machine->subgroup);

        escaped = unit_name_escape(machine->name);
        if (!escaped)
                return log_oom();

        unit = strjoin("machine-", escaped, ".scope");
        if (!unit)
                return log_oom();

        r = bus_message_new_method_call(
                        machine->manager->api_bus,
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

        r = bus_append_scope_pidref(m, &machine->leader, allow_pidfd);
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        m, "(sv)(sv)(sv)(sv)",
                        "Delegate", "b", 1,
                        "CollectMode", "s", "inactive-or-failed",
                        "AddRef", "b", 1,
                        "TasksMax", "t", UINT64_C(16384));
        if (r < 0)
                return r;

        if (machine->uid != 0) {
                _cleanup_free_ char *u = NULL;

                if (asprintf(&u, UID_FMT, machine->uid) < 0)
                        return -ENOMEM;

                r = sd_bus_message_append(
                                m, "(sv)",
                                "User", "s", u);
                if (r < 0)
                        return r;
        }

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

        r = sd_bus_call(NULL, m, 0, &e, &reply);
        if (r < 0) {
                /* If this failed with a property we couldn't write, this is quite likely because the server
                 * doesn't support PIDFDs yet, let's try without. */
                if (allow_pidfd &&
                    sd_bus_error_has_names(&e, SD_BUS_ERROR_UNKNOWN_PROPERTY, SD_BUS_ERROR_PROPERTY_READ_ONLY))
                        return machine_start_scope(machine, /* allow_pidfd = */ false, more_properties, error);

                return sd_bus_error_move(error, &e);
        }

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
                r = machine_start_scope(m, /* allow_pidfd = */ true, properties, error);
                if (r < 0)
                        return log_error_errno(r, "Failed to start machine scope: %s", bus_error_message(error, r));
        }

        assert(m->unit);

        if (!m->subgroup) {
                r = hashmap_ensure_put(&m->manager->machines_by_unit, &string_hash_ops, m->unit, m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int machine_dispatch_leader_pidfd(sd_event_source *s, int fd, unsigned revents, void *userdata) {
        Machine *m = ASSERT_PTR(userdata);

        m->leader_pidfd_event_source = sd_event_source_disable_unref(m->leader_pidfd_event_source);
        machine_add_to_gc_queue(m);

        return 0;
}

static int machine_dispatch_supervisor_pidfd(sd_event_source *s, int fd, unsigned revents, void *userdata) {
        Machine *m = ASSERT_PTR(userdata);

        m->supervisor_pidfd_event_source = sd_event_source_disable_unref(m->supervisor_pidfd_event_source);
        machine_add_to_gc_queue(m);

        return 0;
}

static int machine_watch_pidfd(Machine *m, PidRef *pidref, sd_event_source **source, sd_event_io_handler_t cb) {
        int r;

        assert(m);
        assert(m->manager);
        assert(source);
        assert(!*source);
        assert(cb);

        if (!pidref_is_set(pidref) || pidref->fd < 0)
                return 0;

        /* If we have a pidfd for the leader or supervisor, let's also track it for POLLIN, and GC the machine
         * automatically if it dies */

        r = sd_event_add_io(m->manager->event, source, pidref->fd, EPOLLIN, cb, m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(*source, "machine-pidfd");

        return 0;
}

static int machine_dispatch_cgroup_empty(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        Machine *m = ASSERT_PTR(userdata);
        int r;

        assert(m->cgroup);

        r = cg_is_empty(m->cgroup);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if cgroup '%s' is empty: %m", m->cgroup);

        if (r > 0)
                machine_add_to_gc_queue(m);

        return 0;
}

static int machine_watch_cgroup(Machine *m) {
        int r;

        assert(m);
        assert(!m->cgroup_empty_event_source);

        if (!m->cgroup)
                return 0;

        _cleanup_free_ char *p = NULL;
        r = cg_get_path(m->cgroup, "cgroup.events", &p);
        if (r < 0)
                return log_error_errno(r, "Failed to get cgroup path for cgroup '%s': %m", m->cgroup);

        r = sd_event_add_inotify(m->manager->event, &m->cgroup_empty_event_source, p, IN_MODIFY, machine_dispatch_cgroup_empty, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch %s events: %m", p);

        return 0;
}

int machine_start(Machine *m, sd_bus_message *properties, sd_bus_error *error) {
        int r;

        assert(m);

        if (!IN_SET(m->class, MACHINE_CONTAINER, MACHINE_VM))
                return -EOPNOTSUPP;

        if (m->started)
                return 0;

        r = hashmap_ensure_put(&m->manager->machines_by_leader, &pidref_hash_ops, &m->leader, m);
        if (r < 0)
                return r;

        r = machine_watch_pidfd(m, &m->leader, &m->leader_pidfd_event_source, machine_dispatch_leader_pidfd);
        if (r < 0)
                return r;

        r = machine_watch_pidfd(m, &m->supervisor, &m->supervisor_pidfd_event_source, machine_dispatch_supervisor_pidfd);
        if (r < 0)
                return r;

        r = machine_watch_cgroup(m);
        if (r < 0)
                return r;

        /* Create cgroup */
        r = machine_ensure_scope(m, properties, error);
        if (r < 0)
                return r;

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_MACHINE_START_STR),
                   LOG_ITEM("NAME=%s", m->name),
                   LOG_ITEM("LEADER="PID_FMT, m->leader.pid),
                   LOG_MESSAGE("New machine %s.", m->name));

        if (!dual_timestamp_is_set(&m->timestamp))
                dual_timestamp_now(&m->timestamp);

        m->started = true;

        /* Save new machine data */
        machine_save(m);

        machine_send_signal(m, true);

        return 0;
}

int machine_stop(Machine *m) {
        int r;

        assert(m);

        log_debug("Stopping machine '%s'.", m->name);

        if (!IN_SET(m->class, MACHINE_CONTAINER, MACHINE_VM))
                return -EOPNOTSUPP;

        if (m->unit && !m->subgroup) {
                /* If the machine runs as its own unit, then we'll terminate that */
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                char *job = NULL;

                r = manager_stop_unit(m->manager, m->unit, &error, &job);
                if (r < 0)
                        return log_error_errno(r, "Failed to stop machine unit: %s", bus_error_message(&error, r));

                free_and_replace(m->scope_job, job);

        } else if (pidref_is_set(&m->supervisor)) {
                /* Otherwise, send a friendly SIGTERM to the supervisor */
                r = pidref_kill(&m->supervisor, SIGTERM);
                if (r < 0)
                        return log_error_errno(r, "Failed to kill supervisor process " PID_FMT " of machine '%s': %m", m->supervisor.pid, m->name);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Don't know how to terminate machine '%s'.", m->name);

        m->stopping = true;

        machine_save(m);

        return 0;
}

int machine_finalize(Machine *m) {
        assert(m);

        if (m->started) {
                log_struct(LOG_INFO,
                           LOG_MESSAGE_ID(SD_MESSAGE_MACHINE_STOP_STR),
                           LOG_ITEM("NAME=%s", m->name),
                           LOG_ITEM("LEADER="PID_FMT, m->leader.pid),
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
        int r;

        assert(m);

        if (m->class == MACHINE_HOST)
                return false;

        if (drop_not_started && !m->started)
                return true;

        r = pidref_is_alive(&m->leader);
        if (r == -ESRCH)
                return true;
        if (r < 0)
                log_debug_errno(r, "Unable to determine if leader PID " PID_FMT " is still alive, assuming not: %m", m->leader.pid);
        if (r > 0)
                return false;

        if (m->scope_job) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_job_is_active(m->manager, m->scope_job, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether job '%s' is active, assuming it is: %s", m->scope_job, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        if (m->unit && !m->subgroup) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_unit_is_active(m->manager, m->unit, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether unit '%s' is active, assuming it is: %s", m->unit, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        if (m->cgroup) {
                r = cg_is_empty(m->cgroup);
                if (IN_SET(r, 0, -ENOENT))
                        return true;
                if (r < 0)
                        log_debug_errno(r, "Failed to determine if cgroup '%s' is empty, ignoring: %m", m->cgroup);
        }

        return true;
}

void machine_add_to_gc_queue(Machine *m) {
        assert(m);

        if (m->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, m->manager->machine_gc_queue, m);
        m->in_gc_queue = true;

        manager_enqueue_gc(m->manager);
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

int machine_kill(Machine *m, KillWhom whom, int signo) {
        assert(m);

        log_debug("Killing machine '%s' (%s) with signal %s.", m->name, kill_whom_to_string(whom), signal_to_string(signo));

        if (!IN_SET(m->class, MACHINE_VM, MACHINE_CONTAINER))
                return -EOPNOTSUPP;

        switch (whom) {

        case KILL_LEADER:
                return pidref_kill(&m->leader, signo);

        case KILL_SUPERVISOR:
                return pidref_kill(&m->supervisor, signo);

        case KILL_ALL:
                if (!m->unit)
                        return -ESRCH;

                return manager_kill_unit(m->manager, m->unit, m->subgroup, signo, /* error= */ NULL);

        default:
                assert_not_reached();
        }
}

int machine_openpt(Machine *m, int flags, char **ret_peer) {
        assert(m);

        switch (m->class) {

        case MACHINE_HOST:
                return openpt_allocate(flags, ret_peer);

        case MACHINE_CONTAINER:
                if (!pidref_is_set(&m->leader))
                        return -EINVAL;

                return openpt_allocate_in_namespace(&m->leader, flags, ret_peer);

        default:
                return -EOPNOTSUPP;
        }
}

static int machine_bus_new(Machine *m, sd_bus_error *error, sd_bus **ret) {
        int r;

        assert(m);
        assert(ret);

        switch (m->class) {

        case MACHINE_HOST:
                *ret = NULL;
                return 0;

        case MACHINE_CONTAINER: {
                _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
                char *address;

                r = sd_bus_new(&bus);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate new DBus: %m");

                if (asprintf(&address, "x-machine-unix:pid=%" PID_PRI, m->leader.pid) < 0)
                        return -ENOMEM;

                bus->address = address;
                bus->bus_client = true;
                bus->trusted = false;
                bus->runtime_scope = RUNTIME_SCOPE_SYSTEM;

                r = sd_bus_start(bus);
                if (r == -ENOENT)
                        return sd_bus_error_set_errnof(error, r, "There is no system bus in container %s.", m->name);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(bus);
                return 0;
        }

        default:
                return -EOPNOTSUPP;
        }
}

int machine_start_getty(Machine *m, const char *ptmx_name, sd_bus_error *error) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *allocated_bus = NULL;
        sd_bus *container_bus = NULL;
        const char *p, *getty;
        int r;

        assert(m);
        assert(ptmx_name);

        p = path_startswith(ptmx_name, "/dev/pts/");
        if (!p)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Path of pseudo TTY has unexpected prefix");

        r = machine_bus_new(m, error, &allocated_bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to create DBus to machine: %m");

        container_bus = allocated_bus ?: m->manager->system_bus;
        getty = strjoina("container-getty@", p, ".service");

        r = bus_call_method(container_bus, bus_systemd_mgr, "StartUnit", error, /* ret_reply = */ NULL, "ss", getty, "replace");
        if (r < 0)
                return log_debug_errno(r, "Failed to StartUnit '%s' in container '%s': %m", getty, m->name);

        return 0;
}

int machine_start_shell(
                Machine *m,
                int ptmx_fd,
                const char *ptmx_name,
                const char *user,
                const char *path,
                char **args,
                char **env,
                sd_bus_error *error) {
        _cleanup_close_ int pty_fd = -EBADF;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *tm = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *allocated_bus = NULL;
        const char *p, *utmp_id, *unit, *description;
        sd_bus *container_bus = NULL;
        int r;

        assert(m);
        assert(ptmx_fd >= 0);
        assert(ptmx_name);

        if (isempty(user) || isempty(path) || strv_isempty(args))
                return -EINVAL;

        p = path_startswith(ptmx_name, "/dev/pts/");
        utmp_id = path_startswith(ptmx_name, "/dev/");
        if (!p || !utmp_id)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Path of pseudo TTY has unexpected prefix");

        pty_fd = pty_open_peer(ptmx_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (pty_fd < 0)
                return log_debug_errno(pty_fd, "Failed to open terminal: %m");

        r = machine_bus_new(m, error, &allocated_bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to create DBus to machine: %m");

        container_bus = allocated_bus ?: m->manager->system_bus;
        r = bus_message_new_method_call(container_bus, &tm, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return r;

        /* Name and mode */
        unit = strjoina("container-shell@", p, ".service");
        r = sd_bus_message_append(tm, "ss", unit, "fail");
        if (r < 0)
                return r;

        /* Properties */
        r = sd_bus_message_open_container(tm, 'a', "(sv)");
        if (r < 0)
                return r;

        description = strjoina("Shell for User ", user);
        r = sd_bus_message_append(tm,
                                  "(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)(sv)",
                                  "Description", "s", description,
                                  "StandardInputFileDescriptor", "h", pty_fd,
                                  "StandardOutputFileDescriptor", "h", pty_fd,
                                  "StandardErrorFileDescriptor", "h", pty_fd,
                                  "SendSIGHUP", "b", true,
                                  "IgnoreSIGPIPE", "b", false,
                                  "KillMode", "s", "mixed",
                                  "TTYPath", "s", ptmx_name,
                                  "TTYReset", "b", true,
                                  "UtmpIdentifier", "s", utmp_id,
                                  "UtmpMode", "s", "user",
                                  "PAMName", "s", "login",
                                  "WorkingDirectory", "s", "-~");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "(sv)", "User", "s", user);
        if (r < 0)
                return r;

        if (!strv_isempty(env)) {
                r = sd_bus_message_open_container(tm, 'r', "sv");
                if (r < 0)
                        return r;

                r = sd_bus_message_append(tm, "s", "Environment");
                if (r < 0)
                        return r;

                r = sd_bus_message_open_container(tm, 'v', "as");
                if (r < 0)
                        return r;

                r = sd_bus_message_append_strv(tm, env);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(tm);
                if (r < 0)
                        return r;

                r = sd_bus_message_close_container(tm);
                if (r < 0)
                        return r;
        }

        /* Exec container */
        r = sd_bus_message_open_container(tm, 'r', "sv");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "s", "ExecStart");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'v', "a(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'a', "(sasb)");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(tm, 'r', "sasb");
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "s", path);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(tm, args);
        if (r < 0)
                return r;

        r = sd_bus_message_append(tm, "b", true);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(tm);
        if (r < 0)
                return r;

        /* Auxiliary units */
        r = sd_bus_message_append(tm, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(container_bus, tm, 0, error, NULL);
        if (r < 0)
                return r;

        return 0;
}

char** machine_default_shell_args(const char *user) {
        _cleanup_strv_free_ char **args = NULL;
        int r;

        assert(user);

        args = new0(char*, 3 + 1);
        if (!args)
                return NULL;

        args[0] = strdup("sh");
        if (!args[0])
                return NULL;

        args[1] = strdup("-c");
        if (!args[1])
                return NULL;

        r = asprintf(&args[2],
                     "shell=$(getent passwd %s 2>/dev/null | { IFS=: read _ _ _ _ _ _ x; echo \"$x\"; })\n"\
                     "exec \"${shell:-/bin/sh}\" -l", /* -l is means --login */
                     user);
        if (r < 0) {
                args[2] = NULL;
                return NULL;
        }

        return TAKE_PTR(args);
}

int machine_copy_from_to_operation(
                Manager *manager,
                Machine *machine,
                const char *host_path,
                const char *container_path,
                bool copy_from_container,
                CopyFlags copy_flags,
                Operation **ret) {

        _cleanup_close_ int host_fd = -EBADF, target_mntns_fd = -EBADF, source_mntns_fd = -EBADF;
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        _cleanup_free_ char *host_basename = NULL, *container_basename = NULL;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        uid_t uid_shift;
        int r;

        assert(manager);
        assert(machine);
        assert(ret);

        if (isempty(host_path) || isempty(container_path))
                return -EINVAL;

        r = path_extract_filename(host_path, &host_basename);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract file name of '%s' path: %m", host_path);

        r = path_extract_filename(container_path, &container_basename);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract file name of '%s' path: %m", container_path);

        host_fd = open_parent(host_path, O_CLOEXEC, 0);
        if (host_fd < 0)
                return log_debug_errno(host_fd, "Failed to open host directory '%s': %m", host_path);

        r = machine_get_uid_shift(machine, &uid_shift);
        if (r < 0)
                return log_debug_errno(r, "Failed to get UID shift of machine '%s': %m", machine->name);

        target_mntns_fd = pidref_namespace_open_by_type(&machine->leader, NAMESPACE_MOUNT);
        if (target_mntns_fd < 0)
                return log_debug_errno(target_mntns_fd, "Failed to open mount namespace of machine '%s': %m", machine->name);

        source_mntns_fd = namespace_open_by_type(NAMESPACE_MOUNT);
        if (source_mntns_fd < 0)
                return log_debug_errno(source_mntns_fd, "Failed to open our own mount namespace: %m");

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = namespace_fork("(sd-copyns)",
                           "(sd-copy)",
                           /* except_fds = */ NULL,
                           /* n_except_fds = */ 0,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                           /* pidns_fd = */ -EBADF,
                           target_mntns_fd,
                           /* netns_fd = */ -EBADF,
                           /* userns_fd = */ -EBADF,
                           /* root_fd = */ -EBADF,
                           &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork into mount namespace of machine '%s': %m", machine->name);
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                _cleanup_close_ int container_fd = -EBADF;
                container_fd = open_parent(container_path, O_CLOEXEC, 0);
                if (container_fd < 0) {
                        log_debug_errno(container_fd, "Failed to open container directory: %m");
                        report_errno_and_exit(errno_pipe_fd[1], container_fd);
                }

                /* Rejoin the host namespace, so that /proc/self/fd/… works, which copy_tree_at() relies on
                 * in some cases (by means of fd_reopen()) */
                if (setns(source_mntns_fd, CLONE_NEWNS) < 0) {
                        r = log_debug_errno(errno, "Failed to rejoin namespace of host: %m");
                        report_errno_and_exit(errno_pipe_fd[1], r);
                }

                /* Run the actual copy operation. Note that when a UID shift is set we'll either clamp the UID/GID to
                 * 0 or to the actual UID shift depending on the direction we copy. If no UID shift is set we'll copy
                 * the UID/GIDs as they are. */
                if (copy_from_container)
                        r = copy_tree_at(
                                        container_fd,
                                        container_basename,
                                        host_fd,
                                        host_basename,
                                        uid_shift == 0 ? UID_INVALID : 0,
                                        uid_shift == 0 ? GID_INVALID : 0,
                                        copy_flags,
                                        /* denylist = */ NULL,
                                        /* subvolumes = */ NULL);
                else
                        r = copy_tree_at(
                                        host_fd,
                                        host_basename,
                                        container_fd,
                                        container_basename,
                                        uid_shift == 0 ? UID_INVALID : uid_shift,
                                        uid_shift == 0 ? GID_INVALID : uid_shift,
                                        copy_flags,
                                        /* denylist = */ NULL,
                                        /* subvolumes = */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to copy tree: %m");

                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        Operation *operation;
        r = operation_new(manager, machine, child, errno_pipe_fd[0], &operation);
        if (r < 0)
                return r;

        TAKE_FD(errno_pipe_fd[0]);
        TAKE_PID(child);

        *ret = operation;
        return 0;
}

void machine_release_unit(Machine *m) {
        assert(m);

        if (!m->unit)
                return;

        assert(m->manager);

        if (m->referenced) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                int r;

                r = manager_unref_unit(m->manager, m->unit, &error);
                if (r < 0)
                        log_full_errno(ERRNO_IS_DISCONNECT(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to drop reference to machine scope, ignoring: %s",
                                       bus_error_message(&error, r));

                m->referenced = false;
        }

        if (!m->subgroup)
                (void) hashmap_remove_value(m->manager->machines_by_unit, m->unit, m);

        m->unit = mfree(m->unit);

        /* Also free the subgroup, because it only makes sense in the context of the unit */
        m->subgroup = mfree(m->subgroup);
}

int machine_get_uid_shift(Machine *m, uid_t *ret) {
        char p[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(pid_t) + 1];
        uid_t uid_base, uid_shift, uid_range;
        gid_t gid_base, gid_shift, gid_range;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

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
        r = fscanf(f, GID_FMT " " GID_FMT " " GID_FMT "\n", &gid_base, &gid_shift, &gid_range);
        if (r == EOF)
                return errno_or_else(ENOMSG);
        assert(r >= 0);
        if (r != 3)
                return -EBADMSG;

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

        r = pidref_verify(&m->leader);
        if (r < 0)
                return r;

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

                r = pidref_verify(&machine->leader);
                if (r < 0)
                        return r;

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

                r = pidref_verify(&machine->leader);
                if (r < 0)
                        return r;

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

int machine_open_root_directory(Machine *machine) {
        int r;

        assert(machine);

        switch (machine->class) {
        case MACHINE_HOST: {
                int fd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to open host root directory: %m");

                return fd;
        }

        case MACHINE_CONTAINER: {
                _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF;
                _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR, fd_pass_socket[2] = EBADF_PAIR;
                pid_t child;

                r = pidref_namespace_open(&machine->leader,
                                          /* ret_pidns_fd = */ NULL,
                                          &mntns_fd,
                                          /* ret_netns_fd = */ NULL,
                                          /* ret_userns_fd = */ NULL,
                                          &root_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to open mount namespace of machine '%s': %m", machine->name);

                if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                        return log_debug_errno(errno, "Failed to open pipe: %m");

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, fd_pass_socket) < 0)
                        return log_debug_errno(errno, "Failed to create socket pair: %m");

                r = namespace_fork(
                                "(sd-openrootns)",
                                "(sd-openroot)",
                                /* except_fds = */ NULL,
                                /* n_except_fds = */ 0,
                                FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                                /* pidns_fd = */  -EBADF,
                                mntns_fd,
                                /* netns_fd = */  -EBADF,
                                /* userns_fd = */ -EBADF,
                                root_fd,
                                &child);
                if (r < 0)
                        return log_debug_errno(r, "Failed to fork into mount namespace of machine '%s': %m", machine->name);
                if (r == 0) {
                        _cleanup_close_ int dfd = -EBADF;

                        errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);
                        fd_pass_socket[0] = safe_close(fd_pass_socket[0]);

                        dfd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                        if (dfd < 0) {
                                log_debug_errno(errno, "Failed to open root directory of machine '%s': %m", machine->name);
                                report_errno_and_exit(errno_pipe_fd[1], -errno);
                        }

                        r = send_one_fd(fd_pass_socket[1], dfd, /* flags = */ 0);
                        dfd = safe_close(dfd);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to send FD over socket: %m");
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }

                        _exit(EXIT_SUCCESS);
                }

                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);
                fd_pass_socket[1] = safe_close(fd_pass_socket[1]);

                r = wait_for_terminate_and_check("(sd-openrootns)", child, /* flags = */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to wait for child: %m");

                r = read_errno(errno_pipe_fd[0]); /* the function does debug reporting */
                if (r < 0)
                        return r;

                int fd = receive_one_fd(fd_pass_socket[0], MSG_DONTWAIT);
                if (fd < 0)
                        return log_debug_errno(fd, "Failed to receive FD from child: %m");

                return fd;
        }

        default:
                return -EOPNOTSUPP;
        }
}

static const char* const machine_class_table[_MACHINE_CLASS_MAX] = {
        [MACHINE_CONTAINER] = "container",
        [MACHINE_VM]        = "vm",
        [MACHINE_HOST]      = "host",
};

DEFINE_STRING_TABLE_LOOKUP(machine_class, MachineClass);

static const char* const machine_state_table[_MACHINE_STATE_MAX] = {
        [MACHINE_OPENING] = "opening",
        [MACHINE_RUNNING] = "running",
        [MACHINE_CLOSING] = "closing"
};

DEFINE_STRING_TABLE_LOOKUP(machine_state, MachineState);

static const char* const kill_whom_table[_KILL_WHOM_MAX] = {
        [KILL_LEADER]     = "leader",
        [KILL_SUPERVISOR] = "supervisor",
        [KILL_ALL]        = "all",
};

DEFINE_STRING_TABLE_LOOKUP(kill_whom, KillWhom);

static const char* const acquire_metadata_table[_ACQUIRE_METADATA_MAX] = {
        [ACQUIRE_METADATA_NO]       = "no",
        [ACQUIRE_METADATA_YES]      = "yes",
        [ACQUIRE_METADATA_GRACEFUL] = "graceful"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(acquire_metadata, AcquireMetadata, ACQUIRE_METADATA_YES);
