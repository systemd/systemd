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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/capability.h>

#include "sd-id128.h"
#include "sd-messages.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "special.h"
#include "fileio-label.h"
#include "label.h"
#include "utf8.h"
#include "unit-name.h"
#include "bus-util.h"
#include "bus-errors.h"
#include "time-util.h"
#include "cgroup-util.h"
#include "machined.h"

static int method_get_machine(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        p = machine_bus_path(machine);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_machine_by_pid(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;
        Machine *machine = NULL;
        pid_t pid;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;

        if (pid == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        r = manager_get_machine_by_pid(m, pid, &machine);
        if (r < 0)
                return r;
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_MACHINE_FOR_PID, "PID "PID_FMT" does not belong to any known machine", pid);

        p = machine_bus_path(machine);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_machines(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Machine *machine;
        Iterator i;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        r = sd_bus_message_open_container(reply, 'a', "(ssso)");
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        HASHMAP_FOREACH(machine, m->machines, i) {
                _cleanup_free_ char *p = NULL;

                p = machine_bus_path(machine);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(ssso)",
                                          machine->name,
                                          strempty(machine_class_to_string(machine->class)),
                                          machine->service,
                                          p);
                if (r < 0)
                        return sd_bus_error_set_errno(error, r);
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return sd_bus_send(bus, reply, NULL);
}

static int method_create_or_register_machine(Manager *manager, sd_bus_message *message, Machine **_m, sd_bus_error *error) {
        const char *name, *service, *class, *root_directory;
        MachineClass c;
        uint32_t leader;
        sd_id128_t id;
        const void *v;
        Machine *m;
        size_t n;
        int r;

        assert(manager);
        assert(message);
        assert(_m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;
        if (!machine_name_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine name");

        r = sd_bus_message_read_array(message, 'y', &v, &n);
        if (r < 0)
                return r;
        if (n == 0)
                id = SD_ID128_NULL;
        else if (n == 16)
                memcpy(&id, v, n);
        else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine ID parameter");

        r = sd_bus_message_read(message, "ssus", &service, &class, &leader, &root_directory);
        if (r < 0)
                return r;

        if (isempty(class))
                c = _MACHINE_CLASS_INVALID;
        else {
                c = machine_class_from_string(class);
                if (c < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid machine class parameter");
        }

        if (leader == 1)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid leader PID");

        if (!isempty(root_directory) && !path_is_absolute(root_directory))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Root directory must be empty or an absolute path");

        if (leader == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                assert_cc(sizeof(uint32_t) == sizeof(pid_t));

                r = sd_bus_creds_get_pid(creds, (pid_t*) &leader);
                if (r < 0)
                        return r;
        }

        if (hashmap_get(manager->machines, name))
                return sd_bus_error_setf(error, BUS_ERROR_MACHINE_EXISTS, "Machine '%s' already exists", name);

        r = manager_add_machine(manager, name, &m);
        if (r < 0)
                return r;

        m->leader = leader;
        m->class = c;
        m->id = id;

        if (!isempty(service)) {
                m->service = strdup(service);
                if (!m->service) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        if (!isempty(root_directory)) {
                m->root_directory = strdup(root_directory);
                if (!m->root_directory) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        *_m = m;

        return 1;

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_create_machine(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        Machine *m = NULL;
        int r;

        r = method_create_or_register_machine(manager, message, &m, error);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                goto fail;

        r = machine_start(m, message, error);
        if (r < 0)
                goto fail;

        m->create_message = sd_bus_message_ref(message);
        return 1;

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_register_machine(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        _cleanup_free_ char *p = NULL;
        Machine *m = NULL;
        int r;

        r = method_create_or_register_machine(manager, message, &m, error);
        if (r < 0)
                return r;

        r = cg_pid_get_unit(m->leader, &m->unit);
        if (r < 0) {
                r = sd_bus_error_set_errnof(error, r, "Failed to determine unit of process "PID_FMT" : %s", m->leader, strerror(-r));
                goto fail;
        }

        m->registered = true;

        r = machine_start(m, NULL, error);
        if (r < 0)
                goto fail;

        p = machine_bus_path(m);
        if (!p) {
                r = -ENOMEM;
                goto fail;
        }

        return sd_bus_reply_method_return(message, "o", p);

fail:
        machine_add_to_gc_queue(m);
        return r;
}

static int method_terminate_machine(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_terminate(bus, message, machine, error);
}

static int method_kill_machine(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_kill(bus, message, machine, error);
}

static int method_get_machine_addresses(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_get_addresses(bus, message, machine, error);
}

static int method_get_machine_os_release(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        const char *name;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        machine = hashmap_get(m->machines, name);
        if (!machine)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_MACHINE, "No machine '%s' known", name);

        return bus_machine_method_get_os_release(bus, message, machine, error);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("GetMachine", "s", "o", method_get_machine, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineByPID", "u", "o", method_get_machine_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListMachines", NULL, "a(ssso)", method_list_machines, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateMachine", "sayssusa(sv)", "o", method_create_machine, 0),
        SD_BUS_METHOD("RegisterMachine", "sayssus", "o", method_register_machine, 0),
        SD_BUS_METHOD("KillMachine", "ssi", NULL, method_kill_machine, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("TerminateMachine", "s", NULL, method_terminate_machine, SD_BUS_VTABLE_CAPABILITY(CAP_KILL)),
        SD_BUS_METHOD("GetMachineAddresses", "s", "a(yay)", method_get_machine_addresses, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetMachineOSRelease", "s", "a{ss}", method_get_machine_os_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("MachineNew", "so", 0),
        SD_BUS_SIGNAL("MachineRemoved", "so", 0),
        SD_BUS_VTABLE_END
};

int match_job_removed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *result, *unit;
        Manager *m = userdata;
        Machine *machine;
        uint32_t id;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        machine = hashmap_get(m->machine_units, unit);
        if (!machine)
                return 0;

        if (streq_ptr(path, machine->scope_job)) {
                free(machine->scope_job);
                machine->scope_job = NULL;

                if (machine->started) {
                        if (streq(result, "done"))
                                machine_send_create_reply(machine, NULL);
                        else {
                                _cleanup_bus_error_free_ sd_bus_error e = SD_BUS_ERROR_NULL;

                                sd_bus_error_setf(&e, BUS_ERROR_JOB_FAILED, "Start job for unit %s failed with '%s'", unit, result);

                                machine_send_create_reply(machine, &e);
                        }
                } else
                        machine_save(machine);
        }

        machine_add_to_gc_queue(machine);
        return 0;
}

int match_properties_changed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *unit = NULL;
        Manager *m = userdata;
        Machine *machine;
        const char *path;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r < 0)
                return r;

        machine = hashmap_get(m->machine_units, unit);
        if (machine)
                machine_add_to_gc_queue(machine);

        return 0;
}

int match_unit_removed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = userdata;
        Machine *machine;
        int r;

        assert(bus);
        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        machine = hashmap_get(m->machine_units, unit);
        if (machine)
                machine_add_to_gc_queue(machine);

        return 0;
}

int match_reloading(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        Machine *machine;
        Iterator i;
        int b, r;

        assert(bus);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }
        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our machines */
        log_debug("System manager has been reloaded, rechecking machines...");

        HASHMAP_FOREACH(machine, m->machines, i)
                machine_add_to_gc_queue(machine);

        return 0;
}

int manager_start_scope(
                Manager *manager,
                const char *scope,
                pid_t pid,
                const char *slice,
                const char *description,
                sd_bus_message *more_properties,
                sd_bus_error *error,
                char **job) {

        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        int r;

        assert(manager);
        assert(scope);
        assert(pid > 1);

        r = sd_bus_message_new_method_call(
                        manager->bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", strempty(scope), "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        if (!isempty(slice)) {
                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        if (!isempty(description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", description);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, pid);
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

        r = sd_bus_call(manager->bus, m, 0, error, &reply);
        if (r < 0)
                return r;

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_stop_unit(Manager *manager, const char *unit, sd_bus_error *error, char **job) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StopUnit",
                        error,
                        &reply,
                        "ss", unit, "fail");
        if (r < 0) {
                if (sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(error, BUS_ERROR_LOAD_FAILED)) {

                        if (job)
                                *job = NULL;

                        sd_bus_error_free(error);
                        return 0;
                }

                return r;
        }

        if (job) {
                const char *j;
                char *copy;

                r = sd_bus_message_read(reply, "o", &j);
                if (r < 0)
                        return r;

                copy = strdup(j);
                if (!copy)
                        return -ENOMEM;

                *job = copy;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, int signo, sd_bus_error *error) {
        assert(manager);
        assert(unit);

        return sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "KillUnit",
                        error,
                        NULL,
                        "ssi", unit, "all", signo);
}

int manager_unit_is_active(Manager *manager, const char *unit) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        const char *state;
        int r;

        assert(manager);
        assert(unit);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ||
                    sd_bus_error_has_name(&error, BUS_ERROR_LOAD_FAILED))
                        return false;

                return r;
        }

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return -EINVAL;

        return !streq(state, "inactive") && !streq(state, "failed");
}

int manager_job_is_active(Manager *manager, const char *path) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(path);

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Job",
                        "State",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_NO_REPLY) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_DISCONNECTED))
                        return true;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        return false;

                return r;
        }

        /* We don't actually care about the state really. The fact
         * that we could read the job state is enough for us */

        return true;
}

int manager_get_machine_by_pid(Manager *m, pid_t pid, Machine **machine) {
        _cleanup_free_ char *unit = NULL;
        Machine *mm;
        int r;

        assert(m);
        assert(pid >= 1);
        assert(machine);

        r = cg_pid_get_unit(pid, &unit);
        if (r < 0)
                mm = hashmap_get(m->machine_leaders, UINT_TO_PTR(pid));
        else
                mm = hashmap_get(m->machine_units, unit);

        if (!mm)
                return 0;

        *machine = mm;
        return 1;
}

int manager_add_machine(Manager *m, const char *name, Machine **_machine) {
        Machine *machine;

        assert(m);
        assert(name);

        machine = hashmap_get(m->machines, name);
        if (!machine) {
                machine = machine_new(m, name);
                if (!machine)
                        return -ENOMEM;
        }

        if (_machine)
                *_machine = machine;

        return 0;
}
