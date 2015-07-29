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
#include <unistd.h>

#include "log.h"
#include "strv.h"
#include "build.h"
#include "install.h"
#include "selinux-access.h"
#include "watchdog.h"
#include "clock-util.h"
#include "path-util.h"
#include "virt.h"
#include "architecture.h"
#include "env-util.h"
#include "dbus.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-unit.h"
#include "dbus-snapshot.h"
#include "dbus-execute.h"
#include "bus-common-errors.h"
#include "formats-util.h"

static int property_get_version(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", PACKAGE_VERSION);
}

static int property_get_features(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", SYSTEMD_FEATURES);
}

static int property_get_virtualization(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        const char *id = NULL;

        assert(bus);
        assert(reply);

        detect_virtualization(&id);

        return sd_bus_message_append(reply, "s", id);
}

static int property_get_architecture(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", architecture_to_string(uname_architecture()));
}

static int property_get_tainted(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        char buf[sizeof("split-usr:mtab-not-symlink:cgroups-missing:local-hwclock:")] = "", *e = buf;
        _cleanup_free_ char *p = NULL;
        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        if (m->taint_usr)
                e = stpcpy(e, "split-usr:");

        if (readlink_malloc("/etc/mtab", &p) < 0)
                e = stpcpy(e, "mtab-not-symlink:");

        if (access("/proc/cgroups", F_OK) < 0)
                e = stpcpy(e, "cgroups-missing:");

        if (clock_is_localtime() > 0)
                e = stpcpy(e, "local-hwclock:");

        /* remove the last ':' */
        if (e != buf)
                e[-1] = 0;

        return sd_bus_message_append(reply, "s", buf);
}

static int property_get_log_target(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", log_target_to_string(log_get_target()));
}

static int property_set_log_target(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        return log_set_target_from_string(t);
}

static int property_get_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *t = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = log_level_to_string_alloc(log_get_max_level(), &t);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "s", t);
}

static int property_set_log_level(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        const char *t;
        int r;

        assert(bus);
        assert(value);

        r = sd_bus_message_read(value, "s", &t);
        if (r < 0)
                return r;

        return log_set_max_level_from_string(t);
}

static int property_get_n_names(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "u", (uint32_t) hashmap_size(m->units));
}

static int property_get_n_failed_units(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "u", (uint32_t) set_size(m->failed_units));
}

static int property_get_n_jobs(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "u", (uint32_t) hashmap_size(m->jobs));
}

static int property_get_progress(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;
        double d;

        assert(bus);
        assert(reply);
        assert(m);

        if (dual_timestamp_is_set(&m->finish_timestamp))
                d = 1.0;
        else
                d = 1.0 - ((double) hashmap_size(m->jobs) / (double) m->n_installed_jobs);

        return sd_bus_message_append(reply, "d", d);
}

static int property_get_system_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = userdata;

        assert(bus);
        assert(reply);
        assert(m);

        return sd_bus_message_append(reply, "s", manager_state_to_string(manager_state(m)));
}

static int property_set_runtime_watchdog(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *value,
                void *userdata,
                sd_bus_error *error) {

        usec_t *t = userdata;
        int r;

        assert(bus);
        assert(value);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        r = sd_bus_message_read(value, "t", t);
        if (r < 0)
                return r;

        return watchdog_set_timeout(t);
}

static int method_get_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (isempty(name)) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                pid_t pid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pid(m, pid);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Client not member of any unit.");
        } else {
                u = manager_get_unit(m, name);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", name);
        }

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_get_unit_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        pid_t pid;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid PID " PID_FMT, pid);

        if (pid == 0) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;
        }

        u = manager_get_unit_by_pid(m, pid);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_UNIT_FOR_PID, "PID "PID_FMT" does not belong to any loaded unit.", pid);

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_load_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        if (isempty(name)) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                pid_t pid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pid(m, pid);
                if (!u)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Client not member of any unit.");
        } else {
                r = manager_load_unit(m, name, NULL, error, &u);
                if (r < 0)
                        return r;
        }

        r = mac_selinux_unit_access_check(u, message, "status", error);
        if (r < 0)
                return r;

        path = unit_dbus_path(u);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_start_unit_generic(sd_bus_message *message, Manager *m, JobType job_type, bool reload_if_possible, sd_bus_error *error) {
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        return bus_unit_method_start_generic(message, u, job_type, reload_if_possible, error);
}

static int method_start_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_START, false, error);
}

static int method_stop_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_STOP, false, error);
}

static int method_reload_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RELOAD, false, error);
}

static int method_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, false, error);
}

static int method_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, false, error);
}

static int method_reload_or_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_RESTART, true, error);
}

static int method_reload_or_try_restart_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_start_unit_generic(message, userdata, JOB_TRY_RESTART, true, error);
}

static int method_start_unit_replace(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *old_name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &old_name);
        if (r < 0)
                return r;

        u = manager_get_unit(m, old_name);
        if (!u || !u->job || u->job->type != JOB_START)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "No job queued for unit %s", old_name);

        return method_start_unit_generic(message, m, JOB_START, false, error);
}

static int method_kill_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        u = manager_get_unit(m, name);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);

        return bus_unit_method_kill(message, u, error);
}

static int method_reset_failed_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        u = manager_get_unit(m, name);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);

        return bus_unit_method_reset_failed(message, u, error);
}

static int method_set_unit_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        u = manager_get_unit(m, name);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);

        return bus_unit_method_set_properties(message, u, error);
}

static int transient_unit_from_message(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                Unit **unit,
                sd_bus_error *error) {

        Unit *u;
        int r;

        assert(m);
        assert(message);
        assert(name);

        r = manager_load_unit(m, name, NULL, error, &u);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_NOT_FOUND ||
            set_size(u->dependencies[UNIT_REFERENCED_BY]) > 0)
                return sd_bus_error_setf(error, BUS_ERROR_UNIT_EXISTS, "Unit %s already exists.", name);

        /* OK, the unit failed to load and is unreferenced, now let's
         * fill in the transient data instead */
        r = unit_make_transient(u);
        if (r < 0)
                return r;

        /* Set our properties */
        r = bus_unit_set_properties(u, message, UNIT_RUNTIME, false, error);
        if (r < 0)
                return r;

        *unit = u;

        return 0;
}

static int transient_aux_units_from_message(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *error) {

        Unit *u;
        char *name = NULL;
        int r;

        assert(m);
        assert(message);

        r = sd_bus_message_enter_container(message, 'a', "(sa(sv))");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_enter_container(message, 'r', "sa(sv)")) > 0) {
                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        return r;

                r = transient_unit_from_message(m, message, name, &u, error);
                if (r < 0 && r != -EEXIST)
                        return r;

                if (r != -EEXIST) {
                        r = unit_load(u);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        return 0;
}

static int method_start_transient_unit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name, *smode;
        Manager *m = userdata;
        JobMode mode;
        UnitType t;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ss", &name, &smode);
        if (r < 0)
                return r;

        t = unit_name_to_type(name);
        if (t < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit type.");

        if (!unit_vtable[t]->can_transient)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit type %s does not support transient units.", unit_type_to_string(t));

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s is invalid.", smode);

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = transient_unit_from_message(m, message, name, &u, error);
        if (r < 0)
                return r;

        r = transient_aux_units_from_message(m, message, error);
        if (r < 0)
                return r;

        /* And load this stub fully */
        r = unit_load(u);
        if (r < 0)
                return r;

        manager_dispatch_load_queue(m);

        /* Finally, start it */
        return bus_unit_queue_job(message, u, JOB_START, mode, false, error);
}

static int method_get_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        uint32_t id;
        Job *j;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        r = mac_selinux_unit_access_check(j->unit, message, "status", error);
        if (r < 0)
                return r;

        path = job_dbus_path(j);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_cancel_job(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        uint32_t id;
        Job *j;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "u", &id);
        if (r < 0)
                return r;

        j = manager_get_job(m, id);
        if (!j)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);

        return bus_job_method_cancel(message, j, error);
}

static int method_clear_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_clear_jobs(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_reset_failed(m);

        return sd_bus_reply_method_return(message, NULL);
}

static int list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error, char **states) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        const char *k;
        Iterator i;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssssouso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;
                Unit *following;

                if (k != u->id)
                        continue;

                following = unit_following(u);

                if (!strv_isempty(states) &&
                    !strv_contains(states, unit_load_state_to_string(u->load_state)) &&
                    !strv_contains(states, unit_active_state_to_string(unit_active_state(u))) &&
                    !strv_contains(states, unit_sub_state_to_string(u)))
                        continue;

                unit_path = unit_dbus_path(u);
                if (!unit_path)
                        return -ENOMEM;

                if (u->job) {
                        job_path = job_dbus_path(u->job);
                        if (!job_path)
                                return -ENOMEM;
                }

                r = sd_bus_message_append(
                                reply, "(ssssssouso)",
                                u->id,
                                unit_description(u),
                                unit_load_state_to_string(u->load_state),
                                unit_active_state_to_string(unit_active_state(u)),
                                unit_sub_state_to_string(u),
                                following ? following->id : "",
                                unit_path,
                                u->job ? u->job->id : 0,
                                u->job ? job_type_to_string(u->job->type) : "",
                                job_path ? job_path : "/");
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_list_units(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return list_units_filtered(message, userdata, error, NULL);
}

static int method_list_units_filtered(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **states = NULL;
        int r;

        r = sd_bus_message_read_strv(message, &states);
        if (r < 0)
                return r;

        return list_units_filtered(message, userdata, error, states);
}

static int method_list_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Iterator i;
        Job *j;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(j, m->jobs, i) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;

                job_path = job_dbus_path(j);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(j->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(
                                reply, "(usssoo)",
                                j->id,
                                j->unit->id,
                                job_type_to_string(j->type),
                                job_state_to_string(j->state),
                                job_path,
                                unit_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_subscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {

                /* Note that direct bus connection subscribe by
                 * default, we only track peers on the API bus here */

                if (!m->subscribed) {
                        r = sd_bus_track_new(sd_bus_message_get_bus(message), &m->subscribed, NULL, NULL);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_track_add_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, BUS_ERROR_ALREADY_SUBSCRIBED, "Client is already subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unsubscribe(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == m->api_bus) {
                r = sd_bus_track_remove_sender(m->subscribed, message);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, BUS_ERROR_NOT_SUBSCRIBED, "Client is not subscribed.");
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_dump(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *dump = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        Manager *m = userdata;
        size_t size;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        f = open_memstream(&dump, &size);
        if (!f)
                return -ENOMEM;

        manager_dump_units(m, f, NULL);
        manager_dump_jobs(m, f, NULL);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", dump);
}

static int method_create_snapshot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *path = NULL;
        Manager *m = userdata;
        const char *name;
        int cleanup;
        Snapshot *s = NULL;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sb", &name, &cleanup);
        if (r < 0)
                return r;

        if (isempty(name))
                name = NULL;

        r = bus_verify_manage_units_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = snapshot_create(m, name, cleanup, error, &s);
        if (r < 0)
                return r;

        path = unit_dbus_path(UNIT(s));
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int method_remove_snapshot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        u = manager_get_unit(m, name);
        if (!u)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s does not exist.", name);

        if (u->type != UNIT_SNAPSHOT)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not a snapshot", name);

        return bus_snapshot_method_remove(message, u, error);
}

static int method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Instead of sending the reply back right away, we just
         * remember that we need to and then send it after the reload
         * is finished. That way the caller knows when the reload
         * finished. */

        assert(!m->queued_message);
        r = sd_bus_message_new_method_return(message, &m->queued_message);
        if (r < 0)
                return r;

        m->exit_code = MANAGER_RELOAD;

        return 1;
}

static int method_reexecute(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_reload_daemon_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* We don't send a reply back here, the client should
         * just wait for us disconnecting. */

        m->exit_code = MANAGER_REEXECUTE;
        return 1;
}

static int method_exit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (m->running_as == MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Exit is only supported for user service managers.");

        m->exit_code = MANAGER_EXIT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (m->running_as != MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Reboot is only supported for system managers.");

        m->exit_code = MANAGER_REBOOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (m->running_as != MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Powering off is only supported for system managers.");

        m->exit_code = MANAGER_POWEROFF;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_halt(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "halt", error);
        if (r < 0)
                return r;

        if (m->running_as != MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Halt is only supported for system managers.");

        m->exit_code = MANAGER_HALT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kexec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (m->running_as != MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "KExec is only supported for system managers.");

        m->exit_code = MANAGER_KEXEC;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_switch_root(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        char *ri = NULL, *rt = NULL;
        const char *root, *init;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reboot", error);
        if (r < 0)
                return r;

        if (m->running_as != MANAGER_SYSTEM)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Root switching is only supported by system manager.");

        r = sd_bus_message_read(message, "ss", &root, &init);
        if (r < 0)
                return r;

        if (path_equal(root, "/") || !path_is_absolute(root))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid switch root path %s", root);

        /* Safety check */
        if (isempty(init)) {
                if (!path_is_os_tree(root))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified switch root path %s does not seem to be an OS tree. os-release file is missing.", root);
        } else {
                _cleanup_free_ char *p = NULL;

                if (!path_is_absolute(init))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid init path %s", init);

                p = strappend(root, init);
                if (!p)
                        return -ENOMEM;

                if (access(p, X_OK) < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified init binary %s does not exist.", p);
        }

        rt = strdup(root);
        if (!rt)
                return -ENOMEM;

        if (!isempty(init)) {
                ri = strdup(init);
                if (!ri) {
                        free(rt);
                        return -ENOMEM;
                }
        }

        free(m->switch_root);
        m->switch_root = rt;

        free(m->switch_root_init);
        m->switch_root_init = ri;

        m->exit_code = MANAGER_SWITCH_ROOT;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **plus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;
        if (!strv_env_is_valid(plus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_environment_add(m, NULL, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment variable names or assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_environment_add(m, minus, NULL);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unset_and_set_environment(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **minus = NULL, **plus = NULL;
        Manager *m = userdata;
        int r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "reload", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &minus);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &plus);
        if (r < 0)
                return r;

        if (!strv_env_name_or_assignment_is_valid(minus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment variable names or assignments");
        if (!strv_env_is_valid(plus))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment assignments");

        r = bus_verify_set_environment_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_environment_add(m, minus, plus);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_list_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        UnitFileList *item;
        Hashmap *h;
        Iterator i;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return -ENOMEM;

        r = unit_file_get_list(m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER, NULL, h);
        if (r < 0)
                goto fail;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                goto fail;

        HASHMAP_FOREACH(item, h, i) {

                r = sd_bus_message_append(reply, "(ss)", item->path, unit_file_state_to_string(item->state));
                if (r < 0)
                        goto fail;
        }

        unit_file_list_free(h);

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);

fail:
        unit_file_list_free(h);
        return r;
}

static int method_get_unit_file_state(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *name;
        UnitFileState state;
        UnitFileScope scope;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        state = unit_file_get_state(scope, NULL, name);
        if (state < 0)
                return state;

        return sd_bus_reply_method_return(message, "s", unit_file_state_to_string(state));
}

static int method_get_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *default_target = NULL;
        Manager *m = userdata;
        UnitFileScope scope;
        int r;

        assert(message);
        assert(m);

        /* Anyone can call this method */

        r = mac_selinux_access_check(message, "status", error);
        if (r < 0)
                return r;

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = unit_file_get_default(scope, NULL, &default_target);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, "s", default_target);
}

static int send_unit_files_changed(sd_bus *bus, void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnitFilesChanged");
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

static int reply_unit_file_changes_and_free(
                Manager *m,
                sd_bus_message *message,
                int carries_install_info,
                UnitFileChange *changes,
                unsigned n_changes) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        unsigned i;
        int r;

        if (n_changes > 0) {
                r = bus_foreach_bus(m, NULL, send_unit_files_changed, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to send UnitFilesChanged signal: %m");
        }

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                goto fail;

        if (carries_install_info >= 0) {
                r = sd_bus_message_append(reply, "b", carries_install_info);
                if (r < 0)
                        goto fail;
        }

        r = sd_bus_message_open_container(reply, 'a', "(sss)");
        if (r < 0)
                goto fail;

        for (i = 0; i < n_changes; i++) {
                r = sd_bus_message_append(
                                reply, "(sss)",
                                unit_file_change_type_to_string(changes[i].type),
                                changes[i].path,
                                changes[i].source);
                if (r < 0)
                        goto fail;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                goto fail;

        return sd_bus_send(NULL, reply, NULL);

fail:
        unit_file_changes_free(changes, n_changes);
        return r;
}

static int method_enable_unit_files_generic(
                sd_bus_message *message,
                Manager *m,
                const char *verb,
                int (*call)(UnitFileScope scope, bool runtime, const char *root_dir, char *files[], bool force, UnitFileChange **changes, unsigned *n_changes),
                bool carries_install_info,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        UnitFileScope scope;
        int runtime, force, r;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "bb", &runtime, &force);
        if (r < 0)
                return r;

        r = mac_selinux_unit_access_check_strv(l, message, m, verb, error);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = call(scope, runtime, NULL, l, force, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, carries_install_info ? r : -1, changes, n_changes);
}

static int method_enable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, "enable", unit_file_enable, true, error);
}

static int method_reenable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, "enable", unit_file_reenable, true, error);
}

static int method_link_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, "enable", unit_file_link, false, error);
}

static int unit_file_preset_without_mode(UnitFileScope scope, bool runtime, const char *root_dir, char **files, bool force, UnitFileChange **changes, unsigned *n_changes) {
        return unit_file_preset(scope, runtime, root_dir, files, UNIT_FILE_PRESET_FULL, force, changes, n_changes);
}

static int method_preset_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, "enable", unit_file_preset_without_mode, true, error);
}

static int method_mask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_enable_unit_files_generic(message, userdata, "disable", unit_file_mask, false, error);
}

static int method_preset_unit_files_with_mode(sd_bus_message *message, void *userdata, sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        Manager *m = userdata;
        UnitFilePresetMode mm;
        UnitFileScope scope;
        int runtime, force, r;
        const char *mode;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        if (isempty(mode))
                mm = UNIT_FILE_PRESET_FULL;
        else {
                mm = unit_file_preset_mode_from_string(mode);
                if (mm < 0)
                        return -EINVAL;
        }

        r = mac_selinux_unit_access_check_strv(l, message, m, "enable", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = unit_file_preset(scope, runtime, NULL, l, mm, force, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, r, changes, n_changes);
}

static int method_disable_unit_files_generic(
                sd_bus_message *message,
                Manager *m, const
                char *verb,
                int (*call)(UnitFileScope scope, bool runtime, const char *root_dir, char *files[], UnitFileChange **changes, unsigned *n_changes),
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        UnitFileScope scope;
        int r, runtime;

        assert(message);
        assert(m);

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = mac_selinux_unit_access_check_strv(l, message, m, verb, error);
        if (r < 0)
                return r;

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = call(scope, runtime, NULL, l, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes);
}

static int method_disable_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, "disable", unit_file_disable, error);
}

static int method_unmask_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return method_disable_unit_files_generic(message, userdata, "enable", unit_file_unmask, error);
}

static int method_set_default_target(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        Manager *m = userdata;
        UnitFileScope scope;
        const char *name;
        int force, r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sb", &name, &force);
        if (r < 0)
                return r;

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = unit_file_set_default(scope, NULL, name, force, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes);
}

static int method_preset_all_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        Manager *m = userdata;
        UnitFilePresetMode mm;
        UnitFileScope scope;
        const char *mode;
        int force, runtime, r;

        assert(message);
        assert(m);

        r = mac_selinux_access_check(message, "enable", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "sbb", &mode, &runtime, &force);
        if (r < 0)
                return r;

        if (isempty(mode))
                mm = UNIT_FILE_PRESET_FULL;
        else {
                mm = unit_file_preset_mode_from_string(mode);
                if (mm < 0)
                        return -EINVAL;
        }

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = unit_file_preset_all(scope, runtime, NULL, mm, force, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes);
}

static int method_add_dependency_unit_files(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        UnitFileScope scope;
        int runtime, force, r;
        char *target;
        char *type;
        UnitDependency dep;

        assert(message);
        assert(m);

        r = bus_verify_manage_unit_files_async(m, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = sd_bus_message_read_strv(message, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "ssbb", &target, &type, &runtime, &force);
        if (r < 0)
                return r;

        dep = unit_dependency_from_string(type);
        if (dep < 0)
                return -EINVAL;

        r = mac_selinux_unit_access_check_strv(l, message, m, "enable", error);
        if (r < 0)
                return r;

        scope = m->running_as == MANAGER_SYSTEM ? UNIT_FILE_SYSTEM : UNIT_FILE_USER;

        r = unit_file_add_dependency(scope, runtime, NULL, l, target, dep, force, &changes, &n_changes);
        if (r < 0)
                return r;

        return reply_unit_file_changes_and_free(m, message, -1, changes, n_changes);
}

const sd_bus_vtable bus_manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Version", "s", property_get_version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Features", "s", property_get_features, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Virtualization", "s", property_get_virtualization, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Architecture", "s", property_get_architecture, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Tainted", "s", property_get_tainted, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FirmwareTimestamp", offsetof(Manager, firmware_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("LoaderTimestamp", offsetof(Manager, loader_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("KernelTimestamp", offsetof(Manager, kernel_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("InitRDTimestamp", offsetof(Manager, initrd_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UserspaceTimestamp", offsetof(Manager, userspace_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("FinishTimestamp", offsetof(Manager, finish_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityStartTimestamp", offsetof(Manager, security_start_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("SecurityFinishTimestamp", offsetof(Manager, security_finish_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsStartTimestamp", offsetof(Manager, generators_start_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("GeneratorsFinishTimestamp", offsetof(Manager, generators_finish_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadStartTimestamp", offsetof(Manager, units_load_start_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("UnitsLoadFinishTimestamp", offsetof(Manager, units_load_finish_timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_WRITABLE_PROPERTY("LogLevel", "s", property_get_log_level, property_set_log_level, 0, 0),
        SD_BUS_WRITABLE_PROPERTY("LogTarget", "s", property_get_log_target, property_set_log_target, 0, 0),
        SD_BUS_PROPERTY("NNames", "u", property_get_n_names, 0, 0),
        SD_BUS_PROPERTY("NFailedUnits", "u", property_get_n_failed_units, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NJobs", "u", property_get_n_jobs, 0, 0),
        SD_BUS_PROPERTY("NInstalledJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_installed_jobs), 0),
        SD_BUS_PROPERTY("NFailedJobs", "u", bus_property_get_unsigned, offsetof(Manager, n_failed_jobs), 0),
        SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),
        SD_BUS_PROPERTY("Environment", "as", NULL, offsetof(Manager, environment), 0),
        SD_BUS_PROPERTY("ConfirmSpawn", "b", bus_property_get_bool, offsetof(Manager, confirm_spawn), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ShowStatus", "b", bus_property_get_bool, offsetof(Manager, show_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UnitPath", "as", NULL, offsetof(Manager, lookup_paths.unit_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardOutput", "s", bus_property_get_exec_output, offsetof(Manager, default_std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultStandardError", "s", bus_property_get_exec_output, offsetof(Manager, default_std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_WRITABLE_PROPERTY("RuntimeWatchdogUSec", "t", bus_property_get_usec, property_set_runtime_watchdog, offsetof(Manager, runtime_watchdog), 0),
        SD_BUS_WRITABLE_PROPERTY("ShutdownWatchdogUSec", "t", bus_property_get_usec, bus_property_set_usec, offsetof(Manager, shutdown_watchdog), 0),
        SD_BUS_PROPERTY("ControlGroup", "s", NULL, offsetof(Manager, cgroup_root), 0),
        SD_BUS_PROPERTY("SystemState", "s", property_get_system_state, 0, 0),

        SD_BUS_METHOD("GetUnit", "s", "o", method_get_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitByPID", "u", "o", method_get_unit_by_pid, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LoadUnit", "s", "o", method_load_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartUnit", "ss", "o", method_start_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartUnitReplace", "sss", "o", method_start_unit_replace, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StopUnit", "ss", "o", method_stop_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadUnit", "ss", "o", method_reload_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RestartUnit", "ss", "o", method_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TryRestartUnit", "ss", "o", method_try_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrRestartUnit", "ss", "o", method_reload_or_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrTryRestartUnit", "ss", "o", method_reload_or_try_restart_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("KillUnit", "ssi", NULL, method_kill_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailedUnit", "s", NULL, method_reset_failed_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetUnitProperties", "sba(sv)", NULL, method_set_unit_properties, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("StartTransientUnit", "ssa(sv)a(sa(sv))", "o", method_start_transient_unit, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetJob", "u", "o", method_get_job, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CancelJob", "u", NULL, method_cancel_job, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ClearJobs", NULL, NULL, method_clear_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailed", NULL, NULL, method_reset_failed, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnits", NULL, "a(ssssssouso)", method_list_units, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitsFiltered", "as", "a(ssssssouso)", method_list_units_filtered, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListJobs", NULL, "a(usssoo)", method_list_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Subscribe", NULL, NULL, method_subscribe, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unsubscribe", NULL, NULL, method_unsubscribe, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Dump", NULL, "s", method_dump, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CreateSnapshot", "sb", "o", method_create_snapshot, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RemoveSnapshot", "s", NULL, method_remove_snapshot, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reload", NULL, NULL, method_reload, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reexecute", NULL, NULL, method_reexecute, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", NULL, NULL, method_exit, 0),
        SD_BUS_METHOD("Reboot", NULL, NULL, method_reboot, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("PowerOff", NULL, NULL, method_poweroff, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("Halt", NULL, NULL, method_halt, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("KExec", NULL, NULL, method_kexec, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("SwitchRoot", "ss", NULL, method_switch_root, SD_BUS_VTABLE_CAPABILITY(CAP_SYS_BOOT)),
        SD_BUS_METHOD("SetEnvironment", "as", NULL, method_set_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnsetEnvironment", "as", NULL, method_unset_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnsetAndSetEnvironment", "asas", NULL, method_unset_and_set_environment, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListUnitFiles", NULL, "a(ss)", method_list_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetUnitFileState", "s", "s", method_get_unit_file_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("EnableUnitFiles", "asbb", "ba(sss)", method_enable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("DisableUnitFiles", "asb", "a(sss)", method_disable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReenableUnitFiles", "asbb", "ba(sss)", method_reenable_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LinkUnitFiles", "asbb", "a(sss)", method_link_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetUnitFiles", "asbb", "ba(sss)", method_preset_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetUnitFilesWithMode", "assbb", "ba(sss)", method_preset_unit_files_with_mode, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("MaskUnitFiles", "asbb", "a(sss)", method_mask_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnmaskUnitFiles", "asb", "a(sss)", method_unmask_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDefaultTarget", "sb", "a(sss)", method_set_default_target, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetDefaultTarget", NULL, "s", method_get_default_target, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PresetAllUnitFiles", "sbb", "a(sss)", method_preset_all_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("AddDependencyUnitFiles", "asssbb", "a(sss)", method_add_dependency_unit_files, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL("UnitNew", "so", 0),
        SD_BUS_SIGNAL("UnitRemoved", "so", 0),
        SD_BUS_SIGNAL("JobNew", "uos", 0),
        SD_BUS_SIGNAL("JobRemoved", "uoss", 0),
        SD_BUS_SIGNAL("StartupFinished", "tttttt", 0),
        SD_BUS_SIGNAL("UnitFilesChanged", NULL, 0),
        SD_BUS_SIGNAL("Reloading", "b", 0),

        SD_BUS_VTABLE_END
};

static int send_finished(sd_bus *bus, void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *message = NULL;
        usec_t *times = userdata;
        int r;

        assert(bus);
        assert(times);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartupFinished");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "tttttt", times[0], times[1], times[2], times[3], times[4], times[5]);
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void bus_manager_send_finished(
                Manager *m,
                usec_t firmware_usec,
                usec_t loader_usec,
                usec_t kernel_usec,
                usec_t initrd_usec,
                usec_t userspace_usec,
                usec_t total_usec) {

        int r;

        assert(m);

        r = bus_foreach_bus(
                        m,
                        NULL,
                        send_finished,
                        (usec_t[6]) {
                                firmware_usec,
                                loader_usec,
                                kernel_usec,
                                initrd_usec,
                                userspace_usec,
                                total_usec
                        });
        if (r < 0)
                log_debug_errno(r, "Failed to send finished signal: %m");
}

static int send_reloading(sd_bus *bus, void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *message = NULL;
        int r;

        assert(bus);

        r = sd_bus_message_new_signal(bus, &message, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Reloading");
        if (r < 0)
                return r;

        r = sd_bus_message_append(message, "b", PTR_TO_INT(userdata));
        if (r < 0)
                return r;

        return sd_bus_send(bus, message, NULL);
}

void bus_manager_send_reloading(Manager *m, bool active) {
        int r;

        assert(m);

        r = bus_foreach_bus(m, NULL, send_reloading, INT_TO_PTR(active));
        if (r < 0)
                log_debug_errno(r, "Failed to send reloading signal: %m");
}

static int send_changed_signal(sd_bus *bus, void *userdata) {
        assert(bus);

        return sd_bus_emit_properties_changed_strv(bus,
                                                   "/org/freedesktop/systemd1",
                                                   "org.freedesktop.systemd1.Manager",
                                                   NULL);
}

void bus_manager_send_change_signal(Manager *m) {
        int r;

        assert(m);

        r = bus_foreach_bus(m, NULL, send_changed_signal, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send manager change signal: %m");
}
