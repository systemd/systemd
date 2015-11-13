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

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "cgroup-util.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "locale-util.h"
#include "log.h"
#include "selinux-access.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_load_state, unit_load_state, UnitLoadState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_job_mode, job_mode, JobMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_failure_action, failure_action, FailureAction);

static int property_get_names(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;
        Iterator i;
        const char *t;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(t, u->names, i) {
                r = sd_bus_message_append(reply, "s", t);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_following(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata, *f;

        assert(bus);
        assert(reply);
        assert(u);

        f = unit_following(u);
        return sd_bus_message_append(reply, "s", f ? f->id : "");
}

static int property_get_dependencies(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Set *s = *(Set**) userdata;
        Iterator j;
        Unit *u;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(u, s, j) {
                r = sd_bus_message_append(reply, "s", u->id);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_obsolete_dependencies(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        assert(bus);
        assert(reply);

        /* For dependency types we don't support anymore always return an empty array */
        return sd_bus_message_append(reply, "as", 0);
}

static int property_get_description(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", unit_description(u));
}

static int property_get_active_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", unit_active_state_to_string(unit_active_state(u)));
}

static int property_get_sub_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", unit_sub_state_to_string(u));
}

static int property_get_unit_file_preset(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = unit_get_unit_file_preset(u);

        return sd_bus_message_append(reply, "s",
                                     r < 0 ? "":
                                     r > 0 ? "enabled" : "disabled");
}

static int property_get_unit_file_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", unit_file_state_to_string(unit_get_unit_file_state(u)));
}

static int property_get_can_start(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "b", unit_can_start(u) && !u->refuse_manual_start);
}

static int property_get_can_stop(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        /* On the lower levels we assume that every unit we can start
         * we can also stop */

        return sd_bus_message_append(reply, "b", unit_can_start(u) && !u->refuse_manual_stop);
}

static int property_get_can_reload(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "b", unit_can_reload(u));
}

static int property_get_can_isolate(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "b", unit_can_isolate(u) && !u->refuse_manual_start);
}

static int property_get_job(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        if (!u->job)
                return sd_bus_message_append(reply, "(uo)", 0, "/");

        p = job_dbus_path(u->job);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(uo)", u->job->id, p);
}

static int property_get_need_daemon_reload(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "b", unit_need_daemon_reload(u));
}

static int property_get_conditions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        const char *(*to_string)(ConditionType type) = NULL;
        Condition **list = userdata, *c;
        int r;

        assert(bus);
        assert(reply);
        assert(list);

        to_string = streq(property, "Asserts") ? assert_type_to_string : condition_type_to_string;

        r = sd_bus_message_open_container(reply, 'a', "(sbbsi)");
        if (r < 0)
                return r;

        LIST_FOREACH(conditions, c, *list) {
                int tristate;

                tristate =
                        c->result == CONDITION_UNTESTED ? 0 :
                        c->result == CONDITION_SUCCEEDED ? 1 : -1;

                r = sd_bus_message_append(reply, "(sbbsi)",
                                          to_string(c->type),
                                          c->trigger, c->negate,
                                          c->parameter, tristate);
                if (r < 0)
                        return r;

        }

        return sd_bus_message_close_container(reply);
}

static int property_get_load_error(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_bus_error_free_ sd_bus_error e = SD_BUS_ERROR_NULL;
        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        if (u->load_error != 0)
                sd_bus_error_set_errno(&e, u->load_error);

        return sd_bus_message_append(reply, "(ss)", e.name, e.message);
}

static int bus_verify_manage_units_async_full(
                Unit *u,
                const char *verb,
                int capability,
                const char *polkit_message,
                sd_bus_message *call,
                sd_bus_error *error) {

        const char *details[9] = {
                "unit", u->id,
                "verb", verb,
        };

        if (polkit_message) {
                details[4] = "polkit.message";
                details[5] = polkit_message;
                details[6] = "polkit.gettext_domain";
                details[7] = GETTEXT_PACKAGE;
        }

        return bus_verify_polkit_async(call, capability, "org.freedesktop.systemd1.manage-units", details, false, UID_INVALID, &u->manager->polkit_registry, error);
}

int bus_unit_method_start_generic(
                sd_bus_message *message,
                Unit *u,
                JobType job_type,
                bool reload_if_possible,
                sd_bus_error *error) {

        const char *smode;
        JobMode mode;
        _cleanup_free_ char *verb = NULL;
        static const char *const polkit_message_for_job[_JOB_TYPE_MAX] = {
                [JOB_START]       = N_("Authentication is required to start '$(unit)'."),
                [JOB_STOP]        = N_("Authentication is required to stop '$(unit)'."),
                [JOB_RELOAD]      = N_("Authentication is required to reload '$(unit)'."),
                [JOB_RESTART]     = N_("Authentication is required to restart '$(unit)'."),
                [JOB_TRY_RESTART] = N_("Authentication is required to restart '$(unit)'."),
        };
        int r;

        assert(message);
        assert(u);
        assert(job_type >= 0 && job_type < _JOB_TYPE_MAX);

        r = mac_selinux_unit_access_check(u, message, job_type == JOB_STOP ? "stop" : "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s invalid", smode);

        if (reload_if_possible)
                verb = strjoin("reload-or-", job_type_to_string(job_type), NULL);
        else
                verb = strdup(job_type_to_string(job_type));
        if (!verb)
                return -ENOMEM;

        r = bus_verify_manage_units_async_full(
                        u,
                        verb,
                        CAP_SYS_ADMIN,
                        job_type < _JOB_TYPE_MAX ? polkit_message_for_job[job_type] : NULL,
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        return bus_unit_queue_job(message, u, job_type, mode, reload_if_possible, error);
}

static int method_start(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_START, false, error);
}

static int method_stop(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_STOP, false, error);
}

static int method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RELOAD, false, error);
}

static int method_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, false, error);
}

static int method_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, false, error);
}

static int method_reload_or_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, true, error);
}

static int method_reload_or_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, true, error);
}

int bus_unit_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = userdata;
        const char *swho;
        int32_t signo;
        KillWho who;
        int r;

        assert(message);
        assert(u);

        r = mac_selinux_unit_access_check(u, message, "stop", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "si", &swho, &signo);
        if (r < 0)
                return r;

        if (isempty(swho))
                who = KILL_ALL;
        else {
                who = kill_who_from_string(swho);
                if (who < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid who argument %s", swho);
        }

        if (signo <= 0 || signo >= _NSIG)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Signal number out of range.");

        r = bus_verify_manage_units_async_full(
                        u,
                        "kill",
                        CAP_KILL,
                        N_("Authentication is required to kill '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_kill(u, who, signo, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = userdata;
        int r;

        assert(message);
        assert(u);

        r = mac_selinux_unit_access_check(u, message, "reload", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "reset-failed",
                        CAP_SYS_ADMIN,
                        N_("Authentication is required to reset the \"failed\" state of '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        unit_reset_failed(u);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_set_properties(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Unit *u = userdata;
        int runtime, r;

        assert(message);
        assert(u);

        r = mac_selinux_unit_access_check(u, message, "start", error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "set-property",
                        CAP_SYS_ADMIN,
                        N_("Authentication is required to set properties on '$(unit)'."),
                        message,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = bus_unit_set_properties(u, message, runtime ? UNIT_RUNTIME : UNIT_PERSISTENT, true, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable bus_unit_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Unit, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Names", "as", property_get_names, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Following", "s", property_get_following, 0, 0),
        SD_BUS_PROPERTY("Requires", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_REQUIRES]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Requisite", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_REQUISITE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Wants", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_WANTS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BindsTo", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_BINDS_TO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PartOf", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_PART_OF]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequiredBy", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_REQUIRED_BY]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequisiteOf", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_REQUISITE_OF]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WantedBy", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_WANTED_BY]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BoundBy", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_BOUND_BY]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConsistsOf", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_CONSISTS_OF]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Conflicts", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_CONFLICTS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConflictedBy", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_CONFLICTED_BY]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Before", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_BEFORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("After", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_AFTER]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnFailure", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_ON_FAILURE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Triggers", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_TRIGGERS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggeredBy", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_TRIGGERED_BY]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PropagatesReloadTo", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_PROPAGATES_RELOAD_TO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReloadPropagatedFrom", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_RELOAD_PROPAGATED_FROM]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JoinsNamespaceOf", "as", property_get_dependencies, offsetof(Unit, dependencies[UNIT_JOINS_NAMESPACE_OF]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequiresOverridable", "as", property_get_obsolete_dependencies, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequisiteOverridable", "as", property_get_obsolete_dependencies, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequiredByOverridable", "as", property_get_obsolete_dependencies, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequisiteOfOverridable", "as", property_get_obsolete_dependencies, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequiresMountsFor", "as", NULL, offsetof(Unit, requires_mounts_for), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Documentation", "as", NULL, offsetof(Unit, documentation), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Description", "s", property_get_description, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LoadState", "s", property_get_load_state, offsetof(Unit, load_state), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ActiveState", "s", property_get_active_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("SubState", "s", property_get_sub_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("FragmentPath", "s", NULL, offsetof(Unit, fragment_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SourcePath", "s", NULL, offsetof(Unit, source_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DropInPaths", "as", NULL, offsetof(Unit, dropin_paths), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UnitFileState", "s", property_get_unit_file_state, 0, 0),
        SD_BUS_PROPERTY("UnitFilePreset", "s", property_get_unit_file_preset, 0, 0),
        BUS_PROPERTY_DUAL_TIMESTAMP("InactiveExitTimestamp", offsetof(Unit, inactive_exit_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ActiveEnterTimestamp", offsetof(Unit, active_enter_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ActiveExitTimestamp", offsetof(Unit, active_exit_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("InactiveEnterTimestamp", offsetof(Unit, inactive_enter_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanStart", "b", property_get_can_start, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanStop", "b", property_get_can_stop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanReload", "b", property_get_can_reload, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanIsolate", "b", property_get_can_isolate, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Job", "(uo)", property_get_job, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StopWhenUnneeded", "b", bus_property_get_bool, offsetof(Unit, stop_when_unneeded), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RefuseManualStart", "b", bus_property_get_bool, offsetof(Unit, refuse_manual_start), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RefuseManualStop", "b", bus_property_get_bool, offsetof(Unit, refuse_manual_stop), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("AllowIsolate", "b", bus_property_get_bool, offsetof(Unit, allow_isolate), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultDependencies", "b", bus_property_get_bool, offsetof(Unit, default_dependencies), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnFailureJobMode", "s", property_get_job_mode, offsetof(Unit, on_failure_job_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IgnoreOnIsolate", "b", bus_property_get_bool, offsetof(Unit, ignore_on_isolate), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NeedDaemonReload", "b", property_get_need_daemon_reload, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobTimeoutUSec", "t", bus_property_get_usec, offsetof(Unit, job_timeout), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobTimeoutAction", "s", property_get_failure_action, offsetof(Unit, job_timeout_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobTimeoutRebootArgument", "s", NULL, offsetof(Unit, job_timeout_reboot_arg), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConditionResult", "b", bus_property_get_bool, offsetof(Unit, condition_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AssertResult", "b", bus_property_get_bool, offsetof(Unit, assert_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ConditionTimestamp", offsetof(Unit, condition_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("AssertTimestamp", offsetof(Unit, assert_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Conditions", "a(sbbsi)", property_get_conditions, offsetof(Unit, conditions), 0),
        SD_BUS_PROPERTY("Asserts", "a(sbbsi)", property_get_conditions, offsetof(Unit, asserts), 0),
        SD_BUS_PROPERTY("LoadError", "(ss)", property_get_load_error, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Transient", "b", bus_property_get_bool, offsetof(Unit, transient), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NetClass", "u", NULL, offsetof(Unit, cgroup_netclass_id), 0),

        SD_BUS_METHOD("Start", "s", "o", method_start, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Stop", "s", "o", method_stop, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Reload", "s", "o", method_reload, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Restart", "s", "o", method_restart, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("TryRestart", "s", "o", method_try_restart, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrRestart", "s", "o", method_reload_or_restart, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReloadOrTryRestart", "s", "o", method_reload_or_try_restart, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Kill", "si", NULL, bus_unit_method_kill, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailed", NULL, NULL, bus_unit_method_reset_failed, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetProperties", "ba(sv)", NULL, bus_unit_method_set_properties, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

static int property_get_slice(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;

        assert(bus);
        assert(reply);
        assert(u);

        return sd_bus_message_append(reply, "s", unit_slice_name(u));
}

static int property_get_current_memory(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t sz = (uint64_t) -1;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = unit_get_memory_current(u, &sz);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get memory.usage_in_bytes attribute: %m");

        return sd_bus_message_append(reply, "t", sz);
}

static int property_get_current_tasks(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t cn = (uint64_t) -1;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = unit_get_tasks_current(u, &cn);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get pids.current attribute: %m");

        return sd_bus_message_append(reply, "t", cn);
}

static int property_get_cpu_usage(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        nsec_t ns = (nsec_t) -1;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        r = unit_get_cpu_usage(u, &ns);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get cpuacct.usage attribute: %m");

        return sd_bus_message_append(reply, "t", ns);
}

static int property_get_cgroup(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata;
        const char *t;

        assert(bus);
        assert(reply);
        assert(u);

        /* Three cases: a) u->cgroup_path is NULL, in which case the
         * unit has no control group, which we report as the empty
         * string. b) u->cgroup_path is the empty string, which
         * indicates the root cgroup, which we report as "/". c) all
         * other cases we report as-is. */

        if (u->cgroup_path)
                t = isempty(u->cgroup_path) ? "/" : u->cgroup_path;
        else
                t = "";

        return sd_bus_message_append(reply, "s", t);
}

const sd_bus_vtable bus_unit_cgroup_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Slice", "s", property_get_slice, 0, 0),
        SD_BUS_PROPERTY("ControlGroup", "s", property_get_cgroup, 0, 0),
        SD_BUS_PROPERTY("MemoryCurrent", "t", property_get_current_memory, 0, 0),
        SD_BUS_PROPERTY("CPUUsageNSec", "t", property_get_cpu_usage, 0, 0),
        SD_BUS_PROPERTY("TasksCurrent", "t", property_get_current_tasks, 0, 0),
        SD_BUS_VTABLE_END
};

static int send_new_signal(sd_bus *bus, void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(u);

        p = unit_dbus_path(u);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "UnitNew");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "so", u->id, p);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

static int send_changed_signal(sd_bus *bus, void *userdata) {
        _cleanup_free_ char *p = NULL;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(u);

        p = unit_dbus_path(u);
        if (!p)
                return -ENOMEM;

        /* Send a properties changed signal. First for the specific
         * type, then for the generic unit. The clients may rely on
         * this order to get atomic behavior if needed. */

        r = sd_bus_emit_properties_changed_strv(
                        bus, p,
                        unit_dbus_interface_from_type(u->type),
                        NULL);
        if (r < 0)
                return r;

        return sd_bus_emit_properties_changed_strv(
                        bus, p,
                        "org.freedesktop.systemd1.Unit",
                        NULL);
}

void bus_unit_send_change_signal(Unit *u) {
        int r;
        assert(u);

        if (u->in_dbus_queue) {
                LIST_REMOVE(dbus_queue, u->manager->dbus_unit_queue, u);
                u->in_dbus_queue = false;
        }

        if (!u->id)
                return;

        r = bus_foreach_bus(u->manager, NULL, u->sent_dbus_new_signal ? send_changed_signal : send_new_signal, u);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to send unit change signal for %s: %m", u->id);

        u->sent_dbus_new_signal = true;
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = userdata;
        int r;

        assert(bus);
        assert(u);

        p = unit_dbus_path(u);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "UnitRemoved");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "so", u->id, p);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

void bus_unit_send_removed_signal(Unit *u) {
        int r;
        assert(u);

        if (!u->sent_dbus_new_signal)
                bus_unit_send_change_signal(u);

        if (!u->id)
                return;

        r = bus_foreach_bus(u->manager, NULL, send_removed_signal, u);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to send unit remove signal for %s: %m", u->id);
}

int bus_unit_queue_job(
                sd_bus_message *message,
                Unit *u,
                JobType type,
                JobMode mode,
                bool reload_if_possible,
                sd_bus_error *error) {

        _cleanup_free_ char *path = NULL;
        Job *j;
        int r;

        assert(message);
        assert(u);
        assert(type >= 0 && type < _JOB_TYPE_MAX);
        assert(mode >= 0 && mode < _JOB_MODE_MAX);

        if (reload_if_possible && unit_can_reload(u)) {
                if (type == JOB_RESTART)
                        type = JOB_RELOAD_OR_START;
                else if (type == JOB_TRY_RESTART)
                        type = JOB_RELOAD;
        }

        r = mac_selinux_unit_access_check(
                        u, message,
                        (type == JOB_START || type == JOB_RESTART || type == JOB_TRY_RESTART) ? "start" :
                        type == JOB_STOP ? "stop" : "reload", error);
        if (r < 0)
                return r;

        if (type == JOB_STOP &&
            (u->load_state == UNIT_NOT_FOUND || u->load_state == UNIT_ERROR) &&
            unit_active_state(u) == UNIT_INACTIVE)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not loaded.", u->id);

        if ((type == JOB_START && u->refuse_manual_start) ||
            (type == JOB_STOP && u->refuse_manual_stop) ||
            ((type == JOB_RESTART || type == JOB_TRY_RESTART) && (u->refuse_manual_start || u->refuse_manual_stop)) ||
            (type == JOB_RELOAD_OR_START && job_type_collapse(type, u) == JOB_START && u->refuse_manual_start))
                return sd_bus_error_setf(error, BUS_ERROR_ONLY_BY_DEPENDENCY, "Operation refused, unit %s may be requested by dependency only.", u->id);

        r = manager_add_job(u->manager, type, u, mode, error, &j);
        if (r < 0)
                return r;

        if (sd_bus_message_get_bus(message) == u->manager->api_bus) {
                if (!j->clients) {
                        r = sd_bus_track_new(sd_bus_message_get_bus(message), &j->clients, NULL, NULL);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_track_add_sender(j->clients, message);
                if (r < 0)
                        return r;
        }

        path = job_dbus_path(j);
        if (!path)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", path);
}

static int bus_unit_set_transient_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(u);
        assert(name);
        assert(message);

        if (streq(name, "Description")) {
                const char *d;

                r = sd_bus_message_read(message, "s", &d);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        r = unit_set_description(u, d);
                        if (r < 0)
                                return r;

                        unit_write_drop_in_format(u, mode, name, "[Unit]\nDescription=%s\n", d);
                }

                return 1;

        } else if (streq(name, "DefaultDependencies")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        u->default_dependencies = b;
                        unit_write_drop_in_format(u, mode, name, "[Unit]\nDefaultDependencies=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "Slice")) {
                Unit *slice;
                const char *s;

                if (!UNIT_HAS_CGROUP_CONTEXT(u))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "The slice property is only available for units with control groups.");
                if (u->type == UNIT_SLICE)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Slice may not be set for slice units.");
                if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot set slice for init.scope");

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                if (!unit_name_is_valid(s, UNIT_NAME_PLAIN))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit name '%s'", s);

                r = manager_load_unit(u->manager, s, NULL, error, &slice);
                if (r < 0)
                        return r;

                if (slice->type != UNIT_SLICE)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unit name '%s' is not a slice", s);

                if (mode != UNIT_CHECK) {
                        r = unit_set_slice(u, slice);
                        if (r < 0)
                                return r;

                        unit_write_drop_in_private_format(u, mode, name, "Slice=%s\n", s);
                }

                return 1;

        } else if (STR_IN_SET(name,
                              "Requires", "RequiresOverridable",
                              "Requisite", "RequisiteOverridable",
                              "Wants",
                              "BindsTo",
                              "Conflicts",
                              "Before", "After",
                              "OnFailure",
                              "PropagatesReloadTo", "ReloadPropagatedFrom",
                              "PartOf")) {

                UnitDependency d;
                const char *other;

                if (streq(name, "RequiresOverridable"))
                        d = UNIT_REQUIRES; /* redirect for obsolete unit dependency type */
                else if (streq(name, "RequisiteOverridable"))
                        d = UNIT_REQUISITE; /* same here */
                else {
                        d = unit_dependency_from_string(name);
                        if (d < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit dependency: %s", name);
                }

                r = sd_bus_message_enter_container(message, 'a', "s");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "s", &other)) > 0) {
                        if (!unit_name_is_valid(other, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit name %s", other);

                        if (mode != UNIT_CHECK) {
                                _cleanup_free_ char *label = NULL;

                                r = unit_add_dependency_by_name(u, d, other, NULL, true);
                                if (r < 0)
                                        return r;

                                label = strjoin(name, "-", other, NULL);
                                if (!label)
                                        return -ENOMEM;

                                unit_write_drop_in_format(u, mode, label, "[Unit]\n%s=%s\n", name, other);
                        }

                }
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                return 1;
        }

        return 0;
}

int bus_unit_set_properties(
                Unit *u,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                bool commit,
                sd_bus_error *error) {

        bool for_real = false;
        unsigned n = 0;
        int r;

        assert(u);
        assert(message);

        /* We iterate through the array twice. First run we just check
         * if all passed data is valid, second run actually applies
         * it. This is to implement transaction-like behaviour without
         * actually providing full transactions. */

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                return r;

        for (;;) {
                const char *name;

                r = sd_bus_message_enter_container(message, 'r', "sv");
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (for_real || mode == UNIT_CHECK)
                                break;

                        /* Reached EOF. Let's try again, and this time for realz... */
                        r = sd_bus_message_rewind(message, false);
                        if (r < 0)
                                return r;

                        for_real = true;
                        continue;
                }

                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        return r;

                if (!UNIT_VTABLE(u)->bus_set_property)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_PROPERTY_READ_ONLY, "Objects of this type do not support setting properties.");

                r = sd_bus_message_enter_container(message, 'v', NULL);
                if (r < 0)
                        return r;

                r = UNIT_VTABLE(u)->bus_set_property(u, name, message, for_real ? mode : UNIT_CHECK, error);
                if (r == 0 && u->transient && u->load_state == UNIT_STUB)
                        r = bus_unit_set_transient_property(u, name, message, for_real ? mode : UNIT_CHECK, error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_PROPERTY_READ_ONLY, "Cannot set property %s, or unknown property.", name);

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                n += for_real;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        if (commit && n > 0 && UNIT_VTABLE(u)->bus_commit_properties)
                UNIT_VTABLE(u)->bus_commit_properties(u);

        return n;
}
