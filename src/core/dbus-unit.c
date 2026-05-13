/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "condition.h"
#include "dbus.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-unit.h"
#include "dbus-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "install.h"
#include "locale-util.h"
#include "log.h"
#include "manager.h"
#include "namespace-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "selinux-access.h"
#include "set.h"
#include "signal-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "transaction.h"                /* IWYU pragma: keep */
#include "unit-name.h"
#include "user-util.h"
#include "web-util.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_collect_mode, collect_mode, CollectMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_load_state, unit_load_state, UnitLoadState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_job_mode, job_mode, JobMode);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_freezer_state, freezer_state, FreezerState);
static BUS_DEFINE_PROPERTY_GET(property_get_description, "s", Unit, unit_description);
static BUS_DEFINE_PROPERTY_GET2(property_get_active_state, "s", Unit, unit_active_state, unit_active_state_to_string);
static BUS_DEFINE_PROPERTY_GET(property_get_sub_state, "s", Unit, unit_sub_state_to_string);
static BUS_DEFINE_PROPERTY_GET2(property_get_unit_file_state, "s", Unit, unit_get_unit_file_state, unit_file_state_to_string);
static BUS_DEFINE_PROPERTY_GET(property_get_can_reload, "b", Unit, unit_can_reload);
static BUS_DEFINE_PROPERTY_GET(property_get_can_start, "b", Unit, unit_can_start_refuse_manual);
static BUS_DEFINE_PROPERTY_GET(property_get_can_stop, "b", Unit, unit_can_stop_refuse_manual);
static BUS_DEFINE_PROPERTY_GET(property_get_can_isolate, "b", Unit, unit_can_isolate_refuse_manual);
static BUS_DEFINE_PROPERTY_GET(property_get_can_freeze, "b", Unit, unit_can_freeze);
static BUS_DEFINE_PROPERTY_GET(property_get_need_daemon_reload, "b", Unit, unit_need_daemon_reload);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_empty_strv, "as", 0);

static int property_get_can_clean(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = userdata;
        ExecCleanMask mask;
        int r;

        assert(bus);
        assert(reply);

        r = unit_can_clean(u, &mask);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        for (ExecDirectoryType t = 0; t < _EXEC_DIRECTORY_TYPE_MAX; t++) {
                if (!BIT_SET(mask, t))
                        continue;

                r = sd_bus_message_append(reply, "s", exec_resource_type_to_string(t));
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(mask, EXEC_CLEAN_FDSTORE)) {
                r = sd_bus_message_append(reply, "s", "fdstore");
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_can_live_mount(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", unit_can_live_mount(u, /* reterr_error= */ NULL) >= 0);
}

static int property_get_names(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        const char *t;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", u->id);
        if (r < 0)
                return r;

        SET_FOREACH(t, u->aliases) {
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
                sd_bus_error *reterr_error) {

        Unit *u = userdata, *f;

        assert(bus);
        assert(reply);
        assert(u);

        f = unit_following(u);
        return sd_bus_message_append(reply, "s", f ? f->id : NULL);
}

static int property_get_dependencies(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = userdata, *other;
        UnitDependency d;
        Hashmap *deps;
        void *v;
        int r;

        assert(bus);
        assert(reply);
        assert(u);

        d = unit_dependency_from_string(property);
        assert_se(d >= 0);

        deps = unit_get_dependencies(u, d);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(v, other, deps) {
                r = sd_bus_message_append(reply, "s", other->id);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_mounts_for(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Hashmap **h = ASSERT_PTR(userdata);
        const char *p;
        void *v;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(v, p, *h) {
                r = sd_bus_message_append(reply, "s", p);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_unit_file_preset(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = unit_get_unit_file_preset(u);

        return sd_bus_message_append(reply, "s", preset_action_past_tense_to_string(r));
}

static int property_get_job(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        _cleanup_free_ char *p = NULL;
        Job **j = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        if (!*j)
                return sd_bus_message_append(reply, "(uo)", 0, "/");

        p = job_dbus_path(*j);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(uo)", (*j)->id, p);
}

static int property_get_conditions(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        const char *(*to_string)(ConditionType type) = NULL;
        Condition **list = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

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
                sd_bus_error *reterr_error) {

        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = bus_unit_validate_load_state(u, &e);
        if (r < 0)
                return sd_bus_message_append(reply, "(ss)", e.name, e.message);

        return sd_bus_message_append(reply, "(ss)", NULL, NULL);
}

static int property_get_markers(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        unsigned *markers = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        BIT_FOREACH(m, *markers) {
                r = sd_bus_message_append(reply, "s", unit_marker_to_string(m));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static const char *const polkit_message_for_job[_JOB_TYPE_MAX] = {
        [JOB_START]       = N_("Authentication is required to start '$(unit)'."),
        [JOB_STOP]        = N_("Authentication is required to stop '$(unit)'."),
        [JOB_RELOAD]      = N_("Authentication is required to reload '$(unit)'."),
        [JOB_RESTART]     = N_("Authentication is required to restart '$(unit)'."),
        [JOB_TRY_RESTART] = N_("Authentication is required to restart '$(unit)'."),
};

int bus_unit_method_start_generic(
                sd_bus_message *message,
                Unit *u,
                JobType job_type,
                bool reload_if_possible,
                sd_bus_error *reterr_error) {

        BusUnitQueueFlags job_flags = reload_if_possible ? BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE : 0;
        const char *smode, *verb;
        JobMode mode;
        int r;

        assert(message);
        assert(u);
        assert(job_type >= 0 && job_type < _JOB_TYPE_MAX);

        r = mac_selinux_unit_access_check(
                        u, message,
                        job_type_to_access_method(job_type),
                        reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &smode);
        if (r < 0)
                return r;

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s invalid", smode);

        if (reload_if_possible)
                verb = strjoina("reload-or-", job_type_to_string(job_type));
        else
                verb = job_type_to_string(job_type);

        if (sd_bus_message_is_method_call(message, NULL, "StartUnitWithFlags")) {
                uint64_t input_flags = 0;

                r = sd_bus_message_read(message, "t", &input_flags);
                if (r < 0)
                        return r;
                /* Let clients know that this version doesn't support any flags at the moment. */
                if (input_flags != 0)
                        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                                          "Invalid 'flags' parameter '%" PRIu64 "'",
                                                          input_flags);
        }

        r = bus_verify_manage_units_async_full(
                        u,
                        verb,
                        polkit_message_for_job[job_type],
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        return bus_unit_queue_job(message, u, job_type, mode, job_flags, reterr_error);
}

static int bus_unit_method_start(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_START, false, reterr_error);
}

static int bus_unit_method_stop(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_STOP, false, reterr_error);
}

static int bus_unit_method_reload(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RELOAD, false, reterr_error);
}

static int bus_unit_method_restart(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, false, reterr_error);
}

static int bus_unit_method_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, false, reterr_error);
}

static int bus_unit_method_reload_or_restart(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_RESTART, true, reterr_error);
}

static int bus_unit_method_reload_or_try_restart(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_start_generic(message, userdata, JOB_TRY_RESTART, true, reterr_error);
}

int bus_unit_method_enqueue_job(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        BusUnitQueueFlags flags = BUS_UNIT_QUEUE_VERBOSE_REPLY;
        const char *jtype, *smode;
        Unit *u = ASSERT_PTR(userdata);
        JobType type;
        JobMode mode;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "ss", &jtype, &smode);
        if (r < 0)
                return r;

        /* Parse the two magic reload types "reload-or-…" manually */
        if (streq(jtype, "reload-or-restart")) {
                type = JOB_RESTART;
                flags |= BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE;
        } else if (streq(jtype, "reload-or-try-restart")) {
                type = JOB_TRY_RESTART;
                flags |= BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE;
        } else {
                /* And the rest generically */
                type = job_type_from_string(jtype);
                if (type < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Job type %s invalid", jtype);
        }

        mode = job_mode_from_string(smode);
        if (mode < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Job mode %s invalid", smode);

        r = mac_selinux_unit_access_check(
                        u, message,
                        job_type_to_access_method(type),
                        reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        jtype,
                        polkit_message_for_job[type],
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        return bus_unit_queue_job(message, u, type, mode, flags, reterr_error);
}

int bus_unit_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int32_t value = 0;
        const char *swhom;
        int32_t signo;
        KillWhom whom;
        int r, code;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "stop", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "si", &swhom, &signo);
        if (r < 0)
                return r;

        if (startswith(sd_bus_message_get_member(message), "QueueSignal")) {
                r = sd_bus_message_read(message, "i", &value);
                if (r < 0)
                        return r;

                code = SI_QUEUE;
        } else
                code = SI_USER;

        if (isempty(swhom))
                whom = KILL_ALL;
        else {
                whom = kill_whom_from_string(swhom);
                if (whom < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid whom argument: %s", swhom);
        }

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Signal number out of range.");

        if (code == SI_QUEUE && !((signo >= SIGRTMIN) && (signo <= SIGRTMAX)))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Value parameter only accepted for realtime signals (SIGRTMIN…SIGRTMAX), refusing for signal SIG%s.", signal_to_string(signo));

        r = bus_verify_manage_units_async_full(
                        u,
                        "kill",
                        N_("Authentication is required to send a UNIX signal to the processes of '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_kill(u, whom, /* subgroup= */ NULL, signo, code, value, reterr_error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_kill_subgroup(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "stop", reterr_error);
        if (r < 0)
                return r;

        const char *swhom, *subgroup;
        int32_t signo;
        r = sd_bus_message_read(message, "ssi", &swhom, &subgroup, &signo);
        if (r < 0)
                return r;

        KillWhom whom;
        if (isempty(swhom))
                whom = KILL_CGROUP;
        else {
                whom = kill_whom_from_string(swhom);
                if (whom < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid whom argument: %s", swhom);
        }

        if (isempty(subgroup))
                subgroup = NULL;
        else if (!path_is_normalized(subgroup))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Specified cgroup sub-path is not valid.");
        else if (!IN_SET(whom, KILL_CGROUP, KILL_CGROUP_FAIL))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Subgroup can only be specified in combination with 'cgroup' or 'cgroup-fail'.");

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Signal number out of range.");

        r = bus_verify_manage_units_async_full(
                        u,
                        "kill-subgroup",
                        N_("Authentication is required to send a UNIX signal to the processes of subgroup of '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_kill(u, whom, subgroup, signo, SI_USER, /* value= */ 0, reterr_error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_reset_failed(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "reload", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "reset-failed",
                        N_("Authentication is required to reset the \"failed\" state of '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        unit_reset_failed(u);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_set_properties(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int runtime, r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "start", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &runtime);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "set-property",
                        N_("Authentication is required to set properties on '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = bus_unit_set_properties(u, message, runtime ? UNIT_RUNTIME : UNIT_PERSISTENT, true, reterr_error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_ref(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "start", reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "ref",
                        /* polkit_message= */ NULL,
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = bus_unit_track_add_sender(u, message);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_unref(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_unit_track_remove_sender(u, message);
        if (r == -EUNATCH)
                return sd_bus_error_set(reterr_error, BUS_ERROR_NOT_REFERENCED, "Unit has not been referenced yet.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_clean(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        ExecCleanMask mask = 0;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "stop", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "s");
        if (r < 0)
                return r;

        for (;;) {
                ExecCleanMask m;
                const char *i;

                r = sd_bus_message_read(message, "s", &i);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                m = exec_clean_mask_from_string(i);
                if (m < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid resource type: %s", i);

                mask |= m;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        "clean",
                        N_("Authentication is required to delete files and directories associated with '$(unit)'."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_clean(u, mask);
        if (r == -EOPNOTSUPP)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED, "Unit '%s' does not support cleaning.", u->id);
        if (r == -EUNATCH)
                return sd_bus_error_set(reterr_error, BUS_ERROR_NOTHING_TO_CLEAN, "No matching resources found.");
        if (r == -EBUSY)
                return sd_bus_error_set(reterr_error, BUS_ERROR_UNIT_BUSY, "Unit is not inactive or has pending job.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int bus_unit_method_freezer_generic(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error, FreezerAction action) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);
        assert(IN_SET(action, FREEZER_FREEZE, FREEZER_THAW));

        const char *perm = action == FREEZER_FREEZE ? "stop" : "start";

        r = mac_selinux_unit_access_check(u, message, perm, reterr_error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async_full(
                        u,
                        perm,
                        N_("Authentication is required to freeze or thaw the processes of '$(unit)' unit."),
                        message,
                        reterr_error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = unit_freezer_action(u, action);
        if (r == -EOPNOTSUPP)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_NOT_SUPPORTED, "Unit does not support freeze/thaw");
        if (r == -EBUSY)
                return sd_bus_error_set(reterr_error, BUS_ERROR_UNIT_BUSY, "Unit has a pending job");
        if (r == -EHOSTDOWN)
                return sd_bus_error_set(reterr_error, BUS_ERROR_UNIT_INACTIVE, "Unit is not active");
        if (r == -EALREADY)
                return sd_bus_error_set(reterr_error, BUS_ERROR_UNIT_BUSY, "Previously requested freezer operation for unit is still in progress");
        if (r == -EDEADLK)
                return sd_bus_error_set(reterr_error, BUS_ERROR_FROZEN_BY_PARENT, "Unit is frozen by a parent slice");
        if (r < 0)
                return r;

        bool reply_now = r == 0;

        if (u->pending_freezer_invocation) {
                bus_unit_send_pending_freezer_message(u, true);
                assert(!u->pending_freezer_invocation);
        }

        u->pending_freezer_invocation = sd_bus_message_ref(message);

        if (reply_now) {
                r = bus_unit_send_pending_freezer_message(u, false);
                if (r < 0)
                        return r;
        }

        return 1;
}

int bus_unit_method_thaw(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_freezer_generic(message, userdata, reterr_error, FREEZER_THAW);
}

int bus_unit_method_freeze(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        return bus_unit_method_freezer_generic(message, userdata, reterr_error, FREEZER_FREEZE);
}

static int property_get_refs(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = userdata;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        for (const char *i = sd_bus_track_first(u->bus_track); i; i = sd_bus_track_next(u->bus_track)) {
                int c;

                c = sd_bus_track_count_name(u->bus_track, i);
                if (c < 0)
                        return c;

                /* Add the item multiple times if the ref count for each is above 1 */
                for (int k = 0; k < c; k++) {
                        r = sd_bus_message_append(reply, "s", i);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable bus_unit_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Unit, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Names", "as", property_get_names, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Following", "s", property_get_following, 0, 0),
        SD_BUS_PROPERTY("Requires", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Requisite", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Wants", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BindsTo", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PartOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Upholds", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequiredBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequisiteOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WantedBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("BoundBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UpheldBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConsistsOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Conflicts", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConflictedBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Before", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("After", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnSuccess", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnSuccessOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnFailure", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnFailureOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Triggers", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TriggeredBy", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PropagatesReloadTo", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReloadPropagatedFrom", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PropagatesStopTo", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StopPropagatedFrom", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JoinsNamespaceOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SliceOf", "as", property_get_dependencies, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RequiresMountsFor", "as", property_get_mounts_for, offsetof(Unit, mounts_for[UNIT_MOUNT_REQUIRES]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WantsMountsFor", "as", property_get_mounts_for, offsetof(Unit, mounts_for[UNIT_MOUNT_WANTS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Documentation", "as", NULL, offsetof(Unit, documentation), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Description", "s", property_get_description, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("AccessSELinuxContext", "s", NULL, offsetof(Unit, access_selinux_context), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LoadState", "s", property_get_load_state, offsetof(Unit, load_state), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ActiveState", "s", property_get_active_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("FreezerState", "s", property_get_freezer_state, offsetof(Unit, freezer_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("SubState", "s", property_get_sub_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("FragmentPath", "s", NULL, offsetof(Unit, fragment_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SourcePath", "s", NULL, offsetof(Unit, source_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DropInPaths", "as", NULL, offsetof(Unit, dropin_paths), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UnitFileState", "s", property_get_unit_file_state, 0, 0),
        SD_BUS_PROPERTY("UnitFilePreset", "s", property_get_unit_file_preset, 0, 0),
        BUS_PROPERTY_DUAL_TIMESTAMP("StateChangeTimestamp", offsetof(Unit, state_change_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("InactiveExitTimestamp", offsetof(Unit, inactive_exit_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ActiveEnterTimestamp", offsetof(Unit, active_enter_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ActiveExitTimestamp", offsetof(Unit, active_exit_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("InactiveEnterTimestamp", offsetof(Unit, inactive_enter_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanStart", "b", property_get_can_start, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanStop", "b", property_get_can_stop, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanReload", "b", property_get_can_reload, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanIsolate", "b", property_get_can_isolate, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanClean", "as", property_get_can_clean, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanFreeze", "b", property_get_can_freeze, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanLiveMount", "b", property_get_can_live_mount, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Job", "(uo)", property_get_job, offsetof(Unit, job), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("StopWhenUnneeded", "b", bus_property_get_bool, offsetof(Unit, stop_when_unneeded), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RefuseManualStart", "b", bus_property_get_bool, offsetof(Unit, refuse_manual_start), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RefuseManualStop", "b", bus_property_get_bool, offsetof(Unit, refuse_manual_stop), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("AllowIsolate", "b", bus_property_get_bool, offsetof(Unit, allow_isolate), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("DefaultDependencies", "b", bus_property_get_bool, offsetof(Unit, default_dependencies), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SurviveFinalKillSignal", "b", bus_property_get_bool, offsetof(Unit, survive_final_kill_signal), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnSuccesJobMode", "s", property_get_job_mode, offsetof(Unit, on_success_job_mode), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN), /* deprecated */
        SD_BUS_PROPERTY("OnSuccessJobMode", "s", property_get_job_mode, offsetof(Unit, on_success_job_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OnFailureJobMode", "s", property_get_job_mode, offsetof(Unit, on_failure_job_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IgnoreOnIsolate", "b", bus_property_get_bool, offsetof(Unit, ignore_on_isolate), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NeedDaemonReload", "b", property_get_need_daemon_reload, 0, 0),
        SD_BUS_PROPERTY("Markers", "as", property_get_markers, offsetof(Unit, markers), 0),
        SD_BUS_PROPERTY("JobTimeoutUSec", "t", bus_property_get_usec, offsetof(Unit, job_timeout), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobRunningTimeoutUSec", "t", bus_property_get_usec, offsetof(Unit, job_running_timeout), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobTimeoutAction", "s", bus_property_get_emergency_action, offsetof(Unit, job_timeout_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobTimeoutRebootArgument", "s", NULL, offsetof(Unit, job_timeout_reboot_arg), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ConditionResult", "b", bus_property_get_bool, offsetof(Unit, condition_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AssertResult", "b", bus_property_get_bool, offsetof(Unit, assert_result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("ConditionTimestamp", offsetof(Unit, condition_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        BUS_PROPERTY_DUAL_TIMESTAMP("AssertTimestamp", offsetof(Unit, assert_timestamp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Conditions", "a(sbbsi)", property_get_conditions, offsetof(Unit, conditions), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Asserts", "a(sbbsi)", property_get_conditions, offsetof(Unit, asserts), SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("LoadError", "(ss)", property_get_load_error, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Transient", "b", bus_property_get_bool, offsetof(Unit, transient), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Perpetual", "b", bus_property_get_bool, offsetof(Unit, perpetual), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StartLimitIntervalUSec", "t", bus_property_get_usec, offsetof(Unit, start_ratelimit.interval), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StartLimitBurst", "u", bus_property_get_unsigned, offsetof(Unit, start_ratelimit.burst), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StartLimitAction", "s", bus_property_get_emergency_action, offsetof(Unit, start_limit_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FailureAction", "s", bus_property_get_emergency_action, offsetof(Unit, failure_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("FailureActionExitStatus", "i", bus_property_get_int, offsetof(Unit, failure_action_exit_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SuccessAction", "s", bus_property_get_emergency_action, offsetof(Unit, success_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SuccessActionExitStatus", "i", bus_property_get_int, offsetof(Unit, success_action_exit_status), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RebootArgument", "s", NULL, offsetof(Unit, reboot_arg), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("InvocationID", "ay", bus_property_get_id128, offsetof(Unit, invocation_id), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CollectMode", "s", property_get_collect_mode, offsetof(Unit, collect_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Refs", "as", property_get_refs, 0, 0),
        SD_BUS_PROPERTY("ActivationDetails", "a(ss)", bus_property_get_activation_details, offsetof(Unit, activation_details), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DebugInvocation", "b", bus_property_get_bool, offsetof(Unit, debug_invocation), 0),

        SD_BUS_METHOD_WITH_ARGS("Start",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_start,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Stop",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_stop,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Reload",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_reload,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Restart",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_restart,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TryRestart",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_try_restart,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReloadOrRestart",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_reload_or_restart,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReloadOrTryRestart",
                                SD_BUS_ARGS("s", mode),
                                SD_BUS_RESULT("o", job),
                                bus_unit_method_reload_or_try_restart,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("EnqueueJob",
                                SD_BUS_ARGS("s", job_type, "s", job_mode),
                                SD_BUS_RESULT("u", job_id, "o", job_path, "s", unit_id, "o", unit_path, "s", job_type, "a(uosos)", affected_jobs),
                                bus_unit_method_enqueue_job,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Kill",
                                SD_BUS_ARGS("s", whom, "i", signal),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_kill,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillSubgroup",
                                SD_BUS_ARGS("s", subgroup, "i", signal),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_kill_subgroup,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("QueueSignal",
                                SD_BUS_ARGS("s", whom, "i", signal, "i", value),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_kill,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetFailed",
                      NULL,
                      NULL,
                      bus_unit_method_reset_failed,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetProperties",
                                SD_BUS_ARGS("b", runtime, "a(sv)", properties),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_set_properties,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Ref",
                      NULL,
                      NULL,
                      bus_unit_method_ref,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unref",
                      NULL,
                      NULL,
                      bus_unit_method_unref,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Clean",
                                SD_BUS_ARGS("as", mask),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_clean,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Freeze",
                      NULL,
                      NULL,
                      bus_unit_method_freeze,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Thaw",
                      NULL,
                      NULL,
                      bus_unit_method_thaw,
                      SD_BUS_VTABLE_UNPRIVILEGED),

        /* For dependency types we don't support anymore always return an empty array */
        SD_BUS_PROPERTY("RequiresOverridable", "as", property_get_empty_strv, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequisiteOverridable", "as", property_get_empty_strv, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequiredByOverridable", "as", property_get_empty_strv, 0, SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("RequisiteOfOverridable", "as", property_get_empty_strv, 0, SD_BUS_VTABLE_HIDDEN),
        /* Obsolete alias names */
        SD_BUS_PROPERTY("StartLimitInterval", "t", bus_property_get_usec, offsetof(Unit, start_ratelimit.interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("StartLimitIntervalSec", "t", bus_property_get_usec, offsetof(Unit, start_ratelimit.interval), SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),

        SD_BUS_VTABLE_END
};

static int property_get_slice(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", unit_slice_name(u));
}

static int property_get_available_memory(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        uint64_t sz = UINT64_MAX;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = unit_get_memory_available(u, &sz);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get total available memory from cgroup: %m");

        return sd_bus_message_append(reply, "t", sz);
}

static int property_get_memory_accounting(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        CGroupMemoryAccountingMetric metric;
        uint64_t sz = UINT64_MAX;

        assert(bus);
        assert(reply);

        assert_se((metric = cgroup_memory_accounting_metric_from_string(property)) >= 0);
        (void) unit_get_memory_accounting(u, metric, &sz);
        return sd_bus_message_append(reply, "t", sz);
}

static int property_get_current_tasks(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        uint64_t cn = UINT64_MAX;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

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
                sd_bus_error *reterr_error) {

        nsec_t ns = NSEC_INFINITY;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = unit_get_cpu_usage(u, &ns);
        if (r < 0 && r != -ENODATA)
                log_unit_warning_errno(u, r, "Failed to get CPU usage: %m");

        return sd_bus_message_append(reply, "t", ns);
}

static int property_get_cpuset_cpus(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        _cleanup_(cpu_set_done) CPUSet cpus = {};
        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;

        assert(bus);
        assert(reply);

        (void) unit_get_cpuset(u, &cpus, "cpuset.cpus.effective");
        (void) cpu_set_to_dbus(&cpus, &array, &allocated);
        return sd_bus_message_append_array(reply, 'y', array, allocated);
}

static int property_get_cpuset_mems(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        _cleanup_(cpu_set_done) CPUSet mems = {};
        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;

        assert(bus);
        assert(reply);

        (void) unit_get_cpuset(u, &mems, "cpuset.mems.effective");
        (void) cpu_set_to_dbus(&mems, &array, &allocated);
        return sd_bus_message_append_array(reply, 'y', array, allocated);
}

static int property_get_cgroup(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);
        const char *t = NULL;

        assert(bus);
        assert(reply);

        /* Three cases: a) u->cgroup_path is NULL, in which case the
         * unit has no control group, which we report as the empty
         * string. b) u->cgroup_path is the empty string, which
         * indicates the root cgroup, which we report as "/". c) all
         * other cases we report as-is. */

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);

        if (crt && crt->cgroup_path)
                t = empty_to_root(crt->cgroup_path);

        return sd_bus_message_append(reply, "s", t);
}

static int property_get_cgroup_id(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        return sd_bus_message_append(reply, "t", crt ? crt->cgroup_id : UINT64_C(0));
}

static int property_get_oom_kills(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        return sd_bus_message_append(reply, "t", crt ? crt->oom_kill_last : UINT64_MAX);
}

static int property_get_managed_oom_kills(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Unit *u = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        return sd_bus_message_append(reply, "t", crt ? crt->managed_oom_kill_last : UINT64_MAX);
}

static int append_process(sd_bus_message *reply, const char *p, PidRef *pid, Set *pids) {
        _cleanup_free_ char *buf = NULL, *cmdline = NULL;
        int r;

        assert(reply);
        assert(pidref_is_set(pid));

        r = set_put(pids, PID_TO_PTR(pid->pid));
        if (IN_SET(r, 0, -EEXIST))
                return 0;
        if (r < 0)
                return r;

        if (!p) {
                r = cg_pidref_get_path(pid, &buf);
                if (r == -ESRCH)
                        return 0;
                if (r < 0)
                        return r;

                p = buf;
        }

        (void) pidref_get_cmdline(
                        pid,
                        SIZE_MAX,
                        PROCESS_CMDLINE_COMM_FALLBACK | PROCESS_CMDLINE_QUOTE,
                        &cmdline);

        return sd_bus_message_append(reply,
                                     "(sus)",
                                     p,
                                     (uint32_t) pid->pid,
                                     cmdline);
}

static int append_cgroup(sd_bus_message *reply, const char *p, Set *pids) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(reply);
        assert(p);

        r = cg_enumerate_processes(p, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                /* libvirt / qemu uses threaded mode and cgroup.procs cannot be read at the lower levels.
                 * From https://docs.kernel.org/admin-guide/cgroup-v2.html#threads, “cgroup.procs” in a
                 * threaded domain cgroup contains the PIDs of all processes in the subtree and is not
                 * readable in the subtree proper.
                 *
                 * We'll see ENODEV when trying to enumerate processes and the cgroup is removed at the same
                 * time. Handle this gracefully. */

                r = cg_read_pidref(f, &pidref, /* flags= */ 0);
                if (IN_SET(r, 0, -EOPNOTSUPP, -ENODEV))
                        break;
                if (r < 0)
                        return r;

                r = pidref_is_kernel_thread(&pidref);
                if (r == -ESRCH) /* gone by now */
                        continue;
                if (r < 0)
                        log_debug_errno(r, "Failed to determine if " PID_FMT " is a kernel thread, assuming not: %m", pidref.pid);
                if (r > 0)
                        continue;

                r = append_process(reply, p, &pidref, pids);
                if (r < 0)
                        return r;
        }

        r = cg_enumerate_subgroups(p, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *g = NULL, *j = NULL;

                r = cg_read_subgroup(d, &g);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                j = path_join(empty_to_root(p), g);
                if (!j)
                        return -ENOMEM;

                r = append_cgroup(reply, j, pids);
                if (r < 0)
                        return r;
        }

        return 0;
}

int bus_unit_method_get_processes(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_set_free_ Set *pids = NULL;
        Unit *u = userdata;
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(u, message, "status", reterr_error);
        if (r < 0)
                return r;

        pids = set_new(NULL);
        if (!pids)
                return -ENOMEM;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(sus)");
        if (r < 0)
                return r;

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (crt && crt->cgroup_path) {
                r = append_cgroup(reply, crt->cgroup_path, pids);
                if (r < 0)
                        return r;
        }

        /* The main and control pids might live outside of the cgroup, hence fetch them separately */
        PidRef *pid = unit_main_pid(u);
        if (pidref_is_set(pid)) {
                r = append_process(reply, NULL, pid, pids);
                if (r < 0)
                        return r;
        }

        pid = unit_control_pid(u);
        if (pidref_is_set(pid)) {
                r = append_process(reply, NULL, pid, pids);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int property_get_ip_counter(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        uint64_t value = UINT64_MAX;
        Unit *u = ASSERT_PTR(userdata);
        CGroupIPAccountingMetric metric;

        assert(bus);
        assert(reply);
        assert(property);

        assert_se((metric = cgroup_ip_accounting_metric_from_string(property)) >= 0);
        (void) unit_get_ip_accounting(u, metric, &value);
        return sd_bus_message_append(reply, "t", value);
}

static int property_get_io_counter(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        uint64_t value = UINT64_MAX;
        Unit *u = ASSERT_PTR(userdata);
        ssize_t metric;

        assert(bus);
        assert(reply);
        assert(property);

        assert_se((metric = cgroup_io_accounting_metric_from_string(property)) >= 0);
        (void) unit_get_io_accounting(u, metric, &value);
        return sd_bus_message_append(reply, "t", value);
}

static int property_get_effective_limit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        uint64_t value = CGROUP_LIMIT_MAX;
        Unit *u = ASSERT_PTR(userdata);
        ssize_t type;

        assert(bus);
        assert(reply);
        assert(property);

        assert_se((type = cgroup_effective_limit_type_from_string(property)) >= 0);
        (void) unit_get_effective_limit(u, type, &value);
        return sd_bus_message_append(reply, "t", value);
}

int bus_unit_method_attach_processes(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_set_free_ Set *pids = NULL;
        const char *path;
        int r;

        assert(message);

        /* This migrates the processes with the specified PIDs into the cgroup of this unit, optionally below a
         * specified cgroup path. Obviously this only works for units that actually maintain a cgroup
         * representation. If a process is already in the cgroup no operation is executed – in this case the specified
         * subcgroup path has no effect! */

        r = mac_selinux_unit_access_check(u, message, "start", reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &path);
        if (r < 0)
                return r;

        path = empty_to_null(path);
        if (path) {
                if (!path_is_absolute(path))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not absolute: %s", path);

                if (!path_is_normalized(path))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not normalized: %s", path);
        }

        if (!unit_cgroup_delegate(u))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Process migration not available on non-delegated units.");

        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Unit is not active, refusing.");

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
        if (r < 0)
                return r;

        /* Let's query the sender's UID, so that we can make our security decisions */
        uid_t sender_uid;
        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0)
                return r;
        bool validate_ownership = sender_uid != 0 && sender_uid != getuid();

        if (validate_ownership && !uid_is_valid(u->ref_uid)) /* process_is_owned_by_uid() requires a valid uid */
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_ACCESS_DENIED,
                                         "Refusing to attach processes to unit with unknown user credentials.");

        r = sd_bus_message_enter_container(message, 'a', "u");
        if (r < 0)
                return r;
        for (;;) {
                _cleanup_(pidref_freep) PidRef *pidref = NULL;
                uint32_t upid;

                r = sd_bus_message_read(message, "u", &upid);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (upid == 0) {
                        _cleanup_(pidref_done) PidRef p = PIDREF_NULL;
                        r = bus_creds_get_pidref(creds, &p);
                        if (r < 0)
                                return r;

                        r = pidref_dup(&p, &pidref);
                } else
                        r = pidref_new_from_pid(upid, &pidref);
                if (r < 0)
                        return r;

                /* Filter out duplicates */
                if (set_contains(pids, pidref))
                        continue;

                /* Check if this process is suitable for attaching to this unit */
                r = unit_pid_attachable(u, pidref, reterr_error);
                if (r < 0)
                        return r;

                /* Let's validate security: if the sender is root or the owner of the service manager, then
                 * all is OK. If the sender is any other user, then the process in question must be owned by
                 * both the sender and the target unit's UID. Note that ownership here means either direct
                 * ownership, or indirect via a userns that is owned by the right UID. */
                if (validate_ownership) {
                        r = process_is_owned_by_uid(pidref, sender_uid);
                        if (r < 0)
                                return sd_bus_error_set_errnof(reterr_error, r, "Failed to check if process " PID_FMT " is owned by client's UID: %m", pidref->pid);
                        if (r == 0)
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_ACCESS_DENIED, "Process " PID_FMT " not owned by client's UID. Refusing.", pidref->pid);

                        r = process_is_owned_by_uid(pidref, u->ref_uid);
                        if (r < 0)
                                return sd_bus_error_set_errnof(reterr_error, r, "Failed to check if process " PID_FMT " is owned by target unit's UID: %m", pidref->pid);
                        if (r == 0)
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_ACCESS_DENIED, "Process " PID_FMT " not owned by target unit's UID. Refusing.", pidref->pid);
                }

                r = set_ensure_consume(&pids, &pidref_hash_ops_free, TAKE_PTR(pidref));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        r = unit_attach_pids_to_cgroup(u, pids, path);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "Failed to attach processes to control group: %m");

        return sd_bus_reply_method_return(message, NULL);
}

int bus_unit_method_remove_subgroup(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(message);

        /* This removes a subcgroup of the unit, regardless which user owns the subcgroup. This is useful
         * when cgroup delegation is enabled for a unit, and the unit subdelegates the cgroup further */

        r = mac_selinux_unit_access_check(u, message, "stop", reterr_error);
        if (r < 0)
                return r;

        const char *path;
        uint64_t flags;
        r = sd_bus_message_read(message, "st", &path, &flags);
        if (r < 0)
                return r;

        /* No flags defined for now. */
        if (flags != 0)
                return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS, "Invalid 'flags' parameter '%" PRIu64 "'", flags);

        if (!unit_cgroup_delegate(u))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Subcgroup removal not available on non-delegated units.");

        if (!path_is_absolute(path))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not absolute: %s", path);

        if (!path_is_normalized(path))
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Control group path is not normalized: %s", path);

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        uid_t sender_uid;
        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0)
                return r;

        /* Allow this only if the client is privileged, is us, or is the user of the unit itself. */
        if (sender_uid != 0 && sender_uid != getuid() && sender_uid != u->ref_uid)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_ACCESS_DENIED, "Client is not permitted to alter cgroup.");

        r = unit_remove_subcgroup(u, path);
        if (r < 0)
                return sd_bus_error_set_errnof(reterr_error, r, "Failed to remove subgroup %s: %m", path);

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable bus_unit_cgroup_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Slice", "s", property_get_slice, 0, 0),
        SD_BUS_PROPERTY("ControlGroup", "s", property_get_cgroup, 0, 0),
        SD_BUS_PROPERTY("ControlGroupId", "t", property_get_cgroup_id, 0, 0),
        SD_BUS_PROPERTY("MemoryCurrent", "t", property_get_memory_accounting, 0, 0),
        SD_BUS_PROPERTY("MemoryPeak", "t", property_get_memory_accounting, 0, 0),
        SD_BUS_PROPERTY("MemorySwapCurrent", "t", property_get_memory_accounting, 0, 0),
        SD_BUS_PROPERTY("MemorySwapPeak", "t", property_get_memory_accounting, 0, 0),
        SD_BUS_PROPERTY("MemoryZSwapCurrent", "t", property_get_memory_accounting, 0, 0),
        SD_BUS_PROPERTY("MemoryAvailable", "t", property_get_available_memory, 0, 0),
        SD_BUS_PROPERTY("EffectiveMemoryMax", "t", property_get_effective_limit, 0, 0),
        SD_BUS_PROPERTY("EffectiveMemoryHigh", "t", property_get_effective_limit, 0, 0),
        SD_BUS_PROPERTY("CPUUsageNSec", "t", property_get_cpu_usage, 0, 0),
        SD_BUS_PROPERTY("EffectiveCPUs", "ay", property_get_cpuset_cpus, 0, 0),
        SD_BUS_PROPERTY("EffectiveMemoryNodes", "ay", property_get_cpuset_mems, 0, 0),
        SD_BUS_PROPERTY("TasksCurrent", "t", property_get_current_tasks, 0, 0),
        SD_BUS_PROPERTY("EffectiveTasksMax", "t", property_get_effective_limit, 0, 0),
        SD_BUS_PROPERTY("IPIngressBytes", "t", property_get_ip_counter, 0, 0),
        SD_BUS_PROPERTY("IPIngressPackets", "t", property_get_ip_counter, 0, 0),
        SD_BUS_PROPERTY("IPEgressBytes", "t", property_get_ip_counter, 0, 0),
        SD_BUS_PROPERTY("IPEgressPackets", "t", property_get_ip_counter, 0, 0),
        SD_BUS_PROPERTY("IOReadBytes", "t", property_get_io_counter, 0, 0),
        SD_BUS_PROPERTY("IOReadOperations", "t", property_get_io_counter, 0, 0),
        SD_BUS_PROPERTY("IOWriteBytes", "t", property_get_io_counter, 0, 0),
        SD_BUS_PROPERTY("IOWriteOperations", "t", property_get_io_counter, 0, 0),
        SD_BUS_PROPERTY("OOMKills", "t", property_get_oom_kills, 0, 0),
        SD_BUS_PROPERTY("ManagedOOMKills", "t", property_get_managed_oom_kills, 0, 0),

        SD_BUS_METHOD_WITH_ARGS("GetProcesses",
                                SD_BUS_NO_ARGS,
                                SD_BUS_ARGS("a(sus)", processes),
                                bus_unit_method_get_processes,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("AttachProcesses",
                                SD_BUS_ARGS("s", subcgroup, "au", pids),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_attach_processes,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("RemoveSubgroup",
                                SD_BUS_ARGS("s", subcgroup, "t", flags),
                                SD_BUS_NO_RESULT,
                                bus_unit_method_remove_subgroup,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

static int send_new_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);

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
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);

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

                /* The unit might be good to be GC once its pending signals have been sent */
                unit_add_to_gc_queue(u);
        }

        if (!u->id)
                return;

        r = bus_foreach_bus(u->manager, u->bus_track, u->sent_dbus_new_signal ? send_changed_signal : send_new_signal, u);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to send unit change signal for %s: %m", u->id);

        u->sent_dbus_new_signal = true;
}

void bus_unit_send_pending_change_signal(Unit *u, bool including_new) {

        /* Sends out any pending change signals, but only if they really are pending. This call is used when we are
         * about to change state in order to force out a PropertiesChanged signal beforehand if there was one pending
         * so that clients can follow the full state transition */

        if (!u->in_dbus_queue) /* If not enqueued, don't bother */
                return;

        if (!u->sent_dbus_new_signal && !including_new) /* If the unit was never announced, don't bother, it's fine if
                                                         * the unit appears in the new state right-away (except if the
                                                         * caller explicitly asked us to send it anyway) */
                return;

        if (MANAGER_IS_RELOADING(u->manager)) /* Don't generate unnecessary PropertiesChanged signals for the same unit
                                               * when we are reloading. */
                return;

        bus_unit_send_change_signal(u);
}

int bus_unit_send_pending_freezer_message(Unit *u, bool canceled) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(u);

        if (!u->pending_freezer_invocation)
                return 0;

        if (canceled)
                r = sd_bus_message_new_method_error(
                                u->pending_freezer_invocation,
                                &reply,
                                &SD_BUS_ERROR_MAKE_CONST(
                                                BUS_ERROR_FREEZE_CANCELLED, "Freeze operation aborted"));
        else
                r = sd_bus_message_new_method_return(u->pending_freezer_invocation, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_send(reply);
        if (r < 0)
                log_warning_errno(r, "Failed to send queued message, ignoring: %m");

        u->pending_freezer_invocation = sd_bus_message_unref(u->pending_freezer_invocation);

        return 0;
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Unit *u = ASSERT_PTR(userdata);
        int r;

        assert(bus);

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

        if (!u->sent_dbus_new_signal || u->in_dbus_queue)
                bus_unit_send_change_signal(u);

        if (!u->id)
                return;

        r = bus_foreach_bus(u->manager, u->bus_track, send_removed_signal, u);
        if (r < 0)
                log_unit_debug_errno(u, r, "Failed to send unit remove signal for %s: %m", u->id);
}

int bus_unit_queue_job_one(
                sd_bus_message *message,
                Unit *u,
                JobType type,
                JobMode mode,
                BusUnitQueueFlags flags,
                sd_bus_message *reply,
                sd_bus_error *reterr_error) {

        _cleanup_set_free_ Set *affected = NULL;
        _cleanup_free_ char *job_path = NULL, *unit_path = NULL;
        Job *j, *a;
        int r;

        assert(u);

        r = unit_queue_job_check_and_mangle_type(
                        u,
                        &type,
                        /* reload_if_possible= */ FLAGS_SET(flags, BUS_UNIT_QUEUE_RELOAD_IF_POSSIBLE),
                        reterr_error);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, BUS_UNIT_QUEUE_VERBOSE_REPLY)) {
                affected = set_new(NULL);
                if (!affected)
                        return -ENOMEM;
        }

        r = manager_add_job_full(u->manager, type, u, mode, /* extra_flags= */ 0, affected, reterr_error, &j);
        if (r < 0)
                return r;

        r = bus_job_track_sender(j, message);
        if (r < 0)
                return r;

        /* Before we send the method reply, force out the announcement JobNew for this job */
        bus_job_send_pending_change_signal(j, true);

        job_path = job_dbus_path(j);
        if (!job_path)
                return -ENOMEM;

        /* The classic response is just a job object path */
        if (!FLAGS_SET(flags, BUS_UNIT_QUEUE_VERBOSE_REPLY))
                return sd_bus_message_append(reply, "o", job_path);

        /* In verbose mode respond with the anchor job plus everything that has been affected */

        unit_path = unit_dbus_path(j->unit);
        if (!unit_path)
                return -ENOMEM;

        r = sd_bus_message_append(reply, "uosos",
                                  j->id, job_path,
                                  j->unit->id, unit_path,
                                  job_type_to_string(j->type));
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(uosos)");
        if (r < 0)
                return r;

        SET_FOREACH(a, affected) {
                if (a->id == j->id)
                        continue;

                /* Free paths from previous iteration */
                job_path = mfree(job_path);
                unit_path = mfree(unit_path);

                job_path = job_dbus_path(a);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(a->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(uosos)",
                                          a->id, job_path,
                                          a->unit->id, unit_path,
                                          job_type_to_string(a->type));
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

int bus_unit_queue_job(
                sd_bus_message *message,
                Unit *u,
                JobType type,
                JobMode mode,
                BusUnitQueueFlags flags,
                sd_bus_error *reterr_error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(message);
        assert(u);
        assert(type >= 0 && type < _JOB_TYPE_MAX);
        assert(mode >= 0 && mode < _JOB_MODE_MAX);

        r = mac_selinux_unit_access_check(
                        u, message,
                        job_type_to_access_method(type),
                        reterr_error);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = bus_unit_queue_job_one(message, u, type, mode, flags, reply, reterr_error);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int bus_unit_set_live_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        int r;

        assert(u);
        assert(name);
        assert(message);

        /* Handles setting properties both "live" (i.e. at any time during runtime), and during creation (for
         * transient units that are being created). */

        if (streq(name, "Description")) {
                const char *d;

                r = sd_bus_message_read(message, "s", &d);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = unit_set_description(u, d);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, "Description=%s", d);
                }

                return 1;
        }

        /* A setting that only applies to active units. We don't actually write this to /run, this state is
         * managed internally. "+foo" sets flag foo, "-foo" unsets flag foo, just "foo" resets flags to
         * foo. The last type cannot be mixed with "+" or "-". */

        if (streq(name, "Markers")) {
                unsigned settings = 0, mask = 0;
                bool some_plus_minus = false, some_absolute = false;

                r = sd_bus_message_enter_container(message, 'a', "s");
                if (r < 0)
                        return r;

                for (;;) {
                        const char *word;

                        r = sd_bus_message_read(message, "s", &word);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = parse_unit_marker(word, &settings, &mask);
                        if (r < 0)
                                return sd_bus_error_setf(reterr_error, BUS_ERROR_BAD_UNIT_SETTING,
                                                         "Unknown marker \"%s\".", word);
                        if (r > 0)
                                some_plus_minus = true;
                        else
                                some_absolute = true;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (some_plus_minus && some_absolute)
                        return sd_bus_error_set(reterr_error, BUS_ERROR_BAD_UNIT_SETTING, "Bad marker syntax.");

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (some_absolute)
                                mask = UINT_MAX;
                        u->markers = unit_normalize_markers((u->markers & ~mask), settings);
                }

                return 1;
        }

        return 0;
}

static int bus_set_transient_emergency_action(
                Unit *u,
                const char *name,
                EmergencyAction *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        const char *s;
        EmergencyAction v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "s", &s);
        if (r < 0)
                return r;

        r = parse_emergency_action(s, u->manager->runtime_scope, &v);
        if (r < 0)
                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS,
                                         r == -EOPNOTSUPP ? "%s setting invalid for manager type: %s"
                                                          : "Invalid %s setting: %s",
                                         name, s);

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = v;
                unit_write_settingf(u, flags, name,
                                    "%s=%s", name, s);
        }

        return 1;
}

static int bus_set_transient_exit_status(
                Unit *u,
                const char *name,
                int *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        int32_t k;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "i", &k);
        if (r < 0)
                return r;

        if (k > 255)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Exit status must be in range 0…255 or negative.");

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = k < 0 ? -1 : k;

                if (k < 0)
                        unit_write_settingf(u, flags, name, "%s=", name);
                else
                        unit_write_settingf(u, flags, name, "%s=%i", name, k);
        }

        return 1;
}

static BUS_DEFINE_SET_TRANSIENT_PARSE(collect_mode, CollectMode, collect_mode_from_string);
static BUS_DEFINE_SET_TRANSIENT_PARSE(job_mode, JobMode, job_mode_from_string);

static int bus_set_transient_conditions(
                Unit *u,
                const char *name,
                Condition **list,
                bool is_condition,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        const char *type_name, *param;
        int trigger, negate, r;
        bool empty = true;

        assert(list);

        r = sd_bus_message_enter_container(message, 'a', "(sbbs)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(message, "(sbbs)", &type_name, &trigger, &negate, &param)) > 0) {
                ConditionType t;

                t = is_condition ? condition_type_from_string(type_name) : assert_type_from_string(type_name);
                if (t < 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid condition type: %s", type_name);

                if (isempty(param))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Condition parameter in %s is empty", type_name);

                if (condition_takes_path(t) && !path_is_absolute(param))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Path in condition %s is not absolute: %s", type_name, param);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        Condition *c;

                        c = condition_new(t, param, trigger, negate);
                        if (!c)
                                return -ENOMEM;

                        LIST_PREPEND(conditions, *list, c);

                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name,
                                            "%s=%s%s%s", type_name,
                                            trigger ? "|" : "", negate ? "!" : "", param);
                }

                empty = false;
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags) && empty) {
                *list = condition_free_list(*list);
                unit_write_settingf(u, flags, name, "%sNull=", is_condition ? "Condition" : "Assert");
        }

        return 1;
}

static int bus_unit_set_transient_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *reterr_error) {

        UnitDependency d;
        int r;

        assert(u);
        assert(name);
        assert(message);

        /* Handles settings when transient units are created. This settings cannot be altered anymore after
         * the unit has been created. */

        if (streq(name, "SourcePath"))
                return bus_set_transient_path(u, name, &u->source_path, message, flags, reterr_error);

        if (streq(name, "StopWhenUnneeded"))
                return bus_set_transient_bool(u, name, &u->stop_when_unneeded, message, flags, reterr_error);

        if (streq(name, "RefuseManualStart"))
                return bus_set_transient_bool(u, name, &u->refuse_manual_start, message, flags, reterr_error);

        if (streq(name, "RefuseManualStop"))
                return bus_set_transient_bool(u, name, &u->refuse_manual_stop, message, flags, reterr_error);

        if (streq(name, "AllowIsolate"))
                return bus_set_transient_bool(u, name, &u->allow_isolate, message, flags, reterr_error);

        if (streq(name, "DefaultDependencies"))
                return bus_set_transient_bool(u, name, &u->default_dependencies, message, flags, reterr_error);

        if (streq(name, "SurviveFinalKillSignal"))
                return bus_set_transient_bool(u, name, &u->survive_final_kill_signal, message, flags, reterr_error);

        if (streq(name, "OnSuccessJobMode"))
                return bus_set_transient_job_mode(u, name, &u->on_success_job_mode, message, flags, reterr_error);

        if (streq(name, "OnFailureJobMode"))
                return bus_set_transient_job_mode(u, name, &u->on_failure_job_mode, message, flags, reterr_error);

        if (streq(name, "IgnoreOnIsolate"))
                return bus_set_transient_bool(u, name, &u->ignore_on_isolate, message, flags, reterr_error);

        if (streq(name, "JobTimeoutUSec")) {
                r = bus_set_transient_usec_fix_0(u, name, &u->job_timeout, message, flags, reterr_error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags) && !u->job_running_timeout_set)
                        u->job_running_timeout = u->job_timeout;
        }

        if (streq(name, "JobRunningTimeoutUSec")) {
                r = bus_set_transient_usec_fix_0(u, name, &u->job_running_timeout, message, flags, reterr_error);
                if (r >= 0 && !UNIT_WRITE_FLAGS_NOOP(flags))
                        u->job_running_timeout_set = true;

                return r;
        }

        if (streq(name, "JobTimeoutAction"))
                return bus_set_transient_emergency_action(u, name, &u->job_timeout_action, message, flags, reterr_error);

        if (streq(name, "JobTimeoutRebootArgument"))
                return bus_set_transient_reboot_parameter(u, name, &u->job_timeout_reboot_arg, message, flags, reterr_error);

        if (streq(name, "StartLimitIntervalUSec"))
                return bus_set_transient_usec(u, name, &u->start_ratelimit.interval, message, flags, reterr_error);

        if (streq(name, "StartLimitBurst"))
                return bus_set_transient_unsigned(u, name, &u->start_ratelimit.burst, message, flags, reterr_error);

        if (streq(name, "StartLimitAction"))
                return bus_set_transient_emergency_action(u, name, &u->start_limit_action, message, flags, reterr_error);

        if (streq(name, "FailureAction"))
                return bus_set_transient_emergency_action(u, name, &u->failure_action, message, flags, reterr_error);

        if (streq(name, "SuccessAction"))
                return bus_set_transient_emergency_action(u, name, &u->success_action, message, flags, reterr_error);

        if (streq(name, "FailureActionExitStatus"))
                return bus_set_transient_exit_status(u, name, &u->failure_action_exit_status, message, flags, reterr_error);

        if (streq(name, "SuccessActionExitStatus"))
                return bus_set_transient_exit_status(u, name, &u->success_action_exit_status, message, flags, reterr_error);

        if (streq(name, "RebootArgument"))
                return bus_set_transient_reboot_parameter(u, name, &u->reboot_arg, message, flags, reterr_error);

        if (streq(name, "CollectMode"))
                return bus_set_transient_collect_mode(u, name, &u->collect_mode, message, flags, reterr_error);

        if (streq(name, "Conditions"))
                return bus_set_transient_conditions(u, name, &u->conditions, true, message, flags, reterr_error);

        if (streq(name, "Asserts"))
                return bus_set_transient_conditions(u, name, &u->asserts, false, message, flags, reterr_error);

        if (streq(name, "Documentation")) {
                _cleanup_strv_free_ char **l = NULL;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, l)
                        if (!documentation_url_is_valid(*p))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid URL in %s: %s", name, *p);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        if (strv_isempty(l)) {
                                u->documentation = strv_free(u->documentation);
                                unit_write_settingf(u, flags, name, "%s=", name);
                        } else {
                                r = strv_extend_strv(&u->documentation, l, /* filter_duplicates= */ false);
                                if (r < 0)
                                        return r;

                                STRV_FOREACH(p, l)
                                        unit_write_settingf(u, flags, name, "%s=%s", name, *p);
                        }
                }

                return 1;
        }

        if (streq(name, "Slice")) {
                Unit *slice;
                const char *s;

                if (!UNIT_HAS_CGROUP_CONTEXT(u))
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "The slice property is only available for units with control groups.");
                if (u->type == UNIT_SLICE)
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Slice may not be set for slice units.");
                if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Cannot set slice for init.scope");

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                if (!unit_name_is_valid(s, UNIT_NAME_PLAIN))
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit name '%s'", s);

                /* Note that we do not dispatch the load queue here yet, as we don't want our own transient unit to be
                 * loaded while we are still setting it up. Or in other words, we use manager_load_unit_prepare()
                 * instead of manager_load_unit() on purpose, here. */
                r = manager_load_unit_prepare(u->manager, s, NULL, reterr_error, &slice);
                if (r < 0)
                        return r;

                if (slice->type != UNIT_SLICE)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Unit name '%s' is not a slice", s);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = unit_set_slice(u, slice);
                        if (r < 0)
                                return r;

                        unit_write_settingf(u, flags|UNIT_PRIVATE, name, "Slice=%s", s);
                }

                return 1;
        }

        if (STR_IN_SET(name, "RequiresMountsFor", "WantsMountsFor")) {
                _cleanup_strv_free_ char **l = NULL;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, l) {
                        path_simplify(*p);

                        if (!path_is_absolute(*p))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Path specified in %s is not absolute: %s", name, *p);

                        if (!path_is_valid(*p))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Path specified in %s has invalid length: %s", name, *p);

                        if (!path_is_normalized(*p))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Path specified in %s is not normalized: %s", name, *p);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = unit_add_mounts_for(u, *p, UNIT_DEPENDENCY_FILE, unit_mount_dependency_type_from_string(name));
                                if (r < 0)
                                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Failed to add requested mount \"%s\": %m", *p);

                                unit_write_settingf(u, flags, name, "%s=%s", name, *p);
                        }
                }

                return 1;
        }

        if (streq(name, "AddRef")) {
                int b;

                /* Why is this called "AddRef" rather than just "Ref", or "Reference"? There's already a "Ref()" method
                 * on the Unit interface, and it's probably not a good idea to expose a property and a method on the
                 * same interface (well, strictly speaking AddRef isn't exposed as full property, we just read it for
                 * transient units, but still). And "References" and "ReferencedBy" is already used as unit reference
                 * dependency type, hence let's not confuse things with that.
                 *
                 * Note that we don't actually add the reference to the bus track. We do that only after the setup of
                 * the transient unit is complete, so that setting this property multiple times in the same transient
                 * unit creation call doesn't count as individual references. */

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (!UNIT_WRITE_FLAGS_NOOP(flags))
                        u->bus_track_add = b;

                return 1;
        }

        if (streq(name, "RequiresOverridable"))
                d = UNIT_REQUIRES; /* redirect for obsolete unit dependency type */
        else if (streq(name, "RequisiteOverridable"))
                d = UNIT_REQUISITE; /* same here */
        else
                d = unit_dependency_from_string(name);
        if (d >= 0) {
                const char *other;

                if (!IN_SET(d,
                            UNIT_REQUIRES,
                            UNIT_REQUISITE,
                            UNIT_WANTS,
                            UNIT_BINDS_TO,
                            UNIT_PART_OF,
                            UNIT_UPHOLDS,
                            UNIT_CONFLICTS,
                            UNIT_BEFORE,
                            UNIT_AFTER,
                            UNIT_ON_SUCCESS,
                            UNIT_ON_FAILURE,
                            UNIT_PROPAGATES_RELOAD_TO,
                            UNIT_RELOAD_PROPAGATED_FROM,
                            UNIT_PROPAGATES_STOP_TO,
                            UNIT_STOP_PROPAGATED_FROM,
                            UNIT_JOINS_NAMESPACE_OF))
                    return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Dependency type %s may not be created transiently.", unit_dependency_to_string(d));

                r = sd_bus_message_enter_container(message, 'a', "s");
                if (r < 0)
                        return r;

                while ((r = sd_bus_message_read(message, "s", &other)) > 0) {
                        if (!unit_name_is_valid(other, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                                return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid unit name %s", other);

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                _cleanup_free_ char *label = NULL;

                                r = unit_add_dependency_by_name(u, d, other, true, UNIT_DEPENDENCY_FILE);
                                if (r < 0)
                                        return r;

                                label = strjoin(name, "-", other);
                                if (!label)
                                        return -ENOMEM;

                                unit_write_settingf(u, flags, label, "%s=%s", unit_dependency_to_string(d), other);
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
                UnitWriteFlags flags,
                bool commit,
                sd_bus_error *reterr_error) {

        bool for_real = false;
        unsigned n = 0;
        int r;

        assert(u);
        assert(message);

        /* We iterate through the array twice. First run just checks if all passed data is valid, second run
         * actually applies it. This implements transaction-like behaviour without actually providing full
         * transactions. */

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                goto error;

        for (;;) {
                const char *name;
                UnitWriteFlags f;

                r = sd_bus_message_enter_container(message, 'r', "sv");
                if (r < 0)
                        goto error;
                if (r == 0) {
                        if (for_real || UNIT_WRITE_FLAGS_NOOP(flags))
                                break;

                        /* Reached EOF. Let's try again, and this time for realz... */
                        r = sd_bus_message_rewind(message, false);
                        if (r < 0)
                                goto error;

                        for_real = true;
                        continue;
                }

                r = sd_bus_message_read(message, "s", &name);
                if (r < 0)
                        goto error;

                r = sd_bus_message_enter_container(message, 'v', NULL);
                if (r < 0)
                        goto error;

                /* If not for real, then mask out the two target flags */
                f = for_real ? flags : (flags & ~(UNIT_RUNTIME|UNIT_PERSISTENT));

                if (UNIT_VTABLE(u)->bus_set_property)
                        r = UNIT_VTABLE(u)->bus_set_property(u, name, message, f, reterr_error);
                else
                        r = 0;
                if (r == 0 && u->transient && u->load_state == UNIT_STUB)
                        r = bus_unit_set_transient_property(u, name, message, f, reterr_error);
                if (r == 0)
                        r = bus_unit_set_live_property(u, name, message, f, reterr_error);
                if (r < 0)
                        goto error;

                if (r == 0)
                        return sd_bus_error_setf(reterr_error, SD_BUS_ERROR_PROPERTY_READ_ONLY,
                                                 "Cannot set property %s, or unknown property.", name);

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        goto error;

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        goto error;

                n += for_real;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                goto error;

        if (commit && n > 0 && UNIT_VTABLE(u)->bus_commit_properties)
                UNIT_VTABLE(u)->bus_commit_properties(u);

        return n;

 error:
        /* Pretty much any of the calls above can fail if the message is not formed properly
         * or if it has unexpected contents. Fill in a more informative error message here. */
        if (sd_bus_error_is_set(reterr_error))
                return r;
        return sd_bus_error_set_errnof(reterr_error, r,
                                       r == -ENXIO ? "Failed to set unit properties: Unexpected message contents"
                                                   : "Failed to set unit properties: %m");
}

int bus_unit_validate_load_state(Unit *u, sd_bus_error *reterr_error) {
        assert(u);

        /* Generates a pretty error if a unit isn't properly loaded. */

        switch (u->load_state) {

        case UNIT_LOADED:
                return 0;

        case UNIT_NOT_FOUND:
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s not found.", u->id);

        case UNIT_BAD_SETTING:
                return sd_bus_error_setf(reterr_error, BUS_ERROR_BAD_UNIT_SETTING, "Unit %s has a bad unit file setting.", u->id);

        case UNIT_ERROR: /* Only show .load_error in UNIT_ERROR state */
                return sd_bus_error_set_errnof(reterr_error, u->load_error,
                                               "Unit %s failed to load properly, please adjust/correct and reload service manager: %m", u->id);

        case UNIT_MASKED:
                return sd_bus_error_setf(reterr_error, BUS_ERROR_UNIT_MASKED, "Unit %s is masked.", u->id);

        case UNIT_STUB:
        case UNIT_MERGED:
        default:
                return sd_bus_error_setf(reterr_error, BUS_ERROR_NO_SUCH_UNIT, "Unexpected load state of unit %s", u->id);
        }
}

static int bus_unit_track_handler(sd_bus_track *t, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);

        assert(t);

        u->bus_track = sd_bus_track_unref(u->bus_track); /* make sure we aren't called again */

        /* Add the unit to the GC queue, after all if the client left it might be time to GC this unit */
        unit_add_to_gc_queue(u);

        return 0;
}

static int bus_unit_allocate_bus_track(Unit *u) {
        int r;

        assert(u);

        if (u->bus_track)
                return 0;

        r = sd_bus_track_new(u->manager->api_bus, &u->bus_track, bus_unit_track_handler, u);
        if (r < 0)
                return r;

        r = sd_bus_track_set_recursive(u->bus_track, true);
        if (r < 0) {
                u->bus_track = sd_bus_track_unref(u->bus_track);
                return r;
        }

        return 0;
}

int bus_unit_track_add_name(Unit *u, const char *name) {
        int r;

        assert(u);

        r = bus_unit_allocate_bus_track(u);
        if (r < 0)
                return r;

        return sd_bus_track_add_name(u->bus_track, name);
}

int bus_unit_track_add_sender(Unit *u, sd_bus_message *m) {
        int r;

        assert(u);

        r = bus_unit_allocate_bus_track(u);
        if (r < 0)
                return r;

        return sd_bus_track_add_sender(u->bus_track, m);
}

int bus_unit_track_remove_sender(Unit *u, sd_bus_message *m) {
        assert(u);

        /* If we haven't allocated the bus track object yet, then there's definitely no reference taken yet,
         * return an error */
        if (!u->bus_track)
                return -EUNATCH;

        return sd_bus_track_remove_sender(u->bus_track, m);
}
