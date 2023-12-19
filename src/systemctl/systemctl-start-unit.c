/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "bus-wait-for-units.h"
#include "macro.h"
#include "special.h"
#include "string-util.h"
#include "systemctl-start-unit.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

static const struct {
        const char *verb;      /* systemctl verb */
        const char *method;    /* Name of the specific D-Bus method */
        const char *job_type;  /* Job type when passing to the generic EnqueueUnitJob() method */
} unit_actions[] = {
        { "start",                 "StartUnit",              "start"                 },
        { "stop",                  "StopUnit",               "stop"                  },
        { "condstop",              "StopUnit",               "stop"                  }, /* legacy alias */
        { "reload",                "ReloadUnit",             "reload"                },
        { "restart",               "RestartUnit",            "restart"               },
        { "try-restart",           "TryRestartUnit",         "try-restart"           },
        { "condrestart",           "TryRestartUnit",         "try-restart"           }, /* legacy alias */
        { "reload-or-restart",     "ReloadOrRestartUnit",    "reload-or-restart"     },
        { "try-reload-or-restart", "ReloadOrTryRestartUnit", "reload-or-try-restart" },
        { "reload-or-try-restart", "ReloadOrTryRestartUnit", "reload-or-try-restart" }, /* legacy alias */
        { "condreload",            "ReloadOrTryRestartUnit", "reload-or-try-restart" }, /* legacy alias */
        { "force-reload",          "ReloadOrTryRestartUnit", "reload-or-try-restart" }, /* legacy alias */
};

static const char *verb_to_method(const char *verb) {
       for (size_t i = 0; i < ELEMENTSOF(unit_actions); i++)
                if (streq_ptr(unit_actions[i].verb, verb))
                        return unit_actions[i].method;

       return "StartUnit";
}

static const char *verb_to_job_type(const char *verb) {
       for (size_t i = 0; i < ELEMENTSOF(unit_actions); i++)
                if (streq_ptr(unit_actions[i].verb, verb))
                        return unit_actions[i].job_type;

       return "start";
}

static int start_unit_one(
                sd_bus *bus,
                const char *method,    /* When using classic per-job bus methods */
                const char *job_type,  /* When using new-style EnqueueUnitJob() */
                const char *name,
                const char *mode,
                sd_bus_error *error,
                BusWaitForJobs *w,
                BusWaitForUnits *wu) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        bool done = false;
        int r;

        assert(method);
        assert(name);
        assert(mode);
        assert(error);

        log_debug("%s dbus call org.freedesktop.systemd1.Manager %s(%s, %s)",
                  arg_dry_run ? "Would execute" : "Executing",
                  method, name, mode);

        if (arg_dry_run)
                return 0;

        if (arg_show_transaction) {
                _cleanup_(sd_bus_error_free) sd_bus_error enqueue_error = SD_BUS_ERROR_NULL;

                /* Use the new, fancy EnqueueUnitJob() API if the user wants us to print the transaction */
                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "EnqueueUnitJob",
                                &enqueue_error,
                                &reply,
                                "sss",
                                name, job_type, mode);
                if (r < 0) {
                        if (!sd_bus_error_has_name(&enqueue_error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
                                (void) sd_bus_error_move(error, &enqueue_error);
                                goto fail;
                        }

                        /* Hmm, the API is not yet available. Let's use the classic API instead (see below). */
                        log_notice("--show-transaction not supported by this service manager, proceeding without.");
                } else {
                        const char *u, *jt;
                        uint32_t id;

                        r = sd_bus_message_read(reply, "uosos", &id, &path, &u, NULL, &jt);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        log_info("Enqueued anchor job %" PRIu32 " %s/%s.", id, u, jt);

                        r = sd_bus_message_enter_container(reply, 'a', "(uosos)");
                        if (r < 0)
                                return bus_log_parse_error(r);
                        for (;;) {
                                r = sd_bus_message_read(reply, "(uosos)", &id, NULL, &u, NULL, &jt);
                                if (r < 0)
                                        return bus_log_parse_error(r);
                                if (r == 0)
                                        break;

                                log_info("Enqueued auxiliary job %" PRIu32 " %s/%s.", id, u, jt);
                        }

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        done = true;
                }
        }

        if (!done) {
                r = bus_call_method(bus, bus_systemd_mgr, method, error, &reply, "ss", name, mode);
                if (r < 0)
                        goto fail;

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        if (need_daemon_reload(bus, name) > 0)
                warn_unit_file_changed(name);

        if (w) {
                log_debug("Adding %s to the set", path);
                r = bus_wait_for_jobs_add(w, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch job for %s: %m", name);
        }

        if (wu) {
                r = bus_wait_for_units_add_unit(wu, name, BUS_WAIT_FOR_INACTIVE|BUS_WAIT_NO_JOB, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch unit %s: %m", name);
        }

        return 0;

fail:
        /* There's always a fallback possible for legacy actions. */
        if (arg_action != ACTION_SYSTEMCTL)
                return r;

        if (sd_bus_error_has_name(error, BUS_ERROR_UNIT_MASKED) &&
            STR_IN_SET(method, "TryRestartUnit", "ReloadOrTryRestartUnit")) {
                /* Ignore masked unit if try-* is requested */

                log_debug_errno(r, "Failed to %s %s, ignoring: %s", job_type, name, bus_error_message(error, r));
                return 0;
        }

        log_error_errno(r, "Failed to %s %s: %s", job_type, name, bus_error_message(error, r));

        if (!sd_bus_error_has_names(error, BUS_ERROR_NO_SUCH_UNIT,
                                           BUS_ERROR_UNIT_MASKED,
                                           BUS_ERROR_JOB_TYPE_NOT_APPLICABLE))
                log_error("See %s logs and 'systemctl%s status%s %s' for details.",
                          runtime_scope_to_string(arg_runtime_scope),
                          arg_runtime_scope == RUNTIME_SCOPE_SYSTEM ? "" : " --user",
                          name[0] == '-' ? " --" : "",
                          name);

        return r;
}

static int enqueue_marked_jobs(
                sd_bus *bus,
                BusWaitForJobs *w) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        log_debug("%s dbus call org.freedesktop.systemd1.Manager EnqueueMarkedJobs()",
                  arg_dry_run ? "Would execute" : "Executing");

        if (arg_dry_run)
                return 0;

        r = bus_call_method(bus, bus_systemd_mgr, "EnqueueMarkedJobs", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to start jobs: %s", bus_error_message(&error, r));

        _cleanup_strv_free_ char **paths = NULL;
        r = sd_bus_message_read_strv(reply, &paths);
        if (r < 0)
                return bus_log_parse_error(r);

        if (w)
                STRV_FOREACH(path, paths) {
                        log_debug("Adding %s to the set", *path);
                        r = bus_wait_for_jobs_add(w, *path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to watch job %s: %m", *path);
                }

        return 0;
}

const struct action_metadata action_table[_ACTION_MAX] = {
        [ACTION_HALT]                   = { SPECIAL_HALT_TARGET,                   "halt",                   "replace-irreversibly" },
        [ACTION_POWEROFF]               = { SPECIAL_POWEROFF_TARGET,               "poweroff",               "replace-irreversibly" },
        [ACTION_REBOOT]                 = { SPECIAL_REBOOT_TARGET,                 "reboot",                 "replace-irreversibly" },
        [ACTION_KEXEC]                  = { SPECIAL_KEXEC_TARGET,                  "kexec",                  "replace-irreversibly" },
        [ACTION_SOFT_REBOOT]            = { SPECIAL_SOFT_REBOOT_TARGET,            "soft-reboot",            "replace-irreversibly" },
        [ACTION_RUNLEVEL2]              = { SPECIAL_MULTI_USER_TARGET,             NULL,                     "isolate"              },
        [ACTION_RUNLEVEL3]              = { SPECIAL_MULTI_USER_TARGET,             NULL,                     "isolate"              },
        [ACTION_RUNLEVEL4]              = { SPECIAL_MULTI_USER_TARGET,             NULL,                     "isolate"              },
        [ACTION_RUNLEVEL5]              = { SPECIAL_GRAPHICAL_TARGET,              NULL,                     "isolate"              },
        [ACTION_RESCUE]                 = { SPECIAL_RESCUE_TARGET,                 "rescue",                 "isolate"              },
        [ACTION_EMERGENCY]              = { SPECIAL_EMERGENCY_TARGET,              "emergency",              "isolate"              },
        [ACTION_DEFAULT]                = { SPECIAL_DEFAULT_TARGET,                "default",                "isolate"              },
        [ACTION_EXIT]                   = { SPECIAL_EXIT_TARGET,                   "exit",                   "replace-irreversibly" },
        [ACTION_SUSPEND]                = { SPECIAL_SUSPEND_TARGET,                "suspend",                "replace-irreversibly" },
        [ACTION_HIBERNATE]              = { SPECIAL_HIBERNATE_TARGET,              "hibernate",              "replace-irreversibly" },
        [ACTION_HYBRID_SLEEP]           = { SPECIAL_HYBRID_SLEEP_TARGET,           "hybrid-sleep",           "replace-irreversibly" },
        [ACTION_SUSPEND_THEN_HIBERNATE] = { SPECIAL_SUSPEND_THEN_HIBERNATE_TARGET, "suspend-then-hibernate", "replace-irreversibly" },
        [ACTION_SLEEP]                  = { NULL, /* handled only by logind */     "sleep",                  NULL                   },
};

enum action verb_to_action(const char *verb) {
        for (enum action i = 0; i < _ACTION_MAX; i++)
                if (streq_ptr(action_table[i].verb, verb))
                        return i;

        return _ACTION_INVALID;
}

static const char** make_extra_args(const char *extra_args[static 4]) {
        size_t n = 0;

        assert(extra_args);

        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                extra_args[n++] = "--user";

        if (arg_transport == BUS_TRANSPORT_REMOTE) {
                extra_args[n++] = "-H";
                extra_args[n++] = arg_host;
        } else if (arg_transport == BUS_TRANSPORT_MACHINE) {
                extra_args[n++] = "-M";
                extra_args[n++] = arg_host;
        } else
                assert(arg_transport == BUS_TRANSPORT_LOCAL);

        extra_args[n] = NULL;
        return extra_args;
}

int verb_start(int argc, char *argv[], void *userdata) {
        _cleanup_(bus_wait_for_units_freep) BusWaitForUnits *wu = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        const char *method, *job_type, *mode, *one_name, *suffix = NULL;
        _cleanup_free_ char **stopped_units = NULL; /* Do not use _cleanup_strv_free_ */
        _cleanup_strv_free_ char **names = NULL;
        int r, ret = EXIT_SUCCESS;
        sd_bus *bus;

        if (arg_wait && !STR_IN_SET(argv[0], "start", "restart"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--wait may only be used with the 'start' or 'restart' commands.");

        /* We cannot do sender tracking on the private bus, so we need the full one for RefUnit to implement
         * --wait */
        r = acquire_bus(arg_wait ? BUS_FULL : BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        ask_password_agent_open_maybe();
        polkit_agent_open_maybe();

        if (arg_action == ACTION_SYSTEMCTL) {
                enum action action;

                action = verb_to_action(argv[0]);

                assert(action != ACTION_SLEEP);

                if (action != _ACTION_INVALID) {
                        /* A command in style "systemctl reboot", "systemctl poweroff", … */
                        method = "StartUnit";
                        job_type = "start";
                        mode = action_table[action].mode;
                        one_name = action_table[action].target;
                } else {
                        if (streq(argv[0], "isolate")) {
                                /* A "systemctl isolate <unit1> <unit2> …" command */
                                method = "StartUnit";
                                job_type = "start";
                                mode = "isolate";
                                suffix = ".target";
                        } else if (!arg_marked) {
                                /* A command in style of "systemctl start <unit1> <unit2> …", "systemctl stop <unit1> <unit2> …" and so on */
                                method = verb_to_method(argv[0]);
                                job_type = verb_to_job_type(argv[0]);
                                mode = arg_job_mode();
                        } else
                                method = job_type = mode = NULL;

                        one_name = NULL;
                }
        } else {
                /* A SysV legacy command such as "halt", "reboot", "poweroff", … */
                assert(arg_action >= 0 && arg_action < _ACTION_MAX);
                assert(action_table[arg_action].target);
                assert(action_table[arg_action].mode);

                method = "StartUnit";
                job_type = "start";
                mode = action_table[arg_action].mode;
                one_name = action_table[arg_action].target;
        }

        if (one_name) {
                names = strv_new(one_name);
                if (!names)
                        return log_oom();
        } else if (!arg_marked) {
                bool expanded;

                r = expand_unit_names(bus, strv_skip(argv, 1), suffix, &names, &expanded);
                if (r < 0)
                        return log_error_errno(r, "Failed to expand names: %m");

                if (!arg_all && expanded && streq(job_type, "start") && !arg_quiet) {
                        log_warning("Warning: %ssystemctl start called with a glob pattern.%s",
                                    ansi_highlight_red(),
                                    ansi_normal());
                        log_notice("Hint: unit globs expand to loaded units, so start will usually have no effect.\n"
                                   "      Passing --all will also load units which are pulled in by other units.\n"
                                   "      See systemctl(1) for more details.");
                }
        }

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        if (arg_wait) {
                r = bus_call_method_async(bus, NULL, bus_systemd_mgr, "Subscribe", NULL, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable subscription: %m");

                r = bus_wait_for_units_new(bus, &wu);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate unit watch context: %m");
        }

        if (arg_marked)
                ret = enqueue_marked_jobs(bus, w);
        else
                STRV_FOREACH(name, names) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        r = start_unit_one(bus, method, job_type, *name, mode, &error, w, wu);
                        if (ret == EXIT_SUCCESS && r < 0)
                                ret = translate_bus_error_to_exit_status(r, &error);

                        if (r >= 0 && streq(method, "StopUnit")) {
                                r = strv_push(&stopped_units, *name);
                                if (r < 0)
                                        return log_oom();
                        }
                }

        if (!arg_no_block) {
                const char* extra_args[4];
                WaitJobsFlags flags = 0;

                SET_FLAG(flags, BUS_WAIT_JOBS_LOG_ERROR, !arg_quiet);
                SET_FLAG(flags, BUS_WAIT_JOBS_LOG_SUCCESS, arg_show_transaction);
                r = bus_wait_for_jobs(w, flags, make_extra_args(extra_args));
                if (r < 0)
                        return r;

                /* When stopping units, warn if they can still be triggered by
                 * another active unit (socket, path, timer) */
                if (!arg_quiet && !arg_no_warn)
                        STRV_FOREACH(unit, stopped_units)
                                warn_triggering_units(bus, *unit, "Stopping", /* ignore_masked = */ true);
        }

        if (arg_wait) {
                r = bus_wait_for_units_run(wu);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for units: %m");
                if (r == BUS_WAIT_FAILURE && ret == EXIT_SUCCESS)
                        ret = EXIT_FAILURE;
        }

        return ret;
}
