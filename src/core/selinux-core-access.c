/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "selinux-core-access.h"

#if HAVE_SELINUX

#include "dbus-callbackdata.h"
#include "selinux-generic-access.h"
#include "selinux-util.h"

struct compat_permission_verb {
        const char *overhaul;
        const char *original;
};

const char *const mac_selinux_overhaul_instance_class = "systemd_instance";
const char *const mac_selinux_original_instance_class = "system";
const struct compat_permission_verb mac_selinux_instance_permissions[_MAC_SELINUX_INSTANCE_PERMISSION_MAX] = {
        [MAC_SELINUX_INSTANCE_STARTTRANSIENT]           = { "start_transient",          "start" },
        [MAC_SELINUX_INSTANCE_CLEARJOBS]                = { "clear_jobs",               "reload" },
        [MAC_SELINUX_INSTANCE_RESETFAILED]              = { "reset_failed",             "reload" },
        [MAC_SELINUX_INSTANCE_LISTUNITS]                = { "list_units",               "status" },
        [MAC_SELINUX_INSTANCE_LISTJOBS]                 = { "list_jobs",                "status" },
        [MAC_SELINUX_INSTANCE_SUBSCRIBE]                = { "subscribe",                "status" },
        [MAC_SELINUX_INSTANCE_UNSUBSCRIBE]              = { "unsubscribe",              "status" },
        [MAC_SELINUX_INSTANCE_DUMP]                     = { "dump",                     "status" },
        [MAC_SELINUX_INSTANCE_RELOAD]                   = { "reload",                   "reload" },
        [MAC_SELINUX_INSTANCE_REEXECUTE]                = { "reexecute",                "reload" },
        [MAC_SELINUX_INSTANCE_EXIT]                     = { "exit",                     "halt" },
        [MAC_SELINUX_INSTANCE_REBOOT]                   = { "reboot",                   "reboot" },
        [MAC_SELINUX_INSTANCE_POWEROFFORHALT]           = { "poweroff_or_halt",         "halt" },
        [MAC_SELINUX_INSTANCE_KEXEC]                    = { "kexec",                    "reboot" },
        [MAC_SELINUX_INSTANCE_SWITCHROOT]               = { "switch_root",              "reboot" },
        [MAC_SELINUX_INSTANCE_SETENVIRONMENT]           = { "set_environment",          "reload" },
        [MAC_SELINUX_INSTANCE_UNSETENVIRONMENT]         = { "unset_environment",        "reload" },
        [MAC_SELINUX_INSTANCE_SETEXITCODE]              = { "set_exit_code",            "exit" },
        [MAC_SELINUX_INSTANCE_LISTUNITFILES]            = { "list_unit_files",          "status" },
        [MAC_SELINUX_INSTANCE_STATEUNITFILE]            = { "state_unit_file",          "status" },
        [MAC_SELINUX_INSTANCE_GETDEFAULTTARGET]         = { "get_default_target",       "status" },
        [MAC_SELINUX_INSTANCE_SETDEFAULTTARGET]         = { "set_default_target",       "enable" },
        [MAC_SELINUX_INSTANCE_PRESETALLUNITFILES]       = { "preset_all_unit_files",    "enable" },
        [MAC_SELINUX_INSTANCE_RAWSET]                   = { "raw_set",                  "reload" },
        [MAC_SELINUX_INSTANCE_RAWSTATUS]                = { "raw_status",               "status" },
        [MAC_SELINUX_INSTANCE_SETLOGTARGET]             = { "set_log_target",           "reload" },
        [MAC_SELINUX_INSTANCE_SETLOGLEVEL]              = { "set_log_level",            "reload" },
        [MAC_SELINUX_INSTANCE_GETUNITFILELINKS]         = { "get_unit_file_links",      "status" },
        [MAC_SELINUX_INSTANCE_ADDDEPENDENCYUNITFILES]   = { "add_dependency_unit_files", "reload" },
        [MAC_SELINUX_INSTANCE_GETDYNAMICUSERS]          = { "get_dynamic_users",        NULL },
        [MAC_SELINUX_INSTANCE_SETWATCHDOG]              = { "set_watchdog",             "reload" },
};

const char *const mac_selinux_overhaul_unit_class = "systemd_unit";
const char *const mac_selinux_original_unit_class = "service";
const struct compat_permission_verb mac_selinux_unit_permissions[_MAC_SELINUX_UNIT_PERMISSION_MAX] = {
        [MAC_SELINUX_UNIT_GETJOB]                       = { "get_job",                  "status" },
        [MAC_SELINUX_UNIT_GETUNIT]                      = { "get_unit",                 "status" },
        [MAC_SELINUX_UNIT_START]                        = { "start",                    "start" },
        [MAC_SELINUX_UNIT_STOP]                         = { "stop",                     "stop" },
        [MAC_SELINUX_UNIT_RELOAD]                       = { "reload",                   "reload" },
        [MAC_SELINUX_UNIT_RESTART]                      = { "restart",                  "start" },
        [MAC_SELINUX_UNIT_NOP]                          = { "nop",                      "reload" },
        [MAC_SELINUX_UNIT_CANCEL]                       = { "cancel",                   "stop" },
        [MAC_SELINUX_UNIT_ABANDON]                      = { "abandon",                  "stop" },
        [MAC_SELINUX_UNIT_KILL]                         = { "kill",                     "stop" },
        [MAC_SELINUX_UNIT_RESETFAILED]                  = { "reset_failed",             "reload" },
        [MAC_SELINUX_UNIT_SETPROPERTIES]                = { "set_properties",           "start" },
        [MAC_SELINUX_UNIT_REF]                          = { "ref",                      "start" },
        [MAC_SELINUX_UNIT_CLEAN]                        = { "clean",                    "stop" },
        [MAC_SELINUX_UNIT_GETPROCESSES]                 = { "get_processes",            "status" },
        [MAC_SELINUX_UNIT_ATTACHPROCESSES]              = { "attach_processes",         "start" },
        [MAC_SELINUX_UNIT_RAWSET]                       = { "raw_set",                  "reload" },
        [MAC_SELINUX_UNIT_RAWSTATUS]                    = { "raw_status",               "status" },
        [MAC_SELINUX_UNIT_BINDMOUNT]                    = { "bind_mount",               "start" },
        [MAC_SELINUX_UNIT_GETWAITING_JOBS]              = { "get_waiting_jobs",         "status" },
        [MAC_SELINUX_UNIT_UNREF]                        = { "unref",                    "stop" },
        [MAC_SELINUX_UNIT_LOADUNIT]                     = { "load_unit",                NULL },
        [MAC_SELINUX_UNIT_ENABLE]                       = { "enable",                   "enable" },
        [MAC_SELINUX_UNIT_REENABLE]                     = { "reenable",                 "enable" },
        [MAC_SELINUX_UNIT_LINK]                         = { "link",                     NULL },
        [MAC_SELINUX_UNIT_PRESET]                       = { "preset",                   "reload" },
        [MAC_SELINUX_UNIT_MASK]                         = { "mask",                     "disable" },
        [MAC_SELINUX_UNIT_DISABLE]                      = { "disable",                  "disable" },
        [MAC_SELINUX_UNIT_UNMASK]                       = { "unmask",                   "enable" },
        [MAC_SELINUX_UNIT_REVERT]                       = { "revert",                   "reload" },
        [MAC_SELINUX_UNIT_ADDDEPENDENCY]                = { "add_dependency",           "reload" },
        [MAC_SELINUX_UNIT_GETUNITFILELINKS]             = { "get_unit_file_links",      "status" },
};

int _mac_selinux_instance_access_check_internal(
                sd_bus_message *message,
                mac_selinux_instance_permission permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *verb;

        assert(message);
        assert(permission >= 0);
        assert(permission < _MAC_SELINUX_INSTANCE_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_instance_class;
                verb = mac_selinux_instance_permissions[permission].overhaul;
        } else {
                class = mac_selinux_original_instance_class;
                verb = mac_selinux_instance_permissions[permission].original;
        }

        /* skip check if variant does not serve permission */
        if (!verb) {
                log_debug("SELinux access check skipped (overhaul=%d func=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, NULL, class, verb, error, func);
}

int _mac_selinux_unit_access_check_internal(
                const Unit *unit,
                sd_bus_message *message,
                mac_selinux_unit_permission permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *verb;
        const char *path;

        assert(unit);
        assert(message);
        assert(permission >= 0);
        assert(permission < _MAC_SELINUX_UNIT_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        path = unit_label_path(unit);

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_unit_class;
                verb = mac_selinux_unit_permissions[permission].overhaul;
        } else {
                class = path ? mac_selinux_original_unit_class : mac_selinux_original_instance_class;
                verb = mac_selinux_unit_permissions[permission].original;
        }

        /* skip check if variant does not serve permission */
        if (!verb) {
                log_debug("SELinux unit access check skipped (overhaul=%d func=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, path, class, verb, error, func);
}

int mac_selinux_unit_callback_check(
                const char *unit_name,
                const MacUnitCallbackUserdata *userdata) {

        const Unit *u;
        const char *path = NULL;

        assert(unit_name);
        assert(userdata);
        assert(userdata->manager);
        assert(userdata->message);
        assert(userdata->error);
        assert(userdata->func);
        assert(userdata->selinux_permission >= 0);
        assert(userdata->selinux_permission < _MAC_SELINUX_UNIT_PERMISSION_MAX);

        if (!mac_selinux_use())
                return 0;

        u = manager_get_unit(userdata->manager, unit_name);
        if (u)
                path = unit_label_path(u);

        /* maybe the unit is not loaded, e.g. a disabled user session unit */
        if (!path)
                path = manager_lookup_unit_label_path(userdata->manager, unit_name);

        return mac_selinux_generic_access_check(
                        userdata->message,
                        path,
                        mac_selinux_overhaul_unit_class,
                        mac_selinux_unit_permissions[userdata->selinux_permission].overhaul,
                        userdata->error,
                        userdata->func);
}

#endif
