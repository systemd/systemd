/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"
#include "manager.h"
#include "sd-bus.h"

enum mac_selinux_pidone_permissions {
        MAC_SELINUX_PIDONE_STARTTRANSIENT,
        MAC_SELINUX_PIDONE_CLEARJOBS,
        MAC_SELINUX_PIDONE_RESETFAILED,
        MAC_SELINUX_PIDONE_LISTUNITS,
        MAC_SELINUX_PIDONE_LISTJOBS,
        MAC_SELINUX_PIDONE_SUBSCRIBE,
        MAC_SELINUX_PIDONE_UNSUBSCRIBE,
        MAC_SELINUX_PIDONE_DUMP,
        MAC_SELINUX_PIDONE_RELOAD,
        MAC_SELINUX_PIDONE_REEXECUTE,
        MAC_SELINUX_PIDONE_EXIT,
        MAC_SELINUX_PIDONE_REBOOT,
        MAC_SELINUX_PIDONE_POWEROFFORHALT,
        MAC_SELINUX_PIDONE_POWEROFF = MAC_SELINUX_PIDONE_POWEROFFORHALT,
        MAC_SELINUX_PIDONE_HALT = MAC_SELINUX_PIDONE_POWEROFFORHALT,
        MAC_SELINUX_PIDONE_KEXEC,
        MAC_SELINUX_PIDONE_SWITCHROOT,
        MAC_SELINUX_PIDONE_SETENVIRONMENT,
        MAC_SELINUX_PIDONE_UNSETANDSETENVIRONMENT = MAC_SELINUX_PIDONE_SETENVIRONMENT,
        MAC_SELINUX_PIDONE_UNSETENVIRONMENT,
        MAC_SELINUX_PIDONE_SETEXITCODE,
        MAC_SELINUX_PIDONE_LISTUNITFILES,
        MAC_SELINUX_PIDONE_STATEUNITFILE,
        MAC_SELINUX_PIDONE_GETDEFAULTTARGET,
        MAC_SELINUX_PIDONE_SETDEFAULTTARGET,
        MAC_SELINUX_PIDONE_PRESETALLUNITFILES,
        MAC_SELINUX_PIDONE_RAWSET,
        MAC_SELINUX_PIDONE_RAWSTATUS,

        MAC_SELINUX_PIDONE_PERMISSION_MAX
};
assert_cc(MAC_SELINUX_PIDONE_PERMISSION_MAX <= 32);

enum mac_selinux_unit_permissions {
        MAC_SELINUX_UNIT_GETJOB,
        MAC_SELINUX_UNIT_GETUNIT,
        MAC_SELINUX_UNIT_START,
        MAC_SELINUX_UNIT_VERIFYACTIVE,
        MAC_SELINUX_UNIT_STOP,
        MAC_SELINUX_UNIT_RELOAD,
        MAC_SELINUX_UNIT_TRYRELOAD = MAC_SELINUX_UNIT_RELOAD,
        MAC_SELINUX_UNIT_RELOADORSTART = MAC_SELINUX_UNIT_RELOAD,
        MAC_SELINUX_UNIT_RESTART,
        MAC_SELINUX_UNIT_TRYRESTART = MAC_SELINUX_UNIT_RESTART,
        MAC_SELINUX_UNIT_NOP,
        MAC_SELINUX_UNIT_CANCEL,
        MAC_SELINUX_UNIT_ABANDON,
        MAC_SELINUX_UNIT_KILL,
        MAC_SELINUX_UNIT_RESETFAILED,
        MAC_SELINUX_UNIT_SETPROPERTIES,
        MAC_SELINUX_UNIT_REF,
        MAC_SELINUX_UNIT_CLEAN,
        MAC_SELINUX_UNIT_GETPROCESSES,
        MAC_SELINUX_UNIT_ATTACHPROCESSES,
        MAC_SELINUX_UNIT_RAWSET,
        MAC_SELINUX_UNIT_RAWSTATUS,

        MAC_SELINUX_UNIT_PERMISSION_MAX
};
assert_cc(MAC_SELINUX_UNIT_PERMISSION_MAX <= 32);

#if HAVE_SELINUX

int mac_selinux_access_check(
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_pidone_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func);

int mac_selinux_unit_access_check(
                const Unit *unit,
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_unit_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func);

#else

_const_ static inline int mac_selinux_access_check(
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_pidone_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func) {
        return 0;
}

_const_ static inline int mac_selinux_unit_access_check(
                const Unit *unit,
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_unit_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func) {
        return 0;
}

#endif
