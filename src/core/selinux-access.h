/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "manager.h"
#include "sd-bus.h"

typedef enum mac_selinux_instance_permission {
        MAC_SELINUX_INSTANCE_STARTTRANSIENT,
        MAC_SELINUX_INSTANCE_CLEARJOBS,
        MAC_SELINUX_INSTANCE_RESETFAILED,
        MAC_SELINUX_INSTANCE_LISTUNITS,
        MAC_SELINUX_INSTANCE_LISTJOBS,
        MAC_SELINUX_INSTANCE_SUBSCRIBE,
        MAC_SELINUX_INSTANCE_UNSUBSCRIBE,
        MAC_SELINUX_INSTANCE_DUMP,
        MAC_SELINUX_INSTANCE_RELOAD,
        MAC_SELINUX_INSTANCE_REEXECUTE,
        MAC_SELINUX_INSTANCE_EXIT,
        MAC_SELINUX_INSTANCE_REBOOT,
        MAC_SELINUX_INSTANCE_POWEROFFORHALT,
        MAC_SELINUX_INSTANCE_POWEROFF = MAC_SELINUX_INSTANCE_POWEROFFORHALT,
        MAC_SELINUX_INSTANCE_HALT = MAC_SELINUX_INSTANCE_POWEROFFORHALT,
        MAC_SELINUX_INSTANCE_KEXEC,
        MAC_SELINUX_INSTANCE_SWITCHROOT,
        MAC_SELINUX_INSTANCE_SETENVIRONMENT,
        MAC_SELINUX_INSTANCE_UNSETANDSETENVIRONMENT = MAC_SELINUX_INSTANCE_SETENVIRONMENT,
        MAC_SELINUX_INSTANCE_UNSETENVIRONMENT,
        MAC_SELINUX_INSTANCE_SETEXITCODE,
        MAC_SELINUX_INSTANCE_LISTUNITFILES,
        MAC_SELINUX_INSTANCE_STATEUNITFILE,
        MAC_SELINUX_INSTANCE_GETDEFAULTTARGET,
        MAC_SELINUX_INSTANCE_SETDEFAULTTARGET,
        MAC_SELINUX_INSTANCE_PRESETALLUNITFILES,
        MAC_SELINUX_INSTANCE_RAWSET,
        MAC_SELINUX_INSTANCE_RAWSTATUS,
        MAC_SELINUX_INSTANCE_ENQUEUEMARKEDJOBS,
        MAC_SELINUX_INSTANCE_SETLOGTARGET,
        MAC_SELINUX_INSTANCE_SETLOGLEVEL,
        MAC_SELINUX_INSTANCE_GETUNITFILELINKS,
        MAC_SELINUX_INSTANCE_ADDDEPENDENCYUNITFILES,
        MAC_SELINUX_INSTANCE_GETDYNAMICUSERS,
        MAC_SELINUX_INSTANCE_SETWATCHDOG,

        _MAC_SELINUX_INSTANCE_PERMISSION_MAX
} mac_selinux_instance_permission;
/* SELinux supports only 32 permissions per class */
assert_cc(_MAC_SELINUX_INSTANCE_PERMISSION_MAX <= 32);

typedef enum mac_selinux_unit_permission {
        MAC_SELINUX_UNIT_GETJOB,
        MAC_SELINUX_UNIT_GETUNIT,
        MAC_SELINUX_UNIT_START,
        MAC_SELINUX_UNIT_THAW = MAC_SELINUX_UNIT_START,
        MAC_SELINUX_UNIT_VERIFYACTIVE = MAC_SELINUX_UNIT_START,
        MAC_SELINUX_UNIT_STOP,
        MAC_SELINUX_UNIT_FREEZE = MAC_SELINUX_UNIT_STOP,
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
        MAC_SELINUX_UNIT_BINDMOUNT,
        MAC_SELINUX_UNIT_GETWAITING_JOBS,
        MAC_SELINUX_UNIT_UNREF,
        MAC_SELINUX_UNIT_LOADUNIT,

        _MAC_SELINUX_UNIT_PERMISSION_MAX
} mac_selinux_unit_permission;
/* SELinux supports only 32 permissions per class */
assert_cc(_MAC_SELINUX_UNIT_PERMISSION_MAX <= 32);

#if HAVE_SELINUX

int _mac_selinux_instance_access_check_internal(
                sd_bus_message *message,
                mac_selinux_instance_permission permission,
                sd_bus_error *error,
                const char *func);

#define mac_selinux_instance_access_check(message, permission, error) \
        _mac_selinux_instance_access_check_internal((message), (permission), (error), __func__)

int _mac_selinux_unit_access_check_internal(
                const Unit *unit,
                sd_bus_message *message,
                mac_selinux_unit_permission permission,
                sd_bus_error *error,
                const char *func);

#define mac_selinux_unit_access_check(unit, message, permission, error) \
        _mac_selinux_unit_access_check_internal((unit), (message), (permission), (error), __func__)

#else

static inline int mac_selinux_instance_access_check(
                sd_bus_message *message,
                mac_selinux_instance_permission permission,
                sd_bus_error *error) {
        return 0;
}

static inline int mac_selinux_unit_access_check(
                const Unit *unit,
                sd_bus_message *message,
                mac_selinux_unit_permission permission,
                sd_bus_error *error) {
        return 0;
}

#endif
