/* SPDX-License-Identifier: LGPL-2.1+ */

#include "logind-selinux-access.h"

#if HAVE_SELINUX

#include "selinux-generic-access.h"

const char *const mac_selinux_logind_class[] = {
        "systemd_logind",
        "systemd_logind2",
};
/* assert that we have enough classes for the number of permission we have
 * (SELinux only supports 32 permission per class) */
assert_cc(_MAC_SELINUX_LOGIND_PERMISSION_MAX <= (32 * ELEMENTSOF(mac_selinux_logind_class)));

const char *const mac_selinux_logind_permissions[_MAC_SELINUX_LOGIND_PERMISSION_MAX] = {
        [MAC_SELINUX_LOGIND_RAWSET]                     = "raw_set",
        [MAC_SELINUX_LOGIND_RAWSTATUS]                  = "raw_status",
        [MAC_SELINUX_LOGIND_GETSESSION]                 = "get_session",
        [MAC_SELINUX_LOGIND_GETUSER]                    = "get_user",
        [MAC_SELINUX_LOGIND_GETSEAT]                    = "get_seat",
        [MAC_SELINUX_LOGIND_LISTSESSIONS]               = "list_sessions",
        [MAC_SELINUX_LOGIND_LISTUSERS]                  = "list_users",
        [MAC_SELINUX_LOGIND_LISTSEATS]                  = "list_seats",
        [MAC_SELINUX_LOGIND_LISTINHIBITORS]             = "list_inhibitors",
        [MAC_SELINUX_LOGIND_CREATESESSION]              = "create_session",
        [MAC_SELINUX_LOGIND_RELEASESESSION]             = "release_session",
        [MAC_SELINUX_LOGIND_ACTIVATESESSION]            = "activate_session",
        [MAC_SELINUX_LOGIND_LOCKSESSION]                = "lock_session",
        [MAC_SELINUX_LOGIND_LOCKSESSIONS]               = "lock_all_sessions",
        [MAC_SELINUX_LOGIND_TERMINATESESSION]           = "terminate_session",
        [MAC_SELINUX_LOGIND_TERMINATEUSER]              = "terminate_user",
        [MAC_SELINUX_LOGIND_TERMINATESEAT]              = "terminate_seat",
        [MAC_SELINUX_LOGIND_SETUSERLINGER]              = "set_user_linger",
        [MAC_SELINUX_LOGIND_ATTACHDEVICE]               = "attach_device",
        [MAC_SELINUX_LOGIND_FLUSHDEVICES]               = "flush_devices",
        [MAC_SELINUX_LOGIND_REBOOT]                     = "reboot",
        [MAC_SELINUX_LOGIND_HALT]                       = "halt",
        [MAC_SELINUX_LOGIND_SCHEDULESHUTDOWN]           = "schedule_shutdown",
        [MAC_SELINUX_LOGIND_CANCELSCHEDULEDSHUTDOWN]    = "cancel_scheduled_shutdown",
        [MAC_SELINUX_LOGIND_SETREBOOTPARAMETER]         = "set_reboot_parameter",
        [MAC_SELINUX_LOGIND_SETREBOOTTOFIRMWARESETUP]   = "set_reboot_to_firmware_setup",
        [MAC_SELINUX_LOGIND_SETREBOOTTOBOOTLOADERMENU]  = "set_reboot_to_bootloader_menu",
        [MAC_SELINUX_LOGIND_SETREBOOTTOBOOTLOADERENTRY] = "set_reboot_to_bootloader_entry",
        [MAC_SELINUX_LOGIND_SETWALLMESSAGE]             = "set_wall_message",
        [MAC_SELINUX_LOGIND_INHIBIT]                    = "inhibit",
        [MAC_SELINUX_LOGIND_SWITCHSEATTO]               = "switch_seat",
        [MAC_SELINUX_LOGIND_SETIDLEHINT]                = "set_idle_hint",
        [MAC_SELINUX_LOGIND_SETLOCKEDHINT]              = "set_locked_hint",
        [MAC_SELINUX_LOGIND_TAKECONTROL]                = "take_control",
        [MAC_SELINUX_LOGIND_RELEASECONTROL]             = "release_control",
        [MAC_SELINUX_LOGIND_TAKEDEVICE]                 = "take_device",
        [MAC_SELINUX_LOGIND_RELEASEDEVICE]              = "release_device",
        [MAC_SELINUX_LOGIND_PAUSEDEVICECOMPLETE]        = "pause_device_complete",
        [MAC_SELINUX_LOGIND_SETBRIGHTNESS]              = "set_brightness",
};

int _mac_selinux_logind_access_check_internal(
                sd_bus_message *message,
                mac_selinux_logind_permission permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *permission_str;
        unsigned short i = 0;

        assert(message);
        assert(permission >= 0);
        assert(permission < _MAC_SELINUX_LOGIND_PERMISSION_MAX);
        assert(error);
        assert(func);

        permission_str = mac_selinux_logind_permissions[permission];

        /* compute the class to use */
        while (permission >= 32) {
                permission -= 32;
                ++i;
        }
        assert(i < ELEMENTSOF(mac_selinux_logind_class));
        class = mac_selinux_logind_class[i];

        /* mac_selinux_generic_access_check() does a mac_selinux_use() check */
        return mac_selinux_generic_access_check(message, NULL, class, permission_str, error, func);
}

#endif /* HAVE_SELINUX */
