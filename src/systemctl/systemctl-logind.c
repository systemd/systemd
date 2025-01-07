/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-login.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "login-util.h"
#include "mountpoint-util.h"
#include "process-util.h"
#include "systemctl-logind.h"
#include "systemctl-start-unit.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "user-util.h"

static int logind_set_wall_message(sd_bus *bus) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *m = NULL;
        int r;

        assert(bus);

        m = strv_join(arg_wall, " ");
        if (!m)
                return log_oom();

        log_debug("%s wall message \"%s\".", arg_dry_run ? "Would set" : "Setting", m);
        if (arg_dry_run)
                return 0;

        r = bus_call_method(bus, bus_login_mgr, "SetWallMessage", &error, NULL, "sb", m, !arg_no_wall);
        if (r < 0)
                return log_warning_errno(r, "Failed to set wall message, ignoring: %s", bus_error_message(&error, r));
#endif
        return 0;
}

/* Ask systemd-logind, which might grant access to unprivileged users through polkit */
int logind_reboot(enum action a) {
#if ENABLE_LOGIND
        static const char* actions[_ACTION_MAX] = {
                [ACTION_POWEROFF]               = "PowerOff",
                [ACTION_REBOOT]                 = "Reboot",
                [ACTION_KEXEC]                  = "Reboot",
                [ACTION_SOFT_REBOOT]            = "Reboot",
                [ACTION_HALT]                   = "Halt",
                [ACTION_SUSPEND]                = "Suspend",
                [ACTION_HIBERNATE]              = "Hibernate",
                [ACTION_HYBRID_SLEEP]           = "HybridSleep",
                [ACTION_SUSPEND_THEN_HIBERNATE] = "SuspendThenHibernate",
                [ACTION_SLEEP]                  = "Sleep",
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        uint64_t flags = 0;
        sd_bus *bus;
        int r;

        assert(a >= 0);
        assert(a < _ACTION_MAX);

        if (!actions[a])
                return -EINVAL;

        r = acquire_bus_full(BUS_FULL, /* graceful = */ true, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();
        (void) logind_set_wall_message(bus);

        const char *method_with_flags = a == ACTION_SLEEP ? actions[a] : strjoina(actions[a], "WithFlags");

        log_debug("%s org.freedesktop.login1.Manager %s dbus call.",
                  arg_dry_run ? "Would execute" : "Executing", method_with_flags);

        if (arg_dry_run)
                return 0;

        SET_FLAG(flags, SD_LOGIND_ROOT_CHECK_INHIBITORS, arg_check_inhibitors > 0);
        SET_FLAG(flags, SD_LOGIND_SKIP_INHIBITORS, arg_check_inhibitors == 0);
        SET_FLAG(flags,
                 SD_LOGIND_REBOOT_VIA_KEXEC,
                 a == ACTION_KEXEC || (a == ACTION_REBOOT && getenv_bool("SYSTEMCTL_SKIP_AUTO_KEXEC") <= 0));
        /* Try to soft-reboot if /run/nextroot/ is a valid OS tree, but only if it's also a mount point.
         * Otherwise, if people store new rootfs directly on /run/ tmpfs, 'systemctl reboot' would always
         * soft-reboot, as /run/nextroot/ can never go away. */
        SET_FLAG(flags,
                 SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP,
                 a == ACTION_REBOOT && getenv_bool("SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT") <= 0 && path_is_mount_point("/run/nextroot") > 0);
        SET_FLAG(flags, SD_LOGIND_SOFT_REBOOT, a == ACTION_SOFT_REBOOT);

        r = bus_call_method(bus, bus_login_mgr, method_with_flags, &error, NULL, "t", flags);
        if (r < 0 && FLAGS_SET(flags, SD_LOGIND_SKIP_INHIBITORS) &&
                        sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS)) {
                sd_bus_error_free(&error);
                flags &= ~SD_LOGIND_SKIP_INHIBITORS;
                r = bus_call_method(bus, bus_login_mgr, method_with_flags, &error, NULL, "t", flags);
        }
        if (r < 0 && FLAGS_SET(flags, SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP) &&
                        sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS)) {
                sd_bus_error_free(&error);
                flags &= ~SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP;
                r = bus_call_method(bus, bus_login_mgr, method_with_flags, &error, NULL, "t", flags);
        }
        if (r >= 0)
                return 0;
        if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD) || a == ACTION_SLEEP)
                return log_error_errno(r, "Call to %s failed: %s", actions[a], bus_error_message(&error, r));

        /* Fall back to original methods in case there is an older version of systemd-logind */
        log_debug("Method %s not available: %s. Falling back to %s", method_with_flags, bus_error_message(&error, r), actions[a]);
        sd_bus_error_free(&error);

        r = bus_call_method(bus, bus_login_mgr, actions[a], &error, NULL, "b", arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Call to %s failed: %s", actions[a], bus_error_message(&error, r));

        return 0;
#else
        return -ENOSYS;
#endif
}

int logind_check_inhibitors(enum action a) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **sessions = NULL;
        const char *what, *who, *why, *mode;
        uint32_t uid, pid;
        sd_bus *bus;
        unsigned c = 0;
        int r;

        assert(a >= 0);
        assert(a < _ACTION_MAX);

        if (arg_check_inhibitors == 0 || arg_force > 0)
                return 0;

        if (arg_when > 0)
                return 0;

        if (arg_check_inhibitors < 0 && !on_tty())
                return 0;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return 0;

        r = acquire_bus_full(BUS_FULL, /* graceful = */ true, &bus);
        if ((ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT) && geteuid() == 0)
                return 0; /* When D-Bus is not running (ECONNREFUSED) or D-Bus socket is not created (ENOENT),
                           * allow root to force a shutdown. E.g. when running at the emergency console. */
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_login_mgr, "ListInhibitors", NULL, &reply, NULL);
        if (r < 0)
                /* If logind is not around, then there are no inhibitors... */
                return 0;

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssuu)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ssssuu)", &what, &who, &why, &mode, &uid, &pid)) > 0) {
                _cleanup_free_ char *comm = NULL, *user = NULL;
                _cleanup_strv_free_ char **sv = NULL;

                if (!STR_IN_SET(mode, "block", "block-weak"))
                        continue;

                if (streq(mode, "block-weak") && (geteuid() == 0 || geteuid() == uid || !on_tty()))
                        continue;

                sv = strv_split(what, ":");
                if (!sv)
                        return log_oom();

                if (!pid_is_valid((pid_t) pid))
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Invalid PID "PID_FMT".", (pid_t) pid);

                if (!strv_contains(sv,
                                   IN_SET(a,
                                          ACTION_HALT,
                                          ACTION_POWEROFF,
                                          ACTION_REBOOT,
                                          ACTION_KEXEC) ? "shutdown" : "sleep"))
                        continue;

                (void) pid_get_comm(pid, &comm);
                user = uid_to_name(uid);

                log_warning("Operation inhibited by \"%s\" (PID "PID_FMT" \"%s\", user %s), reason is \"%s\".",
                            who, (pid_t) pid, strna(comm), strna(user), why);

                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        /* root respects inhibitors since v257 but keeps ignoring sessions by default */
        if (arg_check_inhibitors < 0 && c == 0 && geteuid() == 0)
                return 0;

        /* Check for current sessions */
        sd_get_sessions(&sessions);
        STRV_FOREACH(s, sessions) {
                _cleanup_free_ char *type = NULL, *tty = NULL, *seat = NULL, *user = NULL, *service = NULL, *class = NULL;

                if (sd_session_get_uid(*s, &uid) < 0 || uid == getuid())
                        continue;

                if (sd_session_get_class(*s, &class) < 0 || !streq(class, "user"))
                        continue;

                if (sd_session_get_type(*s, &type) < 0 || !STR_IN_SET(type, "x11", "wayland", "tty", "mir"))
                        continue;

                sd_session_get_tty(*s, &tty);
                sd_session_get_seat(*s, &seat);
                sd_session_get_service(*s, &service);
                user = uid_to_name(uid);

                log_warning("User %s is logged in on %s.", strna(user), isempty(tty) ? (isempty(seat) ? strna(service) : seat) : tty);
                c++;
        }

        if (c <= 0)
                return 0;

        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                               "Please retry operation after closing inhibitors and logging out other users.\n"
                               "'systemd-inhibit' can be used to list active inhibitors.\n"
                               "Alternatively, ignore inhibitors and users with 'systemctl %s -i'.",
                               action_table[a].verb);
#else
        return 0;
#endif
}

int prepare_firmware_setup(void) {

        if (!arg_firmware_setup)
                return 0;

#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_login_mgr, "SetRebootToFirmwareSetup", &error, NULL, "b", true);
        if (r < 0)
                return log_error_errno(r, "Cannot indicate to EFI to boot into setup mode: %s", bus_error_message(&error, r));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Booting into firmware setup not supported.");
#endif
}

int prepare_boot_loader_menu(void) {

        if (arg_boot_loader_menu == USEC_INFINITY)
                return 0;

#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_login_mgr, "SetRebootToBootLoaderMenu", &error, NULL, "t", arg_boot_loader_menu);
        if (r < 0)
                return log_error_errno(r, "Cannot indicate to boot loader to enter boot loader entry menu: %s", bus_error_message(&error, r));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Booting into boot loader menu not supported.");
#endif
}

int prepare_boot_loader_entry(void) {

        if (!arg_boot_loader_entry)
                return 0;

#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_login_mgr, "SetRebootToBootLoaderEntry", &error, NULL, "s", arg_boot_loader_entry);
        if (r < 0)
                return log_error_errno(r, "Cannot set boot into loader entry '%s': %s", arg_boot_loader_entry, bus_error_message(&error, r));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Booting into boot loader entry not supported.");
#endif
}

int logind_schedule_shutdown(enum action a) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *action;
        sd_bus *bus;
        int r;

        assert(a >= 0);
        assert(a < _ACTION_MAX);

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        action = action_table[a].verb;
        if (!action)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Scheduling not supported for this action.");

        if (arg_dry_run)
                action = strjoina("dry-", action);

        (void) logind_set_wall_message(bus);

        r = bus_call_method(bus, bus_login_mgr, "ScheduleShutdown", &error, NULL, "st", action, arg_when);
        if (r < 0)
                return log_warning_errno(r, "Failed to schedule shutdown: %s", bus_error_message(&error, r));

        if (!arg_quiet)
                logind_show_shutdown();

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Cannot schedule shutdown without logind support, proceeding with immediate shutdown.");
#endif
}

int logind_cancel_shutdown(void) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        (void) logind_set_wall_message(bus);

        r = bus_call_method(bus, bus_login_mgr, "CancelScheduledShutdown", &error, NULL, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to talk to logind, shutdown hasn't been cancelled: %s", bus_error_message(&error, r));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Not compiled with logind support, cannot cancel scheduled shutdowns.");
#endif
}

int logind_show_shutdown(void) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        sd_bus *bus;
        const char *action, *pretty_action;
        uint64_t elapse;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_get_property(bus, bus_login_mgr, "ScheduledShutdown", &error, &reply, "(st)");
        if (r < 0)
                return log_error_errno(r, "Failed to query scheduled shutdown: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "(st)", &action, &elapse);
        if (r < 0)
                return r;

        if (isempty(action))
                return log_full_errno(arg_quiet ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ENODATA), "No scheduled shutdown.");

        if (STR_IN_SET(action, "halt", "poweroff", "exit"))
                pretty_action = "Shutdown";
        else if (streq(action, "kexec"))
                pretty_action = "Reboot via kexec";
        else if (streq(action, "reboot"))
                pretty_action = "Reboot";
        else /* If we don't recognize the action string, we'll show it as-is */
                pretty_action = action;

        if (IN_SET(arg_action, ACTION_SYSTEMCTL, ACTION_SYSTEMCTL_SHOW_SHUTDOWN))
                log_info("%s scheduled for %s, use 'systemctl %s --when=cancel' to cancel.",
                         pretty_action,
                         FORMAT_TIMESTAMP_STYLE(elapse, arg_timestamp_style),
                         action);
        else
                log_info("%s scheduled for %s, use 'shutdown -c' to cancel.",
                         pretty_action,
                         FORMAT_TIMESTAMP_STYLE(elapse, arg_timestamp_style));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Not compiled with logind support, cannot show scheduled shutdowns.");
#endif
}

int help_boot_loader_entry(void) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **l = NULL;
        sd_bus *bus;
        int r;

        /* This is called without checking runtime scope and bus transport like we do in parse_argv().
         * Loading boot entries is only supported by system scope. Let's gracefully adjust them. */
        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
        if (arg_transport == BUS_TRANSPORT_CAPSULE) {
                arg_host = NULL;
                arg_transport = BUS_TRANSPORT_LOCAL;
        }

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_get_property_strv(bus, bus_login_mgr, "BootLoaderEntries", &error, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate boot loader entries: %s", bus_error_message(&error, r));

        if (strv_isempty(l))
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "No boot loader entries discovered.");

        STRV_FOREACH(i, l)
                puts(*i);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Not compiled with logind support, cannot display boot loader entries.");
#endif
}
