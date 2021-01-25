/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-login.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "login-util.h"
#include "process-util.h"
#include "systemctl-logind.h"
#include "systemctl-start-unit.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "user-util.h"

int logind_set_wall_message(void) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        _cleanup_free_ char *m = NULL;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

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
        static const struct {
                const char *method;
                const char *description;
        } actions[_ACTION_MAX] = {
                [ACTION_POWEROFF]               = { "PowerOff",             "power off system"                },
                [ACTION_REBOOT]                 = { "Reboot",               "reboot system"                   },
                [ACTION_HALT]                   = { "Halt",                 "halt system"                     },
                [ACTION_SUSPEND]                = { "Suspend",              "suspend system"                  },
                [ACTION_HIBERNATE]              = { "Hibernate",            "hibernate system"                },
                [ACTION_HYBRID_SLEEP]           = { "HybridSleep",          "put system into hybrid sleep"    },
                [ACTION_SUSPEND_THEN_HIBERNATE] = { "SuspendThenHibernate", "suspend system, hibernate later" },
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *method_with_flags;
        uint64_t flags = 0;
        sd_bus *bus;
        int r;

        if (a < 0 || a >= _ACTION_MAX || !actions[a].method)
                return -EINVAL;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();
        (void) logind_set_wall_message();

        log_debug("%s org.freedesktop.login1.Manager %s dbus call.", arg_dry_run ? "Would execute" : "Executing", actions[a].method);

        if (arg_dry_run)
                return 0;

        SET_FLAG(flags, SD_LOGIND_ROOT_CHECK_INHIBITORS, arg_check_inhibitors > 0);

        method_with_flags = strjoina(actions[a].method, "WithFlags");

        r = bus_call_method(bus, bus_login_mgr, method_with_flags, &error, NULL, "t", flags);
        if (r >= 0)
                return 0;
        if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                return log_error_errno(r, "Failed to %s via logind: %s", actions[a].description, bus_error_message(&error, r));

        /* Fallback to original methods in case there is older version of systemd-logind */
        log_debug("Method %s not available: %s. Falling back to %s", method_with_flags, bus_error_message(&error, r), actions[a].method);
        sd_bus_error_free(&error);

        r = bus_call_method(bus, bus_login_mgr, actions[a].method, &error, NULL, "b", arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Failed to %s via logind: %s", actions[a].description, bus_error_message(&error, r));

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
        char **s;
        int r;

        if (arg_check_inhibitors == 0 || arg_force > 0)
                return 0;

        if (arg_when > 0)
                return 0;

        if (arg_check_inhibitors < 0) {
                if (geteuid() == 0)
                        return 0;

                if (!on_tty())
                        return 0;
        }

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return 0;

        r = acquire_bus(BUS_FULL, &bus);
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

                if (!streq(mode, "block"))
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

                (void) get_process_comm(pid, &comm);
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

int logind_schedule_shutdown(void) {

#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char date[FORMAT_TIMESTAMP_MAX];
        const char *action;
        const char *log_action;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        switch (arg_action) {
        case ACTION_HALT:
                action = "halt";
                log_action = "Shutdown";
                break;
        case ACTION_POWEROFF:
                action = "poweroff";
                log_action = "Shutdown";
                break;
        case ACTION_KEXEC:
                action = "kexec";
                log_action = "Reboot via kexec";
                break;
        case ACTION_EXIT:
                action = "exit";
                log_action = "Shutdown";
                break;
        case ACTION_REBOOT:
        default:
                action = "reboot";
                log_action = "Reboot";
                break;
        }

        if (arg_dry_run)
                action = strjoina("dry-", action);

        (void) logind_set_wall_message();

        r = bus_call_method(bus, bus_login_mgr, "ScheduleShutdown", &error, NULL, "st", action, arg_when);
        if (r < 0)
                return log_warning_errno(r, "Failed to call ScheduleShutdown in logind, proceeding with immediate shutdown: %s", bus_error_message(&error, r));

        if (!arg_quiet)
                log_info("%s scheduled for %s, use 'shutdown -c' to cancel.", log_action, format_timestamp_style(date, sizeof(date), arg_when, arg_timestamp_style));
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

        (void) logind_set_wall_message();

        r = bus_call_method(bus, bus_login_mgr, "CancelScheduledShutdown", &error, NULL, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to talk to logind, shutdown hasn't been cancelled: %s", bus_error_message(&error, r));

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(ENOSYS),
                               "Not compiled with logind support, cannot cancel scheduled shutdowns.");
#endif
}

int help_boot_loader_entry(void) {
#if ENABLE_LOGIND
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **l = NULL;
        sd_bus *bus;
        char **i;
        int r;

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
