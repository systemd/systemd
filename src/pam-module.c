/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pwd.h>
#include <endian.h>
#include <sys/capability.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>

#include "util.h"
#include "macro.h"
#include "sd-daemon.h"
#include "strv.h"
#include "dbus-common.h"
#include "def.h"

static int parse_argv(pam_handle_t *handle,
                      int argc, const char **argv,
                      char ***controllers,
                      char ***reset_controllers,
                      bool *kill_processes,
                      char ***kill_only_users,
                      char ***kill_exclude_users,
                      bool *debug) {

        unsigned i;
        bool reset_controller_set = false;
        bool kill_exclude_users_set = false;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < (unsigned) argc; i++) {
                int k;

                if (startswith(argv[i], "kill-processes=")) {
                        if ((k = parse_boolean(argv[i] + 15)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse kill-processes= argument.");
                                return k;
                        }

                        if (kill_processes)
                                *kill_processes = k;

                } else if (startswith(argv[i], "kill-session=")) {
                        /* As compatibility for old versions */

                        if ((k = parse_boolean(argv[i] + 13)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse kill-session= argument.");
                                return k;
                        }

                        if (kill_processes)
                                *kill_processes = k;

                } else if (startswith(argv[i], "controllers=")) {

                        if (controllers) {
                                char **l;

                                if (!(l = strv_split(argv[i] + 12, ","))) {
                                        pam_syslog(handle, LOG_ERR, "Out of memory.");
                                        return -ENOMEM;
                                }

                                strv_free(*controllers);
                                *controllers = l;
                        }

                } else if (startswith(argv[i], "reset-controllers=")) {

                        if (reset_controllers) {
                                char **l;

                                if (!(l = strv_split(argv[i] + 18, ","))) {
                                        pam_syslog(handle, LOG_ERR, "Out of memory.");
                                        return -ENOMEM;
                                }

                                strv_free(*reset_controllers);
                                *reset_controllers = l;
                        }

                        reset_controller_set = true;

                } else if (startswith(argv[i], "kill-only-users=")) {

                        if (kill_only_users) {
                                char **l;

                                if (!(l = strv_split(argv[i] + 16, ","))) {
                                        pam_syslog(handle, LOG_ERR, "Out of memory.");
                                        return -ENOMEM;
                                }

                                strv_free(*kill_only_users);
                                *kill_only_users = l;
                        }

                } else if (startswith(argv[i], "kill-exclude-users=")) {

                        if (kill_exclude_users) {
                                char **l;

                                if (!(l = strv_split(argv[i] + 19, ","))) {
                                        pam_syslog(handle, LOG_ERR, "Out of memory.");
                                        return -ENOMEM;
                                }

                                strv_free(*kill_exclude_users);
                                *kill_exclude_users = l;
                        }

                        kill_exclude_users_set = true;

                } else if (startswith(argv[i], "debug=")) {
                        if ((k = parse_boolean(argv[i] + 6)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse debug= argument.");
                                return k;
                        }

                        if (debug)
                                *debug = k;

                } else if (startswith(argv[i], "create-session=") ||
                           startswith(argv[i], "kill-user=")) {

                        pam_syslog(handle, LOG_WARNING, "Option %s not supported anymore, ignoring.", argv[i]);

                } else {
                        pam_syslog(handle, LOG_ERR, "Unknown parameter '%s'.", argv[i]);
                        return -EINVAL;
                }
        }

        if (!reset_controller_set && reset_controllers) {
                char **l;

                if (!(l = strv_new("cpu", NULL))) {
                        pam_syslog(handle, LOG_ERR, "Out of memory");
                        return -ENOMEM;
                }

                *reset_controllers = l;
        }

        if (controllers)
                strv_remove(*controllers, SYSTEMD_CGROUP_CONTROLLER);

        if (reset_controllers)
                strv_remove(*reset_controllers, SYSTEMD_CGROUP_CONTROLLER);

        if (!kill_exclude_users_set && kill_exclude_users) {
                char **l;

                if (!(l = strv_new("root", NULL))) {
                        pam_syslog(handle, LOG_ERR, "Out of memory");
                        return -ENOMEM;
                }

                *kill_exclude_users = l;
        }

        return 0;
}

static int get_user_data(
                pam_handle_t *handle,
                const char **ret_username,
                struct passwd **ret_pw) {

        const char *username = NULL;
        struct passwd *pw = NULL;
        int r;
        bool have_loginuid = false;
        char *s;

        assert(handle);
        assert(ret_username);
        assert(ret_pw);

        if (have_effective_cap(CAP_AUDIT_CONTROL) > 0) {
                /* Only use audit login uid if we are executed with
                 * sufficient capabilities so that pam_loginuid could
                 * do its job. If we are lacking the CAP_AUDIT_CONTROL
                 * capabality we most likely are being run in a
                 * container and /proc/self/loginuid is useless since
                 * it probably contains a uid of the host system. */

                if (read_one_line_file("/proc/self/loginuid", &s) >= 0) {
                        uint32_t u;

                        r = safe_atou32(s, &u);
                        free(s);

                        if (r >= 0 && u != (uint32_t) -1 && u > 0) {
                                have_loginuid = true;
                                pw = pam_modutil_getpwuid(handle, u);
                        }
                }
        }

        if (!have_loginuid) {
                if ((r = pam_get_user(handle, &username, NULL)) != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to get user name.");
                        return r;
                }

                if (!username || !*username) {
                        pam_syslog(handle, LOG_ERR, "User name not valid.");
                        return PAM_AUTH_ERR;
                }

                pw = pam_modutil_getpwnam(handle, username);
        }

        if (!pw) {
                pam_syslog(handle, LOG_ERR, "Failed to get user data.");
                return PAM_USER_UNKNOWN;
        }

        *ret_pw = pw;
        *ret_username = username ? username : pw->pw_name;

        return PAM_SUCCESS;
}

static bool check_user_lists(
                pam_handle_t *handle,
                uid_t uid,
                char **kill_only_users,
                char **kill_exclude_users) {

        const char *name = NULL;
        char **l;

        assert(handle);

        if (uid == 0)
                name = "root"; /* Avoid obvious NSS requests, to suppress network traffic */
        else {
                struct passwd *pw;

                pw = pam_modutil_getpwuid(handle, uid);
                if (pw)
                        name = pw->pw_name;
        }

        STRV_FOREACH(l, kill_exclude_users) {
                uint32_t id;

                if (safe_atou32(*l, &id) >= 0)
                        if ((uid_t) id == uid)
                                return false;

                if (name && streq(name, *l))
                        return false;
        }

        if (strv_isempty(kill_only_users))
                return true;

        STRV_FOREACH(l, kill_only_users) {
                uint32_t id;

                if (safe_atou32(*l, &id) >= 0)
                        if ((uid_t) id == uid)
                                return true;

                if (name && streq(name, *l))
                        return true;
        }

        return false;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        struct passwd *pw;
        bool kill_processes = false, debug = false;
        const char *username, *id, *object_path, *runtime_path, *service = NULL, *tty = NULL, *display = NULL, *remote_user = NULL, *remote_host = NULL, *seat = NULL, *type;
        char **controllers = NULL, **reset_controllers = NULL, **kill_only_users = NULL, **kill_exclude_users = NULL;
        DBusError error;
        uint32_t uid, pid;
        DBusMessageIter iter;
        dbus_bool_t kp;
        int session_fd = -1;
        DBusConnection *bus = NULL;
        DBusMessage *m = NULL, *reply = NULL;
        dbus_bool_t remote;
        int r;

        assert(handle);

        dbus_error_init(&error);

        /* pam_syslog(handle, LOG_INFO, "pam-systemd initializing"); */

        /* Make this a NOP on non-systemd systems */
        if (sd_booted() <= 0)
                return PAM_SUCCESS;

        if (parse_argv(handle,
                       argc, argv,
                       &controllers, &reset_controllers,
                       &kill_processes, &kill_only_users, &kill_exclude_users,
                       &debug) < 0) {
                r = PAM_SESSION_ERR;
                goto finish;
        }

        r = get_user_data(handle, &username, &pw);
        if (r != PAM_SUCCESS)
                goto finish;

        if (kill_processes)
                kill_processes = check_user_lists(handle, pw->pw_uid, kill_only_users, kill_exclude_users);

        dbus_connection_set_change_sigpipe(FALSE);

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!bus) {
                pam_syslog(handle, LOG_ERR, "Failed to connect to system bus: %s", bus_error_message(&error));
                r = PAM_SESSION_ERR;
                goto finish;
        }

        m = dbus_message_new_method_call(
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "CreateSession");

        if (!m) {
                pam_syslog(handle, LOG_ERR, "Could not allocate create session message.");
                r = PAM_BUF_ERR;
                goto finish;
        }

        uid = pw->pw_uid;
        pid = getpid();

        pam_get_item(handle, PAM_SERVICE, (const void**) &service);
        pam_get_item(handle, PAM_XDISPLAY, (const void**) &display);
        pam_get_item(handle, PAM_TTY, (const void**) &tty);
        pam_get_item(handle, PAM_RUSER, (const void**) &remote_user);
        pam_get_item(handle, PAM_RHOST, (const void**) &remote_host);
        seat = pam_getenv(handle, "XDG_SEAT");

        service = strempty(service);
        tty = strempty(tty);
        display = strempty(display);
        remote_user = strempty(remote_user);
        remote_host = strempty(remote_host);
        seat = strempty(seat);

        if (strchr(tty, ':')) {
                /* A tty with a colon is usually an X11 display, place
                 * there to show up in utmp. We rearrange things and
                 * don't pretend that an X display was a tty */

                if (isempty(display))
                        display = tty;
                tty = NULL;
        }

        type = !isempty(display) ? "x11" :
                   !isempty(tty) ? "tty" : "other";

        remote = !isempty(remote_host) && !streq(remote_host, "localhost") && !streq(remote_host, "localhost.localdomain");

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_UINT32, &uid,
                                      DBUS_TYPE_UINT32, &pid,
                                      DBUS_TYPE_STRING, &service,
                                      DBUS_TYPE_STRING, &type,
                                      DBUS_TYPE_STRING, &seat,
                                      DBUS_TYPE_STRING, &tty,
                                      DBUS_TYPE_STRING, &display,
                                      DBUS_TYPE_BOOLEAN, &remote,
                                      DBUS_TYPE_STRING, &remote_user,
                                      DBUS_TYPE_STRING, &remote_host,
                                      DBUS_TYPE_INVALID)) {
                pam_syslog(handle, LOG_ERR, "Could not attach parameters to message.");
                r = PAM_BUF_ERR;
                goto finish;
        }

        dbus_message_iter_init_append(m, &iter);

        r = bus_append_strv_iter(&iter, controllers);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Could not attach parameter to message.");
                r = PAM_BUF_ERR;
                goto finish;
        }

        r = bus_append_strv_iter(&iter, reset_controllers);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Could not attach parameter to message.");
                r = PAM_BUF_ERR;
                goto finish;
        }

        kp = kill_processes;
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &kp)) {
                pam_syslog(handle, LOG_ERR, "Could not attach parameter to message.");
                r = PAM_BUF_ERR;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                pam_syslog(handle, LOG_ERR, "Failed to create session: %s", bus_error_message(&error));
                r = PAM_SESSION_ERR;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_STRING, &id,
                                   DBUS_TYPE_OBJECT_PATH, &object_path,
                                   DBUS_TYPE_STRING, &runtime_path,
                                   DBUS_TYPE_UNIX_FD, &session_fd,
                                   DBUS_TYPE_INVALID)) {
                pam_syslog(handle, LOG_ERR, "Failed to parse message: %s", bus_error_message(&error));
                r = PAM_SESSION_ERR;
                goto finish;
        }

        r = pam_misc_setenv(handle, "XDG_SESSION_ID", id, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set session id.");
                goto finish;
        }

        r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", runtime_path, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set runtime dir.");
                goto finish;
        }

        if (session_fd >= 0) {
                r = pam_set_data(handle, "systemd.session-fd", INT_TO_PTR(session_fd+1), NULL);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to install session fd.");
                        return r;
                }
        }

        session_fd = -1;

        r = PAM_SUCCESS;

finish:
        strv_free(controllers);
        strv_free(reset_controllers);
        strv_free(kill_only_users);
        strv_free(kill_exclude_users);

        dbus_error_free(&error);

        if (bus) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        if (session_fd >= 0)
                close_nointr_nofail(session_fd);

        return r;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        const void *p = NULL;

        pam_get_data(handle, "systemd.session-fd", &p);

        if (p)
                close_nointr(PTR_TO_INT(p) - 1);

        return PAM_SUCCESS;
}
