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
#include "audit.h"
#include "macro.h"
#include "strv.h"
#include "dbus-common.h"
#include "def.h"
#include "socket-util.h"
#include "fileio.h"

static int parse_argv(pam_handle_t *handle,
                      int argc, const char **argv,
                      const char **class,
                      bool *debug) {

        unsigned i;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < (unsigned) argc; i++) {
                int k;

                if (startswith(argv[i], "class=")) {

                        if (class)
                                *class = argv[i] + 6;

                } else if (startswith(argv[i], "debug=")) {
                        k = parse_boolean(argv[i] + 6);

                        if (k < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse debug= argument.");
                                return k;
                        }

                        if (debug)
                                *debug = k;

                } else {
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring", argv[i]);
                        return 0;
                }
        }

        return 0;
}

static int get_user_data(
                pam_handle_t *handle,
                const char **ret_username,
                struct passwd **ret_pw) {

        const char *username = NULL;
        struct passwd *pw = NULL;
        uid_t uid;
        int r;

        assert(handle);
        assert(ret_username);
        assert(ret_pw);

        r = audit_loginuid_from_pid(0, &uid);
        if (r >= 0)
                pw = pam_modutil_getpwuid(handle, uid);
        else {
                r = pam_get_user(handle, &username, NULL);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to get user name.");
                        return r;
                }

                if (isempty(username)) {
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

static int get_seat_from_display(const char *display, const char **seat, uint32_t *vtnr) {
        _cleanup_free_ char *p = NULL;
        int r;
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        struct ucred ucred;
        socklen_t l;
        _cleanup_free_ char *tty = NULL;
        int v;

        assert(display);
        assert(vtnr);

        /* We deduce the X11 socket from the display name, then use
         * SO_PEERCRED to determine the X11 server process, ask for
         * the controlling tty of that and if it's a VC then we know
         * the seat and the virtual terminal. Sounds ugly, is only
         * semi-ugly. */

        r = socket_from_display(display, &p);
        if (r < 0)
                return r;
        strncpy(sa.un.sun_path, p, sizeof(sa.un.sun_path)-1);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0)
                return -errno;

        l = sizeof(ucred);
        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l);
        if (r < 0)
                return -errno;

        r = get_ctty(ucred.pid, NULL, &tty);
        if (r < 0)
                return r;

        v = vtnr_from_tty(tty);
        if (v < 0)
                return v;
        else if (v == 0)
                return -ENOENT;

        if (seat)
                *seat = "seat0";
        *vtnr = (uint32_t) v;

        return 0;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        struct passwd *pw;
        bool debug = false;
        const char *username, *id, *object_path, *runtime_path, *service = NULL, *tty = NULL, *display = NULL, *remote_user = NULL, *remote_host = NULL, *seat = NULL, *type = NULL, *class = NULL, *class_pam = NULL, *cvtnr = NULL;
        DBusError error;
        uint32_t uid, pid;
        DBusMessageIter iter;
        int session_fd = -1;
        DBusConnection *bus = NULL;
        DBusMessage *m = NULL, *reply = NULL;
        dbus_bool_t remote, existing;
        int r;
        uint32_t vtnr = 0;

        assert(handle);

        dbus_error_init(&error);

        /* pam_syslog(handle, LOG_INFO, "pam-systemd initializing"); */

        /* Make this a NOP on non-logind systems */
        if (!logind_running())
                return PAM_SUCCESS;

        if (parse_argv(handle,
                       argc, argv,
                       &class_pam,
                       &debug) < 0) {
                r = PAM_SESSION_ERR;
                goto finish;
        }

        r = get_user_data(handle, &username, &pw);
        if (r != PAM_SUCCESS)
                goto finish;

        /* Make sure we don't enter a loop by talking to
         * systemd-logind when it is actually waiting for the
         * background to finish start-up. If the service is
         * "systemd-user" we simply set XDG_RUNTIME_DIR and
         * leave. */

        pam_get_item(handle, PAM_SERVICE, (const void**) &service);
        if (streq_ptr(service, "systemd-user")) {
                char *p, *rt = NULL;

                if (asprintf(&p, "/run/systemd/users/%lu", (unsigned long) pw->pw_uid) < 0) {
                        r = PAM_BUF_ERR;
                        goto finish;
                }

                r = parse_env_file(p, NEWLINE,
                                   "RUNTIME", &rt,
                                   NULL);
                free(p);

                if (r < 0 && r != -ENOENT) {
                        r = PAM_SESSION_ERR;
                        free(rt);
                        goto finish;
                }

                if (rt)  {
                        r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", rt, 0);
                        free(rt);

                        if (r != PAM_SUCCESS) {
                                pam_syslog(handle, LOG_ERR, "Failed to set runtime dir.");
                                goto finish;
                        }
                }

                r = PAM_SUCCESS;
                goto finish;
        }

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

        pam_get_item(handle, PAM_XDISPLAY, (const void**) &display);
        pam_get_item(handle, PAM_TTY, (const void**) &tty);
        pam_get_item(handle, PAM_RUSER, (const void**) &remote_user);
        pam_get_item(handle, PAM_RHOST, (const void**) &remote_host);

        seat = pam_getenv(handle, "XDG_SEAT");
        if (isempty(seat))
                seat = getenv("XDG_SEAT");

        cvtnr = pam_getenv(handle, "XDG_VTNR");
        if (isempty(cvtnr))
                cvtnr = getenv("XDG_VTNR");

        service = strempty(service);
        tty = strempty(tty);
        display = strempty(display);
        remote_user = strempty(remote_user);
        remote_host = strempty(remote_host);
        seat = strempty(seat);

        if (strchr(tty, ':')) {
                /* A tty with a colon is usually an X11 display,
                 * placed there to show up in utmp. We rearrange
                 * things and don't pretend that an X display was a
                 * tty. */

                if (isempty(display))
                        display = tty;
                tty = "";
        } else if (streq(tty, "cron")) {
                /* cron has been setting PAM_TTY to "cron" for a very
                 * long time and it probably shouldn't stop doing that
                 * for compatibility reasons. */
                tty = "";
                type = "unspecified";
        } else if (streq(tty, "ssh")) {
                /* ssh has been setting PAM_TTY to "ssh" for a very
                 * long time and probably shouldn't stop doing that
                 * for compatibility reasons. */
                tty = "";
                type ="tty";
        }

        /* If this fails vtnr will be 0, that's intended */
        if (!isempty(cvtnr))
                safe_atou32(cvtnr, &vtnr);

        if (!isempty(display) && vtnr <= 0) {
                if (isempty(seat))
                        get_seat_from_display(display, &seat, &vtnr);
                else if (streq(seat, "seat0"))
                        get_seat_from_display(display, NULL, &vtnr);
        }

        if (!type)
                type = !isempty(display) ? "x11" :
                        !isempty(tty) ? "tty" : "unspecified";

        class = pam_getenv(handle, "XDG_SESSION_CLASS");
        if (isempty(class))
                class = getenv("XDG_SESSION_CLASS");
        if (isempty(class))
                class = class_pam;
        if (isempty(class))
                class = streq(type, "unspecified") ? "background" : "user";

        remote = !isempty(remote_host) &&
                !streq(remote_host, "localhost") &&
                !streq(remote_host, "localhost.localdomain");

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_UINT32, &uid,
                                      DBUS_TYPE_UINT32, &pid,
                                      DBUS_TYPE_STRING, &service,
                                      DBUS_TYPE_STRING, &type,
                                      DBUS_TYPE_STRING, &class,
                                      DBUS_TYPE_STRING, &seat,
                                      DBUS_TYPE_UINT32, &vtnr,
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

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "Asking logind to create session: "
                           "uid=%u pid=%u service=%s type=%s class=%s seat=%s vtnr=%u tty=%s display=%s remote=%s remote_user=%s remote_host=%s",
                           uid, pid, service, type, class, seat, vtnr, tty, display, yes_no(remote), remote_user, remote_host);

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
                                   DBUS_TYPE_STRING, &seat,
                                   DBUS_TYPE_UINT32, &vtnr,
                                   DBUS_TYPE_BOOLEAN, &existing,
                                   DBUS_TYPE_INVALID)) {
                pam_syslog(handle, LOG_ERR, "Failed to parse message: %s", bus_error_message(&error));
                r = PAM_SESSION_ERR;
                goto finish;
        }

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "Reply from logind: "
                           "id=%s object_path=%s runtime_path=%s session_fd=%d seat=%s vtnr=%u",
                           id, object_path, runtime_path, session_fd, seat, vtnr);

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

        if (!isempty(seat)) {
                r = pam_misc_setenv(handle, "XDG_SEAT", seat, 0);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set seat.");
                        goto finish;
                }
        }

        if (vtnr > 0) {
                char buf[11];
                snprintf(buf, sizeof(buf), "%u", vtnr);
                char_array_0(buf);

                r = pam_misc_setenv(handle, "XDG_VTNR", buf, 0);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set virtual terminal number.");
                        goto finish;
                }
        }

        r = pam_set_data(handle, "systemd.existing", INT_TO_PTR(!!existing), NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to install existing flag.");
                return r;
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

        const void *p = NULL, *existing = NULL;
        const char *id;
        DBusConnection *bus = NULL;
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;

        assert(handle);

        dbus_error_init(&error);

        /* Only release session if it wasn't pre-existing when we
         * tried to create it */
        pam_get_data(handle, "systemd.existing", &existing);

        id = pam_getenv(handle, "XDG_SESSION_ID");
        if (id && !existing) {

                /* Before we go and close the FIFO we need to tell
                 * logind that this is a clean session shutdown, so
                 * that it doesn't just go and slaughter us
                 * immediately after closing the fd */

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
                                "ReleaseSession");
                if (!m) {
                        pam_syslog(handle, LOG_ERR, "Could not allocate release session message.");
                        r = PAM_BUF_ERR;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, &id,
                                              DBUS_TYPE_INVALID)) {
                        pam_syslog(handle, LOG_ERR, "Could not attach parameters to message.");
                        r = PAM_BUF_ERR;
                        goto finish;
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                if (!reply) {
                        pam_syslog(handle, LOG_ERR, "Failed to release session: %s", bus_error_message(&error));
                        r = PAM_SESSION_ERR;
                        goto finish;
                }
        }

        r = PAM_SUCCESS;

finish:
        pam_get_data(handle, "systemd.session-fd", &p);
        if (p)
                close_nointr(PTR_TO_INT(p) - 1);

        dbus_error_free(&error);

        if (bus) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return r;
}
