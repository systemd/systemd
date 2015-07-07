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

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>

#include "bus-common-errors.h"
#include "util.h"
#include "audit.h"
#include "macro.h"
#include "strv.h"
#include "bus-util.h"
#include "def.h"
#include "socket-util.h"
#include "fileio.h"
#include "bus-error.h"
#include "formats-util.h"
#include "terminal-util.h"
#include "hostname-util.h"

static int parse_argv(
                pam_handle_t *handle,
                int argc, const char **argv,
                const char **class,
                const char **type,
                bool *debug) {

        unsigned i;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < (unsigned) argc; i++) {
                if (startswith(argv[i], "class=")) {
                        if (class)
                                *class = argv[i] + 6;

                } else if (startswith(argv[i], "type=")) {
                        if (type)
                                *type = argv[i] + 5;

                } else if (streq(argv[i], "debug")) {
                        if (debug)
                                *debug = true;

                } else if (startswith(argv[i], "debug=")) {
                        int k;

                        k = parse_boolean(argv[i] + 6);
                        if (k < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse debug= argument, ignoring.");
                        else if (debug)
                                *debug = k;

                } else
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring", argv[i]);
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

        assert(handle);
        assert(ret_username);
        assert(ret_pw);

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
        if (!pw) {
                pam_syslog(handle, LOG_ERR, "Failed to get user data.");
                return PAM_USER_UNKNOWN;
        }

        *ret_pw = pw;
        *ret_username = username;

        return PAM_SUCCESS;
}

static int get_seat_from_display(const char *display, const char **seat, uint32_t *vtnr) {
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        _cleanup_free_ char *p = NULL, *tty = NULL;
        _cleanup_close_ int fd = -1;
        struct ucred ucred;
        int v, r;

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

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

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

static int export_legacy_dbus_address(
                pam_handle_t *handle,
                uid_t uid,
                const char *runtime) {

        _cleanup_free_ char *s = NULL;
        int r;

        /* skip export if kdbus is not active */
        if (!is_kdbus_available())
                return PAM_SUCCESS;

        if (asprintf(&s, KERNEL_USER_BUS_ADDRESS_FMT ";" UNIX_USER_BUS_ADDRESS_FMT, uid, runtime) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to set bus variable.");
                return PAM_BUF_ERR;
        }

        r = pam_misc_setenv(handle, "DBUS_SESSION_BUS_ADDRESS", s, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set bus variable.");
                return r;
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char
                *username, *id, *object_path, *runtime_path,
                *service = NULL,
                *tty = NULL, *display = NULL,
                *remote_user = NULL, *remote_host = NULL,
                *seat = NULL,
                *type = NULL, *class = NULL,
                *class_pam = NULL, *type_pam = NULL, *cvtnr = NULL, *desktop = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int session_fd = -1, existing, r;
        bool debug = false, remote;
        struct passwd *pw;
        uint32_t vtnr = 0;
        uid_t original_uid;

        assert(handle);

        /* Make this a NOP on non-logind systems */
        if (!logind_running())
                return PAM_SUCCESS;

        if (parse_argv(handle,
                       argc, argv,
                       &class_pam,
                       &type_pam,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd initializing");

        r = get_user_data(handle, &username, &pw);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to get user data.");
                return r;
        }

        /* Make sure we don't enter a loop by talking to
         * systemd-logind when it is actually waiting for the
         * background to finish start-up. If the service is
         * "systemd-user" we simply set XDG_RUNTIME_DIR and
         * leave. */

        pam_get_item(handle, PAM_SERVICE, (const void**) &service);
        if (streq_ptr(service, "systemd-user")) {
                _cleanup_free_ char *p = NULL, *rt = NULL;

                if (asprintf(&p, "/run/systemd/users/"UID_FMT, pw->pw_uid) < 0)
                        return PAM_BUF_ERR;

                r = parse_env_file(p, NEWLINE,
                                   "RUNTIME", &rt,
                                   NULL);
                if (r < 0 && r != -ENOENT)
                        return PAM_SESSION_ERR;

                if (rt)  {
                        r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", rt, 0);
                        if (r != PAM_SUCCESS) {
                                pam_syslog(handle, LOG_ERR, "Failed to set runtime dir.");
                                return r;
                        }

                        r = export_legacy_dbus_address(handle, pw->pw_uid, rt);
                        if (r != PAM_SUCCESS)
                                return r;
                }

                return PAM_SUCCESS;
        }

        /* Otherwise, we ask logind to create a session for us */

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

        type = pam_getenv(handle, "XDG_SESSION_TYPE");
        if (isempty(type))
                type = getenv("XDG_SESSION_TYPE");
        if (isempty(type))
                type = type_pam;

        class = pam_getenv(handle, "XDG_SESSION_CLASS");
        if (isempty(class))
                class = getenv("XDG_SESSION_CLASS");
        if (isempty(class))
                class = class_pam;

        desktop = pam_getenv(handle, "XDG_SESSION_DESKTOP");
        if (isempty(desktop))
                desktop = getenv("XDG_SESSION_DESKTOP");

        tty = strempty(tty);

        if (strchr(tty, ':')) {
                /* A tty with a colon is usually an X11 display,
                 * placed there to show up in utmp. We rearrange
                 * things and don't pretend that an X display was a
                 * tty. */

                if (isempty(display))
                        display = tty;
                tty = NULL;
        } else if (streq(tty, "cron")) {
                /* cron has been setting PAM_TTY to "cron" for a very
                 * long time and it probably shouldn't stop doing that
                 * for compatibility reasons. */
                type = "unspecified";
                class = "background";
                tty = NULL;
        } else if (streq(tty, "ssh")) {
                /* ssh has been setting PAM_TTY to "ssh" for a very
                 * long time and probably shouldn't stop doing that
                 * for compatibility reasons. */
                type ="tty";
                class = "user";
                tty = NULL;
        }

        /* If this fails vtnr will be 0, that's intended */
        if (!isempty(cvtnr))
                (void) safe_atou32(cvtnr, &vtnr);

        if (!isempty(display) && !vtnr) {
                if (isempty(seat))
                        get_seat_from_display(display, &seat, &vtnr);
                else if (streq(seat, "seat0"))
                        get_seat_from_display(display, NULL, &vtnr);
        }

        if (seat && !streq(seat, "seat0") && vtnr != 0) {
                pam_syslog(handle, LOG_DEBUG, "Ignoring vtnr %"PRIu32" for %s which is not seat0", vtnr, seat);
                vtnr = 0;
        }

        if (isempty(type))
                type = !isempty(display) ? "x11" :
                           !isempty(tty) ? "tty" : "unspecified";

        if (isempty(class))
                class = streq(type, "unspecified") ? "background" : "user";

        remote = !isempty(remote_host) && !is_localhost(remote_host);

        /* Talk to logind over the message bus */

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to connect to system bus: %s", strerror(-r));
                return PAM_SESSION_ERR;
        }

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "Asking logind to create session: "
                           "uid="UID_FMT" pid="PID_FMT" service=%s type=%s class=%s desktop=%s seat=%s vtnr=%"PRIu32" tty=%s display=%s remote=%s remote_user=%s remote_host=%s",
                           pw->pw_uid, getpid(),
                           strempty(service),
                           type, class, strempty(desktop),
                           strempty(seat), vtnr, strempty(tty), strempty(display),
                           yes_no(remote), strempty(remote_user), strempty(remote_host));

        r = sd_bus_call_method(bus,
                               "org.freedesktop.login1",
                               "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager",
                               "CreateSession",
                               &error,
                               &reply,
                               "uusssssussbssa(sv)",
                               (uint32_t) pw->pw_uid,
                               (uint32_t) getpid(),
                               service,
                               type,
                               class,
                               desktop,
                               seat,
                               vtnr,
                               tty,
                               display,
                               remote,
                               remote_user,
                               remote_host,
                               0);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_SESSION_BUSY)) {
                        pam_syslog(handle, LOG_DEBUG, "Cannot create session: %s", bus_error_message(&error, r));
                        return PAM_SUCCESS;
                } else {
                        pam_syslog(handle, LOG_ERR, "Failed to create session: %s", bus_error_message(&error, r));
                        return PAM_SYSTEM_ERR;
                }
        }

        r = sd_bus_message_read(reply,
                                "soshusub",
                                &id,
                                &object_path,
                                &runtime_path,
                                &session_fd,
                                &original_uid,
                                &seat,
                                &vtnr,
                                &existing);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to parse message: %s", strerror(-r));
                return PAM_SESSION_ERR;
        }

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "Reply from logind: "
                           "id=%s object_path=%s runtime_path=%s session_fd=%d seat=%s vtnr=%u original_uid=%u",
                           id, object_path, runtime_path, session_fd, seat, vtnr, original_uid);

        r = pam_misc_setenv(handle, "XDG_SESSION_ID", id, 0);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set session id.");
                return r;
        }

        if (original_uid == pw->pw_uid) {
                /* Don't set $XDG_RUNTIME_DIR if the user we now
                 * authenticated for does not match the original user
                 * of the session. We do this in order not to result
                 * in privileged apps clobbering the runtime directory
                 * unnecessarily. */

                r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", runtime_path, 0);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set runtime dir.");
                        return r;
                }

                r = export_legacy_dbus_address(handle, pw->pw_uid, runtime_path);
                if (r != PAM_SUCCESS)
                        return r;
        }

        if (!isempty(seat)) {
                r = pam_misc_setenv(handle, "XDG_SEAT", seat, 0);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set seat.");
                        return r;
                }
        }

        if (vtnr > 0) {
                char buf[DECIMAL_STR_MAX(vtnr)];
                sprintf(buf, "%u", vtnr);

                r = pam_misc_setenv(handle, "XDG_VTNR", buf, 0);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set virtual terminal number.");
                        return r;
                }
        }

        r = pam_set_data(handle, "systemd.existing", INT_TO_PTR(!!existing), NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to install existing flag.");
                return r;
        }

        if (session_fd >= 0) {
                session_fd = fcntl(session_fd, F_DUPFD_CLOEXEC, 3);
                if (session_fd < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to dup session fd: %m");
                        return PAM_SESSION_ERR;
                }

                r = pam_set_data(handle, "systemd.session-fd", INT_TO_PTR(session_fd+1), NULL);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to install session fd.");
                        safe_close(session_fd);
                        return r;
                }
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        const void *existing = NULL;
        const char *id;
        int r;

        assert(handle);

        /* Only release session if it wasn't pre-existing when we
         * tried to create it */
        pam_get_data(handle, "systemd.existing", &existing);

        id = pam_getenv(handle, "XDG_SESSION_ID");
        if (id && !existing) {

                /* Before we go and close the FIFO we need to tell
                 * logind that this is a clean session shutdown, so
                 * that it doesn't just go and slaughter us
                 * immediately after closing the fd */

                r = sd_bus_open_system(&bus);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to connect to system bus: %s", strerror(-r));
                        return PAM_SESSION_ERR;
                }

                r = sd_bus_call_method(bus,
                                       "org.freedesktop.login1",
                                       "/org/freedesktop/login1",
                                       "org.freedesktop.login1.Manager",
                                       "ReleaseSession",
                                       &error,
                                       NULL,
                                       "s",
                                       id);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to release session: %s", bus_error_message(&error, r));
                        return PAM_SESSION_ERR;
                }
        }

        /* Note that we are knowingly leaking the FIFO fd here. This
         * way, logind can watch us die. If we closed it here it would
         * not have any clue when that is completed. Given that one
         * cannot really have multiple PAM sessions open from the same
         * process this means we will leak one FD at max. */

        return PAM_SUCCESS;
}
