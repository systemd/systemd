/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Dan Walsh

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

#include "selinux-access.h"

#ifdef HAVE_SELINUX

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif
#include <dbus.h>

#include "util.h"
#include "log.h"
#include "bus-errors.h"
#include "dbus-common.h"
#include "audit.h"
#include "selinux-util.h"
#include "audit-fd.h"

static bool initialized = false;

struct auditstruct {
        const char *path;
        char *cmdline;
        uid_t loginuid;
        uid_t uid;
        gid_t gid;
};

static int bus_get_selinux_security_context(
                DBusConnection *connection,
                const char *name,
                char **scon,
                DBusError *error) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub;
        const char *bytes;
        char *b;
        int nbytes;

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "GetConnectionSELinuxSecurityContext");
        if (!m) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return -ENOMEM;
        }

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &name,
                            DBUS_TYPE_INVALID)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return -ENOMEM;
        }

        reply = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        if (!reply)
                return -EIO;

        if (dbus_set_error_from_message(error, reply))
                return -EIO;

        if (!dbus_message_iter_init(reply, &iter))
                return -EIO;

        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
                return -EIO;

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_get_fixed_array(&sub, &bytes, &nbytes);

        b = strndup(bytes, nbytes);
        if (!b)
                return -ENOMEM;

        *scon = b;

        return 0;
}

static int bus_get_audit_data(
                DBusConnection *connection,
                const char *name,
                struct auditstruct *audit,
                DBusError *error) {

        pid_t pid;
        int r;

        pid = bus_get_unix_process_id(connection, name, error);
        if (pid <= 0)
                return -EIO;

        r = audit_loginuid_from_pid(pid, &audit->loginuid);
        if (r < 0)
                return r;

        r = get_process_uid(pid, &audit->uid);
        if (r < 0)
                return r;

        r = get_process_gid(pid, &audit->gid);
        if (r < 0)
                return r;

        r = get_process_cmdline(pid, 0, true, &audit->cmdline);
        if (r < 0)
                return r;

        return 0;
}

/*
   Any time an access gets denied this callback will be called
   with the aduit data.  We then need to just copy the audit data into the msgbuf.
*/
static int audit_callback(
                void *auditdata,
                security_class_t cls,
                char *msgbuf,
                size_t msgbufsize) {

        struct auditstruct *audit = (struct auditstruct *) auditdata;

        snprintf(msgbuf, msgbufsize,
                 "auid=%d uid=%d gid=%d%s%s%s%s%s%s",
                 audit->loginuid,
                 audit->uid,
                 audit->gid,
                 (audit->path ? " path=\"" : ""),
                 strempty(audit->path),
                 (audit->path ? "\"" : ""),
                 (audit->cmdline ? " cmdline=\"" : ""),
                 strempty(audit->cmdline),
                 (audit->cmdline ? "\"" : ""));

        msgbuf[msgbufsize-1] = 0;

        return 0;
}

/*
   Any time an access gets denied this callback will be called
   code copied from dbus. If audit is turned on the messages will go as
   user_avc's into the /var/log/audit/audit.log, otherwise they will be
   sent to syslog.
*/
_printf_attr_(2, 3) static int log_callback(int type, const char *fmt, ...) {
        va_list ap;

        va_start(ap, fmt);

#ifdef HAVE_AUDIT
        if (get_audit_fd() >= 0) {
                _cleanup_free_ char *buf = NULL;
                int r;

                r = vasprintf(&buf, fmt, ap);
                va_end(ap);

                if (r >= 0) {
                        audit_log_user_avc_message(get_audit_fd(), AUDIT_USER_AVC, buf, NULL, NULL, NULL, 0);
                        return 0;
                }

                va_start(ap, fmt);
        }
#endif
        log_metav(LOG_USER | LOG_INFO, __FILE__, __LINE__, __FUNCTION__, fmt, ap);
        va_end(ap);

        return 0;
}

/*
   Function must be called once to initialize the SELinux AVC environment.
   Sets up callbacks.
   If you want to cleanup memory you should need to call selinux_access_finish.
*/
static int access_init(void) {
        int r;

        if (avc_open(NULL, 0)) {
                log_error("avc_open() failed: %m");
                return -errno;
        }

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) audit_callback);
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) log_callback);

        if (security_getenforce() >= 0)
                return 0;

        r = -errno;
        avc_destroy();

        return r;
}

static int selinux_access_init(DBusError *error) {
        int r;

        if (initialized)
                return 0;

        if (use_selinux()) {
                r = access_init();
                if (r < 0) {
                        dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED, "Failed to initialize SELinux.");
                        return r;
                }
        }

        initialized = true;
        return 0;
}

void selinux_access_free(void) {
        if (!initialized)
                return;

        avc_destroy();
        initialized = false;
}

static int get_audit_data(
                DBusConnection *connection,
                DBusMessage *message,
                struct auditstruct *audit,
                DBusError *error) {

        const char *sender;
        int r, fd;
        struct ucred ucred;
        socklen_t len = sizeof(ucred);

        sender = dbus_message_get_sender(message);
        if (sender)
                return bus_get_audit_data(connection, sender, audit, error);

        if (!dbus_connection_get_unix_fd(connection, &fd))
                return -EINVAL;

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
        if (r < 0) {
                log_error("Failed to determine peer credentials: %m");
                return -errno;
        }

        audit->uid = ucred.uid;
        audit->gid = ucred.gid;

        r = audit_loginuid_from_pid(ucred.pid, &audit->loginuid);
        if (r < 0)
                return r;

        r = get_process_cmdline(ucred.pid, 0, true, &audit->cmdline);
        if (r < 0)
                return r;

        return 0;
}

/*
   This function returns the security context of the remote end of the dbus
   connections.  Whether it is on the bus or a local connection.
*/
static int get_calling_context(
                DBusConnection *connection,
                DBusMessage *message,
                security_context_t *scon,
                DBusError *error) {

        const char *sender;
        int r;
        int fd;

        /*
           If sender exists then
           if sender is NULL this indicates a local connection.  Grab the fd
           from dbus and do an getpeercon to peers process context
        */
        sender = dbus_message_get_sender(message);
        if (sender) {
                r = bus_get_selinux_security_context(connection, sender, scon, error);
                if (r >= 0)
                        return r;

                log_error("bus_get_selinux_security_context failed: %m");
                return r;
        }

        if (!dbus_connection_get_unix_fd(connection, &fd)) {
                log_error("bus_connection_get_unix_fd failed %m");
                return -EINVAL;
        }

        r = getpeercon(fd, scon);
        if (r < 0) {
                log_error("getpeercon failed %m");
                return -errno;
        }

        return 0;
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
int selinux_access_check(
                DBusConnection *connection,
                DBusMessage *message,
                const char *path,
                const char *permission,
                DBusError *error) {

        security_context_t scon = NULL, fcon = NULL;
        int r = 0;
        const char *tclass = NULL;
        struct auditstruct audit;

        assert(connection);
        assert(message);
        assert(permission);
        assert(error);

        if (!use_selinux())
                return 0;

        r = selinux_access_init(error);
        if (r < 0)
                return r;

        audit.uid = audit.loginuid = (uid_t) -1;
        audit.gid = (gid_t) -1;
        audit.cmdline = NULL;
        audit.path = path;

        r = get_calling_context(connection, message, &scon, error);
        if (r < 0) {
                log_error("Failed to get caller's security context on: %m");
                goto finish;
        }

        if (path) {
                tclass = "service";
                /* get the file context of the unit file */
                r = getfilecon(path, &fcon);
                if (r < 0) {
                        dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED, "Failed to get file context on %s.", path);
                        r = -errno;
                        log_error("Failed to get security context on %s: %m",path);
                        goto finish;
                }

        } else {
                tclass = "system";
                r = getcon(&fcon);
                if (r < 0) {
                        dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED, "Failed to get current context.");
                        r = -errno;
                        log_error("Failed to get current process context on: %m");
                        goto finish;
                }
        }

        (void) get_audit_data(connection, message, &audit, error);

        errno = 0;
        r = selinux_check_access(scon, fcon, tclass, permission, &audit);
        if (r < 0) {
                dbus_set_error(error, DBUS_ERROR_ACCESS_DENIED, "SELinux policy denies access.");
                r = -errno;
                log_error("SELinux policy denies access.");
        }

        log_debug("SELinux access check scon=%s tcon=%s tclass=%s perm=%s path=%s cmdline=%s: %i", scon, fcon, tclass, permission, path, audit.cmdline, r);

finish:
        free(audit.cmdline);
        freecon(scon);
        freecon(fcon);

        if (r && security_getenforce() != 1) {
                dbus_error_init(error);
                r = 0;
        }

        return r;
}

#else

int selinux_access_check(
                DBusConnection *connection,
                DBusMessage *message,
                const char *path,
                const char *permission,
                DBusError *error) {

        return 0;
}

void selinux_access_free(void) {
}

#endif
