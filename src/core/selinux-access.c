
/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Dan Walsh

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

#include "util.h"
#include "job.h"
#include "manager.h"
#include "selinux-access.h"

#ifdef HAVE_SELINUX
#include "dbus.h"
#include "log.h"
#include "dbus-unit.h"
#include "bus-errors.h"
#include "dbus-common.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif
#include <limits.h>

/* FD to send audit messages to */
static int audit_fd = -1;
static int selinux_enabled = -1;
static int first_time = 1;
static int selinux_enforcing = 0;

struct auditstruct {
        const char *path;
        char *cmdline;
        uid_t loginuid;
        uid_t uid;
        gid_t gid;
};

/*
   Define a mapping between the systemd method calls and the SELinux access to check.
   We define two tables, one for access checks on unit files, and one for
   access checks for the system in general.

   If we do not find a match in either table, then the "undefined" system
   check will be called.
*/

static const char * const unit_methods[][2] = {{ "DisableUnitFiles", "disable" },
                                               { "EnableUnitFiles", "enable" },
                                               { "GetUnit", "status" },
                                               { "GetUnitFileState",  "status" },
                                               { "Kill", "stop" },
                                               { "KillUnit", "stop" },
                                               { "LinkUnitFiles", "enable" },
                                               { "MaskUnitFiles", "disable" },
                                               { "PresetUnitFiles", "enable" },
                                               { "ReenableUnitFiles", "enable" },
                                               { "Reexecute", "start" },
                                               { "ReloadOrRestart", "start" },
                                               { "ReloadOrRestartUnit", "start" },
                                               { "ReloadOrTryRestart", "start" },
                                               { "ReloadOrTryRestartUnit", "start" },
                                               { "ReloadUnit", "reload" },
                                               { "ResetFailedUnit", "stop" },
                                               { "Restart", "start" },
                                               { "RestartUnit", "start" },
                                               { "Start", "start" },
                                               { "StartUnit", "start" },
                                               { "StartUnitReplace", "start" },
                                               { "Stop", "stop" },
                                               { "StopUnit", "stop" },
                                               { "TryRestart", "start" },
                                               { "TryRestartUnit", "start" },
                                               { "UnmaskUnitFiles", "enable" },
                                               { NULL, NULL }
};

static const char * const system_methods[][2] = { { "ClearJobs", "reboot" },
                                                  { "CreateSnapshot", "status" },
                                                  { "Dump", "status" },
                                                  { "Exit", "halt" },
                                                  { "FlushDevices", "halt" },
                                                  { "Get", "status" },
                                                  { "GetAll", "status" },
                                                  { "GetJob", "status" },
                                                  { "GetSeat", "status" },
                                                  { "GetSession", "status" },
                                                  { "GetSessionByPID", "status" },
                                                  { "GetUnitByPID", "status" },
                                                  { "GetUser", "status" },
                                                  { "Halt", "halt" },
                                                  { "Introspect", "status" },
                                                  { "KExec", "reboot" },
                                                  { "KillSession", "halt" },
                                                  { "KillUser", "halt" },
                                                  { "LoadUnit", "reload" },
                                                  { "ListJobs", "status" },
                                                  { "ListSeats", "status" },
                                                  { "ListSessions", "status" },
                                                  { "ListUnits", "status" },
                                                  { "ListUnitFiles", "status" },
                                                  { "ListUsers", "status" },
                                                  { "LockSession", "halt" },
                                                  { "PowerOff", "halt" },
                                                  { "Reboot", "reboot" },
                                                  { "Reload", "reload" },
                                                  { "Reexecute", "reload" },
                                                  { "ResetFailed", "reload" },
                                                  { "Subscribe", "status" },
                                                  { "SwithcRoot", "reboot" },
                                                  { "SetEnvironment", "status" },
                                                  { "SetUserLinger", "halt" },
                                                  { "TerminateSeat", "halt" },
                                                  { "TerminateSession", "halt" },
                                                  { "TerminateUser", "halt" },
                                                  { "Unsubscribe", "status" },
                                                  { "UnsetEnvironment", "status" },
                                                  { "UnsetAndSetEnvironment", "status" },
                                                  { NULL, NULL }
};

/*
   If the admin toggles the selinux enforcment mode this callback
   will get called before the next access check
*/
static int setenforce_callback(int enforcing)
{
        selinux_enforcing = enforcing;
        return 0;
}

/* This mimics dbus_bus_get_unix_user() */
static int bus_get_selinux_security_context(
                DBusConnection *connection,
                const char *name,
                char **scon,
                DBusError *error) {

        DBusMessage *m = NULL, *reply = NULL;
        int r;

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "GetConnectionSELinuxSecurityContext");
        if (!m) {
                r = -errno;
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        r = dbus_message_append_args(
                m,
                DBUS_TYPE_STRING, &name,
                DBUS_TYPE_INVALID);
        if (!r) {
                r = -errno;
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        if (!reply) {
                r = -errno;
                goto finish;
        }

        r = dbus_set_error_from_message(error, reply);
        if (!r) {
                r = -errno;
                goto finish;
        }

        r = dbus_message_get_args(
                reply, error,
                DBUS_TYPE_STRING, scon,
                DBUS_TYPE_INVALID);
        if (!r) {
                r = -errno;
                goto finish;
        }

        r = 0;
finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return r;
}

static int get_cmdline(pid_t pid, char **cmdline) {
        char buf[PATH_MAX];
        FILE *f;
        int count;
        int n;

        snprintf(buf, sizeof(buf), "/proc/%lu/cmdline", (unsigned long) pid);
        f = fopen(buf, "re");
        if (!f) {
                return -errno;
        }
        count = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (! count) {
                return -errno;
        }
        for (n = 0; n < count - 1; n++)
        {
                if (buf[n] == '\0')
                        buf[n] = ' ';
        }
        (*cmdline) = strdup(buf);
        if (! (*cmdline)) {
                return -errno;
        }
        return 0;
}

static int get_pid_id(pid_t pid, const char *file, uid_t *id) {
        char buf[PATH_MAX];
        int r = 0;
        FILE *f;
        snprintf(buf, sizeof(buf), "/proc/%lu/%s", (unsigned long) pid, file);
        f = fopen(buf, "re");
        if (!f)
                return -errno;
        fscanf(f, "%d", id);
        if (ferror(f))
                r = -errno;
        fclose(f);
        return r;
}

/* This mimics dbus_bus_get_unix_user() */
static int bus_get_audit_data(
                DBusConnection *connection,
                const char *name,
                struct auditstruct *audit,
                DBusError *error) {

        pid_t pid;
        DBusMessage *m = NULL, *reply = NULL;
        int r = -1;

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "GetConnectionUnixProcessID");
        if (!m) {
                r = -errno;
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        r = dbus_message_append_args(
                m,
                DBUS_TYPE_STRING, &name,
                DBUS_TYPE_INVALID);
        if (!r) {
                r = -errno;
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        if (!reply) {
                r = -errno;
                goto finish;
        }

        r = dbus_set_error_from_message(error, reply);
        if (!r) {
                r = -errno;
                goto finish;
        }

        r = dbus_message_get_args(
                reply, error,
                DBUS_TYPE_UINT32, &pid,
                DBUS_TYPE_INVALID);
        if (!r) {
                r = -errno;
                goto finish;
        }

        r = get_pid_id(pid, "loginuid", &(audit->loginuid));
        if (r)
                goto finish;

        r = get_pid_id(pid, "uid", &(audit->uid));
        if (r)
                goto finish;

        r = get_pid_id(pid, "gid", &(audit->gid));
        if (r)
                goto finish;

        r = get_cmdline(pid, &(audit->cmdline));
        if (r)
                goto finish;

        r = 0;
finish:
        if (m)
                dbus_message_unref(m);
        if (reply)
                dbus_message_unref(reply);
        return r;
}

/*
   Any time an access gets denied this callback will be called
   with the aduit data.  We then need to just copy the audit data into the msgbuf.
*/
static int audit_callback(void *auditdata, security_class_t cls,
                          char *msgbuf, size_t msgbufsize)
{
        struct auditstruct *audit = (struct auditstruct *) auditdata;
        snprintf(msgbuf, msgbufsize,
                 "name=\"%s\" cmdline=\"%s\" auid=%d uid=%d gid=%d",
                 audit->path, audit->cmdline, audit->loginuid,
                 audit->uid, audit->gid);
        return 0;
}

/*
   Any time an access gets denied this callback will be called
   code copied from dbus. If audit is turned on the messages will go as
   user_avc's into the /var/log/audit/audit.log, otherwise they will be
   sent to syslog.
*/
static int log_callback(int type, const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
#ifdef HAVE_AUDIT
        if (audit_fd >= 0) {
                char buf[LINE_MAX*2];

                vsnprintf(buf, sizeof(buf), fmt, ap);
                audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC,
                                           buf, NULL, NULL, NULL, 0);
                return 0;
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

        int r = -1;

        if (avc_open(NULL, 0)) {
                log_full(LOG_ERR, "avc_open failed: %m\n");
                return -errno;
        }

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) &audit_callback);
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) &log_callback);
        selinux_set_callback(SELINUX_CB_SETENFORCE, (union selinux_callback) &setenforce_callback);

        if ((r = security_getenforce()) >= 0) {
                setenforce_callback(r);
                return 0;
        }
        r = -errno;
        avc_destroy();
        return r;
}

static int selinux_init(Manager *m, DBusError *error) {

        int r;

#ifdef HAVE_AUDIT
        audit_fd = m->audit_fd;
#endif
        if (!first_time)
                return 0;

        if (selinux_enabled < 0)
                selinux_enabled = is_selinux_enabled() == 1;

        if (selinux_enabled) {
                /* if not first time is not set, then initialize access */
                r = access_init();
                if (r < 0) {
                        dbus_set_error(error, BUS_ERROR_ACCESS_DENIED, "Unable to initialize SELinux.");

                        return r;
                }
                first_time = 0;
        }

        return 0;
}

static int get_audit_data(
        DBusConnection *connection,
        DBusMessage *message,
        struct auditstruct *audit,
        DBusError *error) {

        const char *sender;
        int r = -1;

        sender = dbus_message_get_sender(message);
        if (sender) {
                r = bus_get_audit_data(
                        connection,
                        sender,
                        audit,
                        error);
                if (r)
                        goto finish;
        } else {
                int fd;
                struct ucred ucred;
                socklen_t len;
                r = dbus_connection_get_unix_fd(connection, &fd);
                if (!r) {
                        r = -EINVAL;
                        goto finish;
                }

                r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
                if (r < 0) {
                        r = -errno;
                        log_error("Failed to determine peer credentials: %m");
                        goto finish;
                }
                audit->uid = ucred.uid;
                audit->gid = ucred.gid;

                r = get_pid_id(ucred.pid, "loginuid", &(audit->loginuid));
                if (r)
                        goto finish;

                r = get_cmdline(ucred.pid, &(audit->cmdline));
                if (r)
                        goto finish;
        }

        r = 0;

finish:
        return r;
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

        /*
           If sender exists then
           if sender is NULL this indicates a local connection.  Grab the fd
           from dbus and do an getpeercon to peers process context
        */
        sender = dbus_message_get_sender(message);
        if (sender) {
                r = bus_get_selinux_security_context(connection, sender, scon, error);
                if (r < 0)
                        return -EINVAL;
        } else {
                int fd;
                r = dbus_connection_get_unix_fd(connection, &fd);
                if (! r)
                        return -EINVAL;

                r = getpeercon(fd, scon);
                if (r < 0)
                        return -errno;
        }

        return 0;
}

/*
   This function returns the SELinux permission to check and whether or not the
   check requires a unit file.
*/
static void selinux_perm_lookup(const char *method, const char **perm, int *require_unit)
{
        int i;
        *require_unit = -1;

        for (i = 0; unit_methods[i][0]; i++) {
                if (streq(method, unit_methods[i][0])) {
                        *perm = unit_methods[i][1];
                        *require_unit = 1;
                        break;
                }
        }

        if (*require_unit < 0) {
                for (i = 0; system_methods[i][0]; i++) {
                        if (streq(method, system_methods[i][0])) {
                                *perm = system_methods[i][1];
                                *require_unit = 0;
                                break;
                        }
                }
        }
        if (*require_unit < 0) {
                *require_unit = 0;
                *perm = "undefined";
        }
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
static int selinux_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, DBusError *error, const char *perm, const char *path) {
        security_context_t scon = NULL;
        security_context_t fcon = NULL;
        int r = 0;
        const char *tclass = NULL;
        struct auditstruct audit;
        audit.uid = audit.loginuid = audit.gid = -1;
        audit.cmdline = NULL;
        audit.path = path;

        r = get_calling_context(connection, message, &scon, error);
        if (r != 0)
                goto finish;

        if (path) {
                tclass = "service";
                /* get the file context of the unit file */
                r = getfilecon(path, &fcon);
                if (r < 0) {
                        log_full(LOG_ERR, "Failed to get security context on: %s %m\n",path);
                        goto finish;
                }

        } else {
                tclass = "system";
                r = getcon(&fcon);
                if (r < 0) {
                        dbus_set_error(error, BUS_ERROR_ACCESS_DENIED, "Unable to get current context, SELinux policy denies access.");
                        goto finish;
                }
        }

        (void) get_audit_data(connection, message, &audit, error);

        errno=0;
        r = selinux_check_access(scon, fcon, tclass, perm, &audit);
        if ( r < 0) {
                r = -errno;
                log_error("SELinux Denied \"%s\"", audit.cmdline);

                dbus_set_error(error, BUS_ERROR_ACCESS_DENIED, "SELinux policy denies access.");
        }

        log_debug("SELinux checkaccess scon %s tcon %s tclass %s perm %s path %s: %d", scon, fcon, tclass, perm, path, r);
finish:
        if (r)
                r = -errno;

        free(audit.cmdline);
        freecon(scon);
        freecon(fcon);

        return r;
}

/*
  Clean up memory allocated in selinux_avc_init
*/
void selinux_access_finish(void) {
        if (!first_time)
                avc_destroy();
        first_time = 1;
}

int selinux_unit_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, const char *path, DBusError *error) {
        const char *perm;
        int require_unit;
        const char *member = dbus_message_get_member(message);
        int r;

        r = selinux_init(m, error);
        if (r)
                return r;

        if (! selinux_enabled)
                return 0;

        selinux_perm_lookup(member, &perm, &require_unit);
        log_debug("SELinux dbus-unit Look %s up perm %s require_unit %d", member, perm, require_unit);

        r = selinux_access_check(connection, message, m, error, perm, path);
        if ((r < 0) && (!selinux_enforcing)) {
                dbus_error_init(error);
                r = 0;
        }

        return r;
}

int selinux_manager_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, DBusError *error) {
        int r = -1;
        const char *member;
        int require_unit;
        const char *perm;
        char *path = NULL;

        r = selinux_init(m, error);
        if (r)
                return r;

        if (! selinux_enabled)
                return 0;

        member = dbus_message_get_member(message);

        selinux_perm_lookup(member, &perm, &require_unit);
        log_debug("SELinux dbus-manager Lookup %s perm %s require_unit %d", member, perm, require_unit);

        if (require_unit) {
                const char *name;
                Unit *u;

                r = dbus_message_get_args(
                        message,
                        error,
                        DBUS_TYPE_STRING, &name,
                        DBUS_TYPE_INVALID);
                if (!r)
                        goto finish;

                u = manager_get_unit(m, name);
                if ( !u ) {
                        if ((r = manager_load_unit(m, name, NULL, error, &u)) < 0) {
                                r = -errno;
                                dbus_set_error(error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);
                                goto finish;
                        }
                }

                path = u->source_path ? u->source_path : u->fragment_path;
        }
        r = selinux_access_check(connection, message, m, error, perm, path);

finish:
        /* if SELinux is in permissive mode return 0 */
        if (r && (!selinux_enforcing)) {
                dbus_error_init(error);
                r = 0;
        }
        return r;
}

#else
int selinux_unit_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, const char *path, DBusError *error) {
        return 0;
}

int selinux_manager_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, DBusError *error) {
        return 0;
}

void selinux_access_finish(void) {}
#endif
