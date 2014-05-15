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
#include <sys/socket.h>
#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "sd-bus.h"
#include "bus-util.h"
#include "util.h"
#include "log.h"
#include "audit.h"
#include "selinux-util.h"
#include "audit-fd.h"
#include "strv.h"

static bool initialized = false;

struct audit_info {
        sd_bus_creds *creds;
        const char *path;
        const char *cmdline;
};

/*
   Any time an access gets denied this callback will be called
   with the aduit data.  We then need to just copy the audit data into the msgbuf.
*/
static int audit_callback(
                void *auditdata,
                security_class_t cls,
                char *msgbuf,
                size_t msgbufsize) {

        const struct audit_info *audit = auditdata;
        uid_t uid = 0, login_uid = 0;
        gid_t gid = 0;

        sd_bus_creds_get_audit_login_uid(audit->creds, &login_uid);
        sd_bus_creds_get_uid(audit->creds, &uid);
        sd_bus_creds_get_gid(audit->creds, &gid);

        snprintf(msgbuf, msgbufsize,
                 "auid=%d uid=%d gid=%d%s%s%s%s%s%s",
                 login_uid, uid, gid,
                 audit->path ? " path=\"" : "", strempty(audit->path), audit->path ? "\"" : "",
                 audit->cmdline ? " cmdline=\"" : "", strempty(audit->cmdline), audit->cmdline ? "\"" : "");

        msgbuf[msgbufsize-1] = 0;

        return 0;
}

/*
   Any time an access gets denied this callback will be called
   code copied from dbus. If audit is turned on the messages will go as
   user_avc's into the /var/log/audit/audit.log, otherwise they will be
   sent to syslog.
*/
_printf_(2, 3) static int log_callback(int type, const char *fmt, ...) {
        va_list ap;

#ifdef HAVE_AUDIT
        if (get_audit_fd() >= 0) {
                _cleanup_free_ char *buf = NULL;
                int r;

                va_start(ap, fmt);
                r = vasprintf(&buf, fmt, ap);
                va_end(ap);

                if (r >= 0) {
                        audit_log_user_avc_message(get_audit_fd(), AUDIT_USER_AVC, buf, NULL, NULL, NULL, 0);
                        return 0;
                }
        }
#endif

        va_start(ap, fmt);
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
        int r = 0;

        if (avc_open(NULL, 0)) {
                log_error("avc_open() failed: %m");
                return -errno;
        }

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) audit_callback);
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) log_callback);

        if (security_getenforce() < 0){
                r = -errno;
                avc_destroy();
        }

        return r;
}

static int selinux_access_init(sd_bus_error *error) {
        int r;

        if (initialized)
                return 0;

        if (!use_selinux())
                return 0;

        r = access_init();
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to initialize SELinux.");

        initialized = true;
        return 0;
}

void selinux_access_free(void) {

        if (!initialized)
                return;

        avc_destroy();
        initialized = false;
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
int selinux_generic_access_check(
                sd_bus_message *message,
                const char *path,
                const char *permission,
                sd_bus_error *error) {

        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        const char *tclass = NULL, *scon = NULL;
        struct audit_info audit_info = {};
        _cleanup_free_ char *cl = NULL;
        security_context_t fcon = NULL;
        char **cmdline = NULL;
        int r = 0;

        assert(message);
        assert(permission);
        assert(error);

        if (!use_selinux())
                return 0;

        r = selinux_access_init(error);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(
                        message,
                        SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|
                        SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_AUDIT_LOGIN_UID|
                        SD_BUS_CREDS_SELINUX_CONTEXT,
                        &creds);
        if (r < 0)
                goto finish;

        r = sd_bus_creds_get_selinux_context(creds, &scon);
        if (r < 0)
                goto finish;

        if (path) {
                /* Get the file context of the unit file */

                r = getfilecon(path, &fcon);
                if (r < 0) {
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get file context on %s.", path);
                        goto finish;
                }

                tclass = "service";
        } else {
                r = getcon(&fcon);
                if (r < 0) {
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get current context.");
                        goto finish;
                }

                tclass = "system";
        }

        sd_bus_creds_get_cmdline(creds, &cmdline);
        cl = strv_join(cmdline, " ");

        audit_info.creds = creds;
        audit_info.path = path;
        audit_info.cmdline = cl;

        r = selinux_check_access((security_context_t) scon, fcon, tclass, permission, &audit_info);
        if (r < 0)
                r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "SELinux policy denies access.");

        log_debug("SELinux access check scon=%s tcon=%s tclass=%s perm=%s path=%s cmdline=%s: %i", scon, fcon, tclass, permission, path, cl, r);

finish:
        freecon(fcon);

        if (r < 0 && security_getenforce() != 1) {
                sd_bus_error_free(error);
                r = 0;
        }

        return r;
}

#else

int selinux_generic_access_check(
                sd_bus_message *message,
                const char *path,
                const char *permission,
                sd_bus_error *error) {

        return 0;
}

void selinux_access_free(void) {
}

#endif
