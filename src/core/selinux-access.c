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
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "sd-bus.h"
#include "bus-util.h"
#include "util.h"
#include "log.h"
#include "selinux-util.h"
#include "audit-fd.h"
#include "strv.h"
#include "path-util.h"

static bool initialized = false;

struct audit_info {
        sd_bus_creds *creds;
        const char *path;
        const char *cmdline;
};

/*
   Any time an access gets denied this callback will be called
   with the audit data.  We then need to just copy the audit data into the msgbuf.
*/
static int audit_callback(
                void *auditdata,
                security_class_t cls,
                char *msgbuf,
                size_t msgbufsize) {

        const struct audit_info *audit = auditdata;
        uid_t uid = 0, login_uid = 0;
        gid_t gid = 0;
        char login_uid_buf[DECIMAL_STR_MAX(uid_t) + 1] = "n/a";
        char uid_buf[DECIMAL_STR_MAX(uid_t) + 1] = "n/a";
        char gid_buf[DECIMAL_STR_MAX(gid_t) + 1] = "n/a";

        if (sd_bus_creds_get_audit_login_uid(audit->creds, &login_uid) >= 0)
                xsprintf(login_uid_buf, UID_FMT, login_uid);
        if (sd_bus_creds_get_euid(audit->creds, &uid) >= 0)
                xsprintf(uid_buf, UID_FMT, uid);
        if (sd_bus_creds_get_egid(audit->creds, &gid) >= 0)
                xsprintf(gid_buf, GID_FMT, gid);

        snprintf(msgbuf, msgbufsize,
                 "auid=%s uid=%s gid=%s%s%s%s%s%s%s",
                 login_uid_buf, uid_buf, gid_buf,
                 audit->path ? " path=\"" : "", strempty(audit->path), audit->path ? "\"" : "",
                 audit->cmdline ? " cmdline=\"" : "", strempty(audit->cmdline), audit->cmdline ? "\"" : "");

        return 0;
}

static int callback_type_to_priority(int type) {
        switch(type) {

        case SELINUX_ERROR:
                return LOG_ERR;

        case SELINUX_WARNING:
                return LOG_WARNING;

        case SELINUX_INFO:
                return LOG_INFO;

        case SELINUX_AVC:
        default:
                return LOG_NOTICE;
        }
}

/*
   libselinux uses this callback when access gets denied or other
   events happen. If audit is turned on, messages will be reported
   using audit netlink, otherwise they will be logged using the usual
   channels.

   Code copied from dbus and modified.
*/
_printf_(2, 3) static int log_callback(int type, const char *fmt, ...) {
        va_list ap;

#ifdef HAVE_AUDIT
        int fd;

        fd = get_audit_fd();

        if (fd >= 0) {
                _cleanup_free_ char *buf = NULL;
                int r;

                va_start(ap, fmt);
                r = vasprintf(&buf, fmt, ap);
                va_end(ap);

                if (r >= 0) {
                        audit_log_user_avc_message(fd, AUDIT_USER_AVC, buf, NULL, NULL, NULL, 0);
                        return 0;
                }
        }
#endif

        va_start(ap, fmt);
        log_internalv(LOG_AUTH | callback_type_to_priority(type),
                      0, __FILE__, __LINE__, __FUNCTION__, fmt, ap);
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

        if (avc_open(NULL, 0))
                return log_error_errno(errno, "avc_open() failed: %m");

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) audit_callback);
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) log_callback);

        if (security_getenforce() < 0){
                r = -errno;
                avc_destroy();
        }

        return r;
}

static int mac_selinux_access_init(sd_bus_error *error) {
        int r;

        if (initialized)
                return 0;

        if (!mac_selinux_use())
                return 0;

        r = access_init();
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to initialize SELinux.");

        initialized = true;
        return 0;
}
#endif

void mac_selinux_access_free(void) {

#ifdef HAVE_SELINUX
        if (!initialized)
                return;

        avc_destroy();
        initialized = false;
#endif
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
int mac_selinux_generic_access_check(
                sd_bus_message *message,
                const char *path,
                const char *permission,
                sd_bus_error *error) {

#ifdef HAVE_SELINUX
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

        if (!mac_selinux_use())
                return 0;

        r = mac_selinux_access_init(error);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(
                        message,
                        SD_BUS_CREDS_PID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|
                        SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_AUDIT_LOGIN_UID|
                        SD_BUS_CREDS_SELINUX_CONTEXT|
                        SD_BUS_CREDS_AUGMENT /* get more bits from /proc */,
                        &creds);
        if (r < 0)
                goto finish;

        /* The SELinux context is something we really should have
         * gotten directly from the message or sender, and not be an
         * augmented field. If it was augmented we cannot use it for
         * authorization, since this is racy and vulnerable. Let's add
         * an extra check, just in case, even though this really
         * shouldn't be possible. */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_SELINUX_CONTEXT) == 0, -EPERM);

        r = sd_bus_creds_get_selinux_context(creds, &scon);
        if (r < 0)
                goto finish;

        if (path) {
                /* Get the file context of the unit file */

                r = getfilecon_raw(path, &fcon);
                if (r < 0) {
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get file context on %s.", path);
                        goto finish;
                }

                tclass = "service";
        } else {
                r = getcon_raw(&fcon);
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

        r = selinux_check_access(scon, fcon, tclass, permission, &audit_info);
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
#else
        return 0;
#endif
}
