/* SPDX-License-Identifier: LGPL-2.1+ */

#include "selinux-access.h"

#if HAVE_SELINUX

#include <errno.h>
#include <selinux/avc.h>
#include <selinux/selinux.h>
#if HAVE_AUDIT
#include <libaudit.h>
#endif

#include "sd-bus.h"

#include "alloc-util.h"
#include "audit-fd.h"
#include "bus-util.h"
#include "dbus-callbackdata.h"
#include "errno-util.h"
#include "format-util.h"
#include "log.h"
#include "path-util.h"
#include "selinux-overhaul-permissions.h"
#include "selinux-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "util.h"

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
        const char *fmt2;

#if HAVE_AUDIT
        int fd;

        fd = get_audit_fd();

        if (fd >= 0) {
                _cleanup_free_ char *buf = NULL;
                int r;

                va_start(ap, fmt);
                r = vasprintf(&buf, fmt, ap);
                va_end(ap);

                if (r >= 0) {
                        if (type == SELINUX_AVC)
                                audit_log_user_avc_message(get_audit_fd(), AUDIT_USER_AVC, buf, NULL, NULL, NULL, 0);
                        else if (type == SELINUX_ERROR)
                                audit_log_user_avc_message(get_audit_fd(), AUDIT_USER_SELINUX_ERR, buf, NULL, NULL, NULL, 0);

                        return 0;
                }
        }
#endif

        fmt2 = strjoina("selinux: ", fmt);

        va_start(ap, fmt);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        log_internalv(LOG_AUTH | callback_type_to_priority(type),
                      0, PROJECT_FILE, __LINE__, __FUNCTION__,
                      fmt2, ap);
#pragma GCC diagnostic pop
        va_end(ap);

        return 0;
}

static int access_init(sd_bus_error *error) {

        if (!mac_selinux_use())
                return 0;

        if (initialized)
                return 1;

        if (avc_open(NULL, 0) != 0) {
                int enforce, saved_errno = errno;

                enforce = security_getenforce();
                log_full_errno(enforce != 0 ? LOG_ERR : LOG_WARNING, saved_errno, "Failed to open the SELinux AVC: %m");

                /* If enforcement isn't on, then let's suppress this
                 * error, and just don't do any AVC checks. The
                 * warning we printed is hence all the admin will
                 * see. */
                if (enforce == 0)
                        return 0;

                /* Return an access denied error, if we couldn't load
                 * the AVC but enforcing mode was on, or we couldn't
                 * determine whether it is one. */
                return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to open the SELinux AVC: %s", strerror_safe(saved_errno));
        }

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) audit_callback);
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) log_callback);

        initialized = true;
        return 1;
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
static int mac_selinux_generic_access_check(
                sd_bus_message *message,
                const char *path,
                const char *class,
                const char *permission,
                sd_bus_error *error,
                const char *func) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        const char *scon = NULL;
        struct audit_info audit_info = {};
        _cleanup_free_ char *cl = NULL;
        char *fcon = NULL;
        char **cmdline = NULL;
        int r = 0;

        assert(message);
        assert(permission);
        assert(error);
        assert(func);

        r = access_init(error);
        if (r <= 0)
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
                        log_warning_errno(errno, "SELinux getfilecon_raw on '%s' failed: %m (class=%s perm=%s)", path, class, permission);
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get file context on %s.", path);
                        goto finish;
                }

                if (!class)
                        class = "service";
        } else {
                r = getcon_raw(&fcon);
                if (r < 0) {
                        log_warning_errno(errno, "SELinux getcon_raw failed: %m (class=%s perm=%s)", class, permission);
                        r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get current context.");
                        goto finish;
                }

                if (!class)
                        class = "system";
        }

        sd_bus_creds_get_cmdline(creds, &cmdline);
        cl = strv_join(cmdline, " ");

        audit_info.creds = creds;
        audit_info.path = path;
        audit_info.cmdline = cl;

        r = selinux_check_access(scon, fcon, class, permission, &audit_info);
        if (r < 0)
                r = sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "SELinux policy denies access.");

        // TODO(cgzones): revert to debug
        log_warning("SELinux access check scon=%s tcon=%s class=%s perm=%s path=%s cmdline=%s func=%s ret=%i", scon, fcon, class, permission, strna(path), cl, func, r);

finish:
        freecon(fcon);

        if (r < 0 && security_getenforce() != 1) {
                sd_bus_error_free(error);
                r = 0;
        }

        return r;
}

int mac_selinux_access_check(
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_pidone_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *permission;

        assert(message);
        assert(overhaul_permission >= 0);
        assert(overhaul_permission < MAC_SELINUX_PIDONE_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_pidone_class;
                permission = mac_selinux_overhaul_pidone_permissions[overhaul_permission];
        } else {
                class = NULL; /* will be set in mac_selinux_generic_access_check() */
                permission = old_permission;
        }

        /* skip check if variant does not serve permission */
        if (!permission) {
                // TODO(cgzones): revert to debug
                log_warning("SELinux access check skipped (overhaul=%d func=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, NULL, class, permission, error, func);
}

int mac_selinux_unit_access_check(
                const Unit *unit,
                sd_bus_message *message,
                const char *old_permission,
                enum mac_selinux_unit_permissions overhaul_permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *permission;

        assert(unit);
        assert(message);
        assert(overhaul_permission >= 0);
        assert(overhaul_permission < MAC_SELINUX_UNIT_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_unit_class;
                permission = mac_selinux_overhaul_unit_permissions[overhaul_permission];
        } else {
                class = NULL; /* will be set in mac_selinux_generic_access_check() */
                permission = old_permission;
        }

        /* skip check if variant does not serve permission */
        if (!permission) {
                // TODO(cgzones): revert to debug
                log_warning("SELinux unit access check skipped (overhaul=%d funk=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, unit_label_path(unit), class, permission, error, func);
}

int mac_selinux_callback_check(
                const char *name,
                struct mac_callback_userdata *userdata) {

        const Unit *u;
        const char *path = NULL;

        assert(name);
        assert(userdata);
        assert(userdata->manager);
        assert(userdata->message);
        assert(userdata->error);
        assert(userdata->func);
        assert(userdata->selinux_permission >= 0);
        assert(userdata->selinux_permission < MAC_SELINUX_UNIT_PERMISSION_MAX);

        if (!mac_selinux_use())
                return 0;

        u = manager_get_unit(userdata->manager, name);
        if (u)
                path = unit_label_path(u);

        /* maybe the unit is not loaded, e.g. a disabled user session unit */
        if (!path)
                path = manager_lookup_unit_path(userdata->manager, name);

        return mac_selinux_generic_access_check(userdata->message, path, mac_selinux_overhaul_unit_class, mac_selinux_overhaul_unit_permissions[userdata->selinux_permission], userdata->error, userdata->func);
}

#endif
