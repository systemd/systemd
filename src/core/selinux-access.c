/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "selinux-access.h"

#if HAVE_SELINUX

#include <selinux/avc.h>
#include <selinux/selinux.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "audit-fd.h"
#include "errno-util.h"
#include "format-util.h"
#include "libaudit-util.h"
#include "log.h"
#include "selinux-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"

static bool initialized = false;

struct audit_info {
        sd_bus_creds *creds;
        sd_varlink *link;
        const char *path;
        const char *cmdline;
        const char *function;
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

        if (audit->creds) {
                /* DBus case */
                if (sd_bus_creds_get_audit_login_uid(audit->creds, &login_uid) >= 0)
                        xsprintf(login_uid_buf, UID_FMT, login_uid);
                if (sd_bus_creds_get_euid(audit->creds, &uid) >= 0)
                        xsprintf(uid_buf, UID_FMT, uid);
                if (sd_bus_creds_get_egid(audit->creds, &gid) >= 0)
                        xsprintf(gid_buf, GID_FMT, gid);
        }

        if (audit->link) {
                /* varlink */
                if (sd_varlink_get_peer_uid(audit->link, &uid) >= 0)
                        xsprintf(uid_buf, UID_FMT, uid);
                if (sd_varlink_get_peer_gid(audit->link, &gid) >= 0)
                        xsprintf(gid_buf, GID_FMT, gid);
        }

        (void) snprintf(msgbuf, msgbufsize,
                        "auid=%s uid=%s gid=%s%s%s%s%s%s%s%s%s%s",
                        login_uid_buf, uid_buf, gid_buf,
                        audit->path ? " path=\"" : "", strempty(audit->path), audit->path ? "\"" : "",
                        audit->cmdline ? " cmdline=\"" : "", strempty(audit->cmdline), audit->cmdline ? "\"" : "",
                        audit->function ? " function=\"" : "", strempty(audit->function), audit->function ? "\"" : "");

        return 0;
}

static int callback_type_to_priority(int type) {
        switch (type) {

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
        int fd = get_core_audit_fd();

        if (fd >= 0) {
                _cleanup_free_ char *buf = NULL;
                int r;

                va_start(ap, fmt);
                r = vasprintf(&buf, fmt, ap);
                va_end(ap);

                if (r >= 0) {
                        if (type == SELINUX_AVC)
                                audit_log_user_avc_message(fd, AUDIT_USER_AVC, buf, NULL, NULL, NULL, getuid());
                        else if (type == SELINUX_ERROR)
                                audit_log_user_avc_message(fd, AUDIT_USER_SELINUX_ERR, buf, NULL, NULL, NULL, getuid());

                        return 0;
                }
        }
#endif

        fmt2 = strjoina("selinux: ", fmt);

        va_start(ap, fmt);

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_AUTH | callback_type_to_priority(type),
                      0, PROJECT_FILE, __LINE__, __func__,
                      fmt2, ap);
        REENABLE_WARNING;
        va_end(ap);

        return 0;
}

static int access_init(sd_bus_error *error) {
        int r;

        if (!mac_selinux_use())
                return 0;

        if (initialized)
                return 1;

        if (avc_open(NULL, 0) != 0) {
                /* Passing errno to save original value for later */
                r = log_selinux_enforcing_errno(errno, "Failed to open the SELinux AVC: %m");
                if (r == 0)
                        /* log_selinux_enforcing_errno() can return 0 if the enforcement isn't on.
                         * In this case don't do any AVC checks.
                         * The warning we printed is hence all the admin will see. */
                        return 0;

                /* Return an access denied error based on the original errno, if we couldn't load the AVC but
                 * enforcing mode was on, or we couldn't determine whether it is one. */
                errno = -r;
                return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to open the SELinux AVC: %m");
        }

        selinux_set_callback(SELINUX_CB_AUDIT, (union selinux_callback) { .func_audit = audit_callback });
        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) { .func_log = log_callback });

        initialized = true;
        return 1;
}

static int get_our_contexts(const Unit *unit, const char **ret_acon, const char **ret_tclass, char **ret_fcon) {
        _cleanup_freecon_ char *fcon = NULL;

        assert(ret_acon);
        assert(ret_tclass);
        assert(ret_fcon);

        if (unit && unit->access_selinux_context) {
                /* Nice! The unit comes with a SELinux context read from the unit file */
                *ret_acon = unit->access_selinux_context;
                *ret_tclass = "service";
                *ret_fcon = NULL;
                return 0;
        }

        /* If no unit context is known, use our own */

        /* Ideally, we should call mac_selinux_get_our_label() here because it
         * does exactly the same - call getcon_raw(). However, it involves
         * selinux_init() which opens label DB. It was not part of the
         * original code. I don't want to change it for now. */
        if (getcon_raw(&fcon) < 0)
                return log_debug_errno(errno, "SELinux getcon_raw() failed: %m");

        if (!fcon)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "SELinux returned no context of the current process");

        *ret_acon = fcon;
        *ret_tclass = "system";
        *ret_fcon = TAKE_PTR(fcon);
        return 0;
}

static int check_access(
                const char *scon,
                const char *tcon,
                const char *tclass,
                const char *permission,
                struct audit_info *audit_info,
                sd_bus_error *error) {

        bool enforce = mac_selinux_enforcing();
        int r;

        assert(scon);
        assert(tcon);
        assert(tclass);
        assert(permission);
        assert(audit_info);
        assert(audit_info->function);

        r = selinux_check_access(scon, tcon, tclass, permission, audit_info);
        if (r < 0) {
                errno = -(r = errno_or_else(EPERM));

                if (enforce)
                        sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "SELinux policy denies access: %m");
        }

        return log_selinux_enforcing_errno(
                              r,
                              "SELinux access check scon=%s tcon=%s tclass=%s perm=%s state=%s function=%s path=%s cmdline=%s: %m",
                              scon,
                              tcon,
                              tclass,
                              permission,
                              enforce ? "enforcing" : "permissive",
                              audit_info->function,
                              empty_to_na(audit_info->path),
                              empty_to_na(audit_info->cmdline));
}

/*
   This function communicates with the kernel to check whether or not it should
   allow the access.
   If the machine is in permissive mode it will return ok.  Audit messages will
   still be generated if the access would be denied in enforcing mode.
*/
int mac_selinux_access_check_bus_internal(
                sd_bus_message *message,
                const Unit *unit,
                const char *permission,
                const char *function,
                sd_bus_error *error) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        const char *tclass, *scon, *acon;
        _cleanup_free_ char *cl = NULL;
        _cleanup_freecon_ char *fcon = NULL;
        char **cmdline = NULL;
        bool enforce;
        int r = 0;

        assert(message);
        assert(permission);
        assert(function);

        r = access_init(error);
        if (r <= 0)
                return r;

        /* delay call until we checked in `access_init()` if SELinux is actually enabled */
        enforce = mac_selinux_enforcing();

        r = sd_bus_query_sender_creds(
                        message,
                        SD_BUS_CREDS_PID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_EGID|
                        SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_AUDIT_LOGIN_UID|
                        SD_BUS_CREDS_SELINUX_CONTEXT|
                        SD_BUS_CREDS_AUGMENT /* get more bits from /proc */,
                        &creds);
        if (r < 0)
                return r;

        /* The SELinux context is something we really should have gotten directly from the message or sender,
         * and not be an augmented field. If it was augmented we cannot use it for authorization, since this
         * is racy and vulnerable. Let's add an extra check, just in case, even though this really shouldn't
         * be possible. */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_SELINUX_CONTEXT) == 0, -EPERM);

        r = sd_bus_creds_get_selinux_context(creds, &scon);
        if (r < 0)
                return r;

        r = get_our_contexts(unit, &acon, &tclass, &fcon);
        if (r < 0) {
                log_selinux_enforcing_errno(
                                r,
                                "Failed to retrieves SELinux context of current process (perm=%s)%s: %m",
                                permission,
                                enforce ? "" : ", ignoring");

                if (!enforce)
                        return 0;

                if (r == -EOPNOTSUPP)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "We appear not to have any SELinux context: %m");

                return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get current context: %m");
        }

        (void) sd_bus_creds_get_cmdline(creds, &cmdline);
        cl = strv_join(cmdline, " ");

        struct audit_info audit_info = {
                .creds = creds,
                .path = unit ? unit->fragment_path : NULL,
                .cmdline = cl,
                .function = function,
        };

        return check_access(scon, acon, tclass, permission, &audit_info, error);
}

int mac_selinux_access_check_varlink_internal(
                sd_varlink *link,
                const Unit *unit,
                const char *permission,
                const char *function) {

        _cleanup_freecon_ char *fcon = NULL, *scon = NULL;
        const char *tclass, *acon;
        int r;

        assert(link);
        assert(permission);
        assert(function);

        r = access_init(/* error= */ NULL);
        if (r <= 0)
                /* access_init() does log_selinux_enforcing_errno() */
                return r;

        /* delay call until we checked in `access_init()` if SELinux is actually enabled */
        bool enforce = mac_selinux_enforcing();

        int fd = sd_varlink_get_fd(link);
        if (fd < 0)
                return log_selinux_enforcing_errno(fd, "Failed to get varlink peer fd: %m");

        /* We should call mac_selinux_get_peer_label() here similarly to get_our_contexts().
         * See the explanation there why not. */
        if (getpeercon_raw(fd, &scon) < 0)
                return log_selinux_enforcing_errno(
                                errno,
                                "Failed to get peer SELinux context%s: %m",
                                enforce ? "" : ", ignoring");

        if (!scon)
                return log_selinux_enforcing_errno(
                                SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "Peer does not have SELinux context");

        r = get_our_contexts(unit, &acon, &tclass, &fcon);
        if (r < 0)
                return log_selinux_enforcing_errno(
                                r,
                                "Failed to retrieves SELinux context of current process (perm=%s)%s: %m",
                                permission,
                                enforce ? "" : ", ignoring");

        struct audit_info audit_info = {
                .link = link,
                .path = unit ? unit->fragment_path : NULL,
                .function = function,
        };

        return check_access(scon, acon, tclass, permission, &audit_info, /* error= */ NULL);
}

#else /* HAVE_SELINUX */

int mac_selinux_access_check_bus_internal(
                sd_bus_message *message,
                const Unit *unit,
                const char *permission,
                const char *function,
                sd_bus_error *error) {

        return 0;
}

int mac_selinux_access_check_varlink_internal(
                sd_varlink *link,
                const Unit *unit,
                const char *permission,
                const char *function) {
        return 0;
}

#endif /* HAVE_SELINUX */
