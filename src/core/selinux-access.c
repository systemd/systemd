/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "errno-util.h"
#include "format-util.h"
#include "log.h"
#include "path-util.h"
#include "selinux-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "util.h"

static bool initialized = false;

struct audit_info {
        sd_bus_creds *creds;
        const char *path;
        const char *cmdline;
        const char *function;
};

struct compat_permission_verb {
        const char *overhaul;
        const char *original;
};

const char *const mac_selinux_overhaul_instance_class = "systemd_instance";
const char *const mac_selinux_original_instance_class = "system";
const struct compat_permission_verb mac_selinux_instance_permissions[_MAC_SELINUX_INSTANCE_PERMISSION_MAX] = {
        [MAC_SELINUX_INSTANCE_STARTTRANSIENT]           = { "start_transient",          "start" },
        [MAC_SELINUX_INSTANCE_CLEARJOBS]                = { "clear_jobs",               "reload" },
        [MAC_SELINUX_INSTANCE_RESETFAILED]              = { "reset_failed",             "reload" },
        [MAC_SELINUX_INSTANCE_LISTUNITS]                = { "list_units",               "status" },
        [MAC_SELINUX_INSTANCE_LISTJOBS]                 = { "list_jobs",                "status" },
        [MAC_SELINUX_INSTANCE_SUBSCRIBE]                = { "subscribe",                "status" },
        [MAC_SELINUX_INSTANCE_UNSUBSCRIBE]              = { "unsubscribe",              "status" },
        [MAC_SELINUX_INSTANCE_DUMP]                     = { "dump",                     "status" },
        [MAC_SELINUX_INSTANCE_RELOAD]                   = { "reload",                   "reload" },
        [MAC_SELINUX_INSTANCE_REEXECUTE]                = { "reexecute",                "reload" },
        [MAC_SELINUX_INSTANCE_EXIT]                     = { "exit",                     "halt" },
        [MAC_SELINUX_INSTANCE_REBOOT]                   = { "reboot",                   "reboot" },
        [MAC_SELINUX_INSTANCE_POWEROFFORHALT]           = { "poweroff_or_halt",         "halt" },
        [MAC_SELINUX_INSTANCE_KEXEC]                    = { "kexec",                    "reboot" },
        [MAC_SELINUX_INSTANCE_SWITCHROOT]               = { "switch_root",              "reboot" },
        [MAC_SELINUX_INSTANCE_SETENVIRONMENT]           = { "set_environment",          "reload" },
        [MAC_SELINUX_INSTANCE_UNSETENVIRONMENT]         = { "unset_environment",        "reload" },
        [MAC_SELINUX_INSTANCE_SETEXITCODE]              = { "set_exit_code",            "exit" },
        [MAC_SELINUX_INSTANCE_LISTUNITFILES]            = { "list_unit_files",          "status" },
        [MAC_SELINUX_INSTANCE_STATEUNITFILE]            = { "state_unit_file",          "status" },
        [MAC_SELINUX_INSTANCE_GETDEFAULTTARGET]         = { "get_default_target",       "status" },
        [MAC_SELINUX_INSTANCE_SETDEFAULTTARGET]         = { "set_default_target",       "enable" },
        [MAC_SELINUX_INSTANCE_PRESETALLUNITFILES]       = { "preset_all_unit_files",    "enable" },
        [MAC_SELINUX_INSTANCE_RAWSET]                   = { "raw_set",                  "reload" },
        [MAC_SELINUX_INSTANCE_RAWSTATUS]                = { "raw_status",               "status" },
        [MAC_SELINUX_INSTANCE_SETLOGTARGET]             = { "set_log_target",           "reload" },
        [MAC_SELINUX_INSTANCE_SETLOGLEVEL]              = { "set_log_level",            "reload" },
        [MAC_SELINUX_INSTANCE_GETUNITFILELINKS]         = { "get_unit_file_links",      "status" },
        [MAC_SELINUX_INSTANCE_ADDDEPENDENCYUNITFILES]   = { "add_dependency_unit_files", "reload" },
        [MAC_SELINUX_INSTANCE_GETDYNAMICUSERS]          = { "get_dynamic_users",        NULL },
        [MAC_SELINUX_INSTANCE_SETWATCHDOG]              = { "set_watchdog",             "reload" },
};

const char *const mac_selinux_overhaul_unit_class = "systemd_unit";
const char *const mac_selinux_original_unit_class = "service";
const struct compat_permission_verb mac_selinux_unit_permissions[_MAC_SELINUX_UNIT_PERMISSION_MAX] = {
        [MAC_SELINUX_UNIT_GETJOB]                       = { "get_job",                  "status" },
        [MAC_SELINUX_UNIT_GETUNIT]                      = { "get_unit",                 "status" },
        [MAC_SELINUX_UNIT_START]                        = { "start",                    "start" },
        [MAC_SELINUX_UNIT_STOP]                         = { "stop",                     "stop" },
        [MAC_SELINUX_UNIT_RELOAD]                       = { "reload",                   "reload" },
        [MAC_SELINUX_UNIT_RESTART]                      = { "restart",                  "start" },
        [MAC_SELINUX_UNIT_NOP]                          = { "nop",                      "reload" },
        [MAC_SELINUX_UNIT_CANCEL]                       = { "cancel",                   "stop" },
        [MAC_SELINUX_UNIT_ABANDON]                      = { "abandon",                  "stop" },
        [MAC_SELINUX_UNIT_KILL]                         = { "kill",                     "stop" },
        [MAC_SELINUX_UNIT_RESETFAILED]                  = { "reset_failed",             "reload" },
        [MAC_SELINUX_UNIT_SETPROPERTIES]                = { "set_properties",           "start" },
        [MAC_SELINUX_UNIT_REF]                          = { "ref",                      "start" },
        [MAC_SELINUX_UNIT_CLEAN]                        = { "clean",                    "stop" },
        [MAC_SELINUX_UNIT_GETPROCESSES]                 = { "get_processes",            "status" },
        [MAC_SELINUX_UNIT_ATTACHPROCESSES]              = { "attach_processes",         "start" },
        [MAC_SELINUX_UNIT_RAWSET]                       = { "raw_set",                  "reload" },
        [MAC_SELINUX_UNIT_RAWSTATUS]                    = { "raw_status",               "status" },
        [MAC_SELINUX_UNIT_BINDMOUNT]                    = { "bind_mount",               "start" },
        [MAC_SELINUX_UNIT_GETWAITING_JOBS]              = { "get_waiting_jobs",         "status" },
        [MAC_SELINUX_UNIT_UNREF]                        = { "unref",                    "stop" },
        [MAC_SELINUX_UNIT_LOADUNIT]                     = { "load_unit",                NULL },
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
                 "auid=%s uid=%s gid=%s%s%s%s%s%s%s%s%s%s",
                 login_uid_buf, uid_buf, gid_buf,
                 audit->path ? " path=\"" : "", strempty(audit->path), audit->path ? "\"" : "",
                 audit->cmdline ? " cmdline=\"" : "", strempty(audit->cmdline), audit->cmdline ? "\"" : "",
                 audit->function ? " function=\"" : "", strempty(audit->function), audit->function ? "\"" : "");

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

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_AUTH | callback_type_to_priority(type),
                      0, PROJECT_FILE, __LINE__, __FUNCTION__,
                      fmt2, ap);
        REENABLE_WARNING;
        va_end(ap);

        return 0;
}

static int access_init(sd_bus_error *error) {

        if (!mac_selinux_use())
                return 0;

        if (initialized)
                return 1;

        if (avc_open(NULL, 0) != 0) {
                int saved_errno = errno;
                bool enforce;

                enforce = security_getenforce() != 0;
                log_full_errno(enforce ? LOG_ERR : LOG_WARNING, saved_errno, "Failed to open the SELinux AVC: %m");

                /* If enforcement isn't on, then let's suppress this
                 * error, and just don't do any AVC checks. The
                 * warning we printed is hence all the admin will
                 * see. */
                if (!enforce)
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
        _cleanup_free_ char *cl = NULL;
        _cleanup_freecon_ char *fcon = NULL;
        char **cmdline = NULL;
        bool enforce;
        int r = 0;

        assert(message);
        assert(class);
        assert(permission);
        assert(error);
        assert(func);

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

        /* The SELinux context is something we really should have
         * gotten directly from the message or sender, and not be an
         * augmented field. If it was augmented we cannot use it for
         * authorization, since this is racy and vulnerable. Let's add
         * an extra check, just in case, even though this really
         * shouldn't be possible. */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_SELINUX_CONTEXT) == 0, -EPERM);

        r = sd_bus_creds_get_selinux_context(creds, &scon);
        if (r < 0)
                return r;

        if (path) {
                /* Get the file context of the unit file */

                if (getfilecon_raw(path, &fcon) < 0) {
                        r = -errno;

                        log_warning_errno(r, "SELinux getfilecon_raw() on '%s' failed%s (perm=%s): %m",
                                          path,
                                          enforce ? "" : ", ignoring",
                                          permission);
                        if (!enforce)
                                return 0;

                        return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get file context on %s.", path);
                }

        } else {
                if (getcon_raw(&fcon) < 0) {
                        r = -errno;

                        log_warning_errno(r, "SELinux getcon_raw() failed%s (perm=%s): %m",
                                          enforce ? "" : ", ignoring",
                                          permission);
                        if (!enforce)
                                return 0;

                        return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Failed to get current context.");
                }
        }

        sd_bus_creds_get_cmdline(creds, &cmdline);
        cl = strv_join(cmdline, " ");

        struct audit_info audit_info = {
                .creds = creds,
                .path = path,
                .cmdline = cl,
                .function = func,
        };

        r = selinux_check_access(scon, fcon, class, permission, &audit_info);
        if (r < 0) {
                r = errno_or_else(EPERM);

                if (enforce)
                        sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "SELinux policy denies access.");
        }

        log_debug_errno(r, "SELinux access check scon=%s tcon=%s tclass=%s perm=%s state=%s path=%s cmdline='%s' func=%s result=%m",
                        scon, fcon, class, permission, enforce ? "enforcing" : "permissive", strna(path), cl, func);
        return enforce ? r : 0;
}

int _mac_selinux_instance_access_check_internal(
                sd_bus_message *message,
                mac_selinux_instance_permission permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *verb;

        assert(message);
        assert(permission >= 0);
        assert(permission < _MAC_SELINUX_INSTANCE_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_instance_class;
                verb = mac_selinux_instance_permissions[permission].overhaul;
        } else {
                class = mac_selinux_original_instance_class;
                verb = mac_selinux_instance_permissions[permission].original;
        }

        /* skip check if variant does not serve permission */
        if (!verb) {
                log_debug("SELinux access check skipped (overhaul=%d func=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, NULL, class, verb, error, func);
}

int _mac_selinux_unit_access_check_internal(
                const Unit *unit,
                sd_bus_message *message,
                mac_selinux_unit_permission permission,
                sd_bus_error *error,
                const char *func) {

        const char *class;
        const char *verb;
        const char *path;

        assert(unit);
        assert(message);
        assert(permission >= 0);
        assert(permission < _MAC_SELINUX_UNIT_PERMISSION_MAX);
        assert(error);
        assert(func);

        if (!mac_selinux_use())
                return 0;

        path = unit_label_path(unit);

        if (mac_selinux_overhaul_enabled()) {
                class = mac_selinux_overhaul_unit_class;
                verb = mac_selinux_unit_permissions[permission].overhaul;
        } else {
                class = path ? mac_selinux_original_unit_class : mac_selinux_original_instance_class;
                verb = mac_selinux_unit_permissions[permission].original;
        }

        /* skip check if variant does not serve permission */
        if (!verb) {
                log_debug("SELinux unit access check skipped (overhaul=%d func=%s)", mac_selinux_overhaul_enabled(), func);
                return 0;
        }

        return mac_selinux_generic_access_check(message, path, class, verb, error, func);
}

#endif /* HAVE_SELINUX */
