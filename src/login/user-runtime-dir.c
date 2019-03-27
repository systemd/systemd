/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdint.h>
#include <sys/mount.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "fs-util.h"
#include "format-util.h"
#include "label.h"
#include "main-func.h"
#include "mkdir.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static int acquire_runtime_dir_size(uint64_t *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_get_property_trivial(bus, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "RuntimeDirectorySize", &error, 't', ret);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire runtime directory size: %s", bus_error_message(&error, r));

        return 0;
}

static int user_mkdir_runtime_path(
                const char *runtime_path,
                uid_t uid,
                gid_t gid,
                uint64_t runtime_dir_size) {

        int r;

        assert(runtime_path);
        assert(path_is_absolute(runtime_path));
        assert(uid_is_valid(uid));
        assert(gid_is_valid(gid));

        r = mkdir_safe_label("/run/user", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/user: %m");

        if (path_is_mount_point(runtime_path, NULL, 0) >= 0)
                log_debug("%s is already a mount point", runtime_path);
        else {
                char options[sizeof("mode=0700,uid=,gid=,size=,smackfsroot=*")
                             + DECIMAL_STR_MAX(uid_t)
                             + DECIMAL_STR_MAX(gid_t)
                             + DECIMAL_STR_MAX(uint64_t)];

                xsprintf(options,
                         "mode=0700,uid=" UID_FMT ",gid=" GID_FMT ",size=%" PRIu64 "%s",
                         uid, gid, runtime_dir_size,
                         mac_smack_use() ? ",smackfsroot=*" : "");

                (void) mkdir_label(runtime_path, 0700);

                r = mount("tmpfs", runtime_path, "tmpfs", MS_NODEV|MS_NOSUID, options);
                if (r < 0) {
                        if (!IN_SET(errno, EPERM, EACCES)) {
                                r = log_error_errno(errno, "Failed to mount per-user tmpfs directory %s: %m", runtime_path);
                                goto fail;
                        }

                        log_debug_errno(errno, "Failed to mount per-user tmpfs directory %s.\n"
                                        "Assuming containerized execution, ignoring: %m", runtime_path);

                        r = chmod_and_chown(runtime_path, 0700, uid, gid);
                        if (r < 0) {
                                log_error_errno(r, "Failed to change ownership and mode of \"%s\": %m", runtime_path);
                                goto fail;
                        }
                }

                r = label_fix(runtime_path, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to fix label of \"%s\", ignoring: %m", runtime_path);
        }

        return 0;

fail:
        /* Try to clean up, but ignore errors */
        (void) rmdir(runtime_path);
        return r;
}

static int user_remove_runtime_path(const char *runtime_path) {
        int r;

        assert(runtime_path);
        assert(path_is_absolute(runtime_path));

        r = rm_rf(runtime_path, 0);
        if (r < 0)
                log_debug_errno(r, "Failed to remove runtime directory %s (before unmounting), ignoring: %m", runtime_path);

        /* Ignore cases where the directory isn't mounted, as that's quite possible, if we lacked the permissions to
         * mount something */
        r = umount2(runtime_path, MNT_DETACH);
        if (r < 0 && !IN_SET(errno, EINVAL, ENOENT))
                log_debug_errno(errno, "Failed to unmount user runtime directory %s, ignoring: %m", runtime_path);

        r = rm_rf(runtime_path, REMOVE_ROOT);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to remove runtime directory %s (after unmounting): %m", runtime_path);

        return 0;
}

static int do_mount(const char *user) {
        char runtime_path[sizeof("/run/user") + DECIMAL_STR_MAX(uid_t)];
        uint64_t runtime_dir_size;
        uid_t uid;
        gid_t gid;
        int r;

        r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ESRCH ? "No such user \"%s\"" :
                                       r == -ENOMSG ? "UID \"%s\" is invalid or has an invalid main group"
                                                    : "Failed to look up user \"%s\": %m",
                                       user);

        r = acquire_runtime_dir_size(&runtime_dir_size);
        if (r < 0)
                return r;

        xsprintf(runtime_path, "/run/user/" UID_FMT, uid);

        log_debug("Will mount %s owned by "UID_FMT":"GID_FMT, runtime_path, uid, gid);
        return user_mkdir_runtime_path(runtime_path, uid, gid, runtime_dir_size);
}

static int do_umount(const char *user) {
        char runtime_path[sizeof("/run/user") + DECIMAL_STR_MAX(uid_t)];
        uid_t uid;
        int r;

        /* The user may be already removed. So, first try to parse the string by parse_uid(),
         * and if it fails, fallback to get_user_creds().*/
        if (parse_uid(user, &uid) < 0) {
                r = get_user_creds(&user, &uid, NULL, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r,
                                               r == -ESRCH ? "No such user \"%s\"" :
                                               r == -ENOMSG ? "UID \"%s\" is invalid or has an invalid main group"
                                                            : "Failed to look up user \"%s\": %m",
                                               user);
        }

        xsprintf(runtime_path, "/run/user/" UID_FMT, uid);

        log_debug("Will remove %s", runtime_path);
        return user_remove_runtime_path(runtime_path);
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes two arguments.");
        if (!STR_IN_SET(argv[1], "start", "stop"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "First argument must be either \"start\" or \"stop\".");

        r = mac_selinux_init();
        if (r < 0)
                return log_error_errno(r, "Could not initialize labelling: %m\n");

        umask(0022);

        if (streq(argv[1], "start"))
                return do_mount(argv[2]);
        if (streq(argv[1], "stop"))
                return do_umount(argv[2]);
        assert_not_reached("Unknown verb!");
}

DEFINE_MAIN_FUNCTION(run);
