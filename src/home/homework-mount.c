/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/mount.h>

#include "alloc-util.h"
#include "homework-mount.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "string-util.h"

static const char *mount_options_for_fstype(const char *fstype) {
        if (streq(fstype, "ext4"))
                return "noquota,user_xattr";
        if (streq(fstype, "xfs"))
                return "noquota";
        if (streq(fstype, "btrfs"))
                return "noacl";
        return NULL;
}

int home_mount_node(const char *node, const char *fstype, bool discard, unsigned long flags) {
        _cleanup_free_ char *joined = NULL;
        const char *options, *discard_option;
        int r;

        options = mount_options_for_fstype(fstype);

        discard_option = discard ? "discard" : "nodiscard";

        if (options) {
                joined = strjoin(options, ",", discard_option);
                if (!joined)
                        return log_oom();

                options = joined;
        } else
                options = discard_option;

        r = mount_nofollow_verbose(LOG_ERR, node, "/run/systemd/user-home-mount", fstype, flags|MS_RELATIME, strempty(options));
        if (r < 0)
                return r;

        log_info("Mounting file system completed.");
        return 0;
}

int home_unshare_and_mount(const char *node, const char *fstype, bool discard, unsigned long flags) {
        int r;

        if (unshare(CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Couldn't unshare file system namespace: %m");

        r = mount_nofollow_verbose(LOG_ERR, "/run", "/run", NULL, MS_SLAVE|MS_REC, NULL); /* Mark /run as MS_SLAVE in our new namespace */
        if (r < 0)
                return r;

        (void) mkdir_p("/run/systemd/user-home-mount", 0700);

        if (node)
                return home_mount_node(node, fstype, discard, flags);

        return 0;
}

int home_move_mount(const char *user_name_and_realm, const char *target) {
        _cleanup_free_ char *subdir = NULL;
        const char *d;
        int r;

        assert(target);

        /* If user_name_and_realm is set, then we'll mount a subdir of the source mount into the host. If
         * it's NULL we'll move the mount itself */
        if (user_name_and_realm) {
                subdir = path_join("/run/systemd/user-home-mount/", user_name_and_realm);
                if (!subdir)
                        return log_oom();

                d = subdir;
        } else
                d = "/run/systemd/user-home-mount/";

        (void) mkdir_p(target, 0700);

        r = mount_nofollow_verbose(LOG_ERR, d, target, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        r = umount_verbose(LOG_ERR, "/run/systemd/user-home-mount", UMOUNT_NOFOLLOW);
        if (r < 0)
                return r;

        log_info("Moving to final mount point %s completed.", target);
        return 0;
}
