/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "btrfs-util.h"
#include "fd-util.h"
#include "homework-directory.h"
#include "homework-quota.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tmpfile-util.h"
#include "umask-util.h"

int home_prepare_directory(UserRecord *h, bool already_activated, HomeSetup *setup) {
        assert(h);
        assert(setup);

        setup->root_fd = open(user_record_image_path(h), O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        return 0;
}

int home_activate_directory(
                UserRecord *h,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *header_home = NULL;
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        const char *hdo, *hd, *ipo, *ip;
        int r;

        assert(h);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT));
        assert(ret_home);

        assert_se(ipo = user_record_image_path(h));
        ip = strdupa(ipo); /* copy out, since reconciliation might cause changing of the field */

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa(hdo);

        r = home_prepare(h, false, cache, &setup, &header_home);
        if (r < 0)
                return r;

        r = home_refresh(h, &setup, header_home, cache, NULL, &new_home);
        if (r < 0)
                return r;

        setup.root_fd = safe_close(setup.root_fd);

        /* Create mount point to mount over if necessary */
        if (!path_equal(ip, hd))
                (void) mkdir_p(hd, 0700);

        /* Create a mount point (even if the directory is already placed correctly), as a way to indicate
         * this mount point is now "activated". Moreover, we want to set per-user
         * MS_NOSUID/MS_NOEXEC/MS_NODEV. */
        r = mount_nofollow_verbose(LOG_ERR, ip, hd, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        r = mount_nofollow_verbose(LOG_ERR, NULL, hd, NULL, MS_BIND|MS_REMOUNT|user_record_mount_flags(h), NULL);
        if (r < 0) {
                (void) umount_verbose(LOG_ERR, hd, UMOUNT_NOFOLLOW);
                return r;
        }

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_create_directory_or_subvolume(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(rm_rf_subvolume_and_freep) char *temporary = NULL;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_close_ int root_fd = -1;
        _cleanup_free_ char *d = NULL;
        const char *ip;
        int r;

        assert(h);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME));
        assert(ret_home);

        assert_se(ip = user_record_image_path(h));

        r = tempfn_random(ip, "homework", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate temporary directory: %m");

        (void) mkdir_parents(d, 0755);

        switch (user_record_storage(h)) {

        case USER_SUBVOLUME:
                RUN_WITH_UMASK(0077)
                        r = btrfs_subvol_make(d);

                if (r >= 0) {
                        log_info("Subvolume created.");

                        if (h->disk_size != UINT64_MAX) {

                                /* Enable quota for the subvolume we just created. Note we don't check for
                                 * errors here and only log about debug level about this. */
                                r = btrfs_quota_enable(d, true);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to enable quota on %s, ignoring: %m", d);

                                r = btrfs_subvol_auto_qgroup(d, 0, false);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to set up automatic quota group on %s, ignoring: %m", d);

                                /* Actually configure the quota. We also ignore errors here, but we do log
                                 * about them loudly, to keep things discoverable even though we don't
                                 * consider lacking quota support in kernel fatal. */
                                (void) home_update_quota_btrfs(h, d);
                        }

                        break;
                }
                if (r != -ENOTTY)
                        return log_error_errno(r, "Failed to create temporary home directory subvolume %s: %m", d);

                log_info("Creating subvolume %s is not supported, as file system does not support subvolumes. Falling back to regular directory.", d);
                _fallthrough_;

        case USER_DIRECTORY:

                if (mkdir(d, 0700) < 0)
                        return log_error_errno(errno, "Failed to create temporary home directory %s: %m", d);

                (void) home_update_quota_classic(h, d);
                break;

        default:
                assert_not_reached("unexpected storage");
        }

        temporary = TAKE_PTR(d); /* Needs to be destroyed now */

        root_fd = open(temporary, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to open temporary home directory: %m");

        r = home_populate(h, root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(root_fd, NULL);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET, &new_home);
        if (r < 0)
                return log_error_errno(r, "Failed to clone record: %m");

        r = user_record_add_binding(
                        new_home,
                        user_record_storage(h),
                        ip,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        NULL,
                        NULL,
                        UINT64_MAX,
                        NULL,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add binding to record: %m");

        if (rename(temporary, ip) < 0)
                return log_error_errno(errno, "Failed to rename %s to %s: %m", temporary, ip);

        temporary = mfree(temporary);

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_resize_directory(
                UserRecord *h,
                bool already_activated,
                PasswordCache *cache,
                HomeSetup *setup,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *embedded_home = NULL, *new_home = NULL;
        int r;

        assert(h);
        assert(setup);
        assert(ret_home);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT));

        r = home_prepare(h, already_activated, cache, setup, NULL);
        if (r < 0)
                return r;

        r = home_load_embedded_identity(h, setup->root_fd, NULL, USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, cache, &embedded_home, &new_home);
        if (r < 0)
                return r;

        r = home_update_quota_auto(h, NULL);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return -ESOCKTNOSUPPORT; /* make recognizable */
        if (r < 0)
                return r;

        r = home_store_embedded_identity(new_home, setup->root_fd, h->uid, embedded_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, setup);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = home_setup_undo(setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}
