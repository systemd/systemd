/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "btrfs-util.h"
#include "fd-util.h"
#include "homework-bulk.h"
#include "homework-directory.h"
#include "homework-mount.h"
#include "homework-quota.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"

int home_setup_directory(UserRecord *h, HomeSetup *setup) {
        const char *ip;
        int r;

        assert(h);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME));
        assert(setup);
        assert(!setup->undo_mount);
        assert(setup->root_fd < 0);

        /* We'll bind mount the image directory to a new mount point where we'll start adjusting it. Only
         * once that's complete we'll move the thing to its final place eventually. */
        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        assert_se(ip = user_record_image_path(h));

        r = mount_follow_verbose(LOG_ERR, ip, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        setup->undo_mount = true;

        /* Turn off any form of propagation for this */
        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_PRIVATE, NULL);
        if (r < 0)
                return r;

        /* Adjust MS_SUID and similar flags */
        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND|MS_REMOUNT|user_record_mount_flags(h), NULL);
        if (r < 0)
                return r;

        setup->root_fd = open(HOME_RUNTIME_WORK_DIR, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        return 0;
}

int home_activate_directory(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *header_home = NULL;
        const char *hd, *hdo;
        int r;

        assert(h);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT));
        assert(setup);
        assert(ret_home);

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa_safe(hdo);

        r = home_setup(h, flags, setup, cache, &header_home);
        if (r < 0)
                return r;

        r = home_refresh(h, flags, setup, header_home, cache, NULL, &new_home);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, setup);
        if (r < 0)
                return r;

        /* Close fd to private mount before moving mount */
        setup->root_fd = safe_close(setup->root_fd);

        /* We are now done with everything, move the mount into place */
        r = home_move_mount(NULL, hd);
        if (r < 0)
                return r;

        setup->undo_mount = false;

        setup->do_drop_caches = false;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_create_directory_or_subvolume(UserRecord *h, HomeSetup *setup, UserRecord **ret_home) {
        _cleanup_(rm_rf_subvolume_and_freep) char *temporary = NULL;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_close_ int mount_fd = -EBADF;
        _cleanup_free_ char *d = NULL;
        bool is_subvolume = false;
        const char *ip;
        int r;

        assert(h);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME));
        assert(setup);
        assert(ret_home);

        assert_se(ip = user_record_image_path(h));

        r = tempfn_random(ip, "homework", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate temporary directory: %m");

        (void) mkdir_parents(d, 0755);

        switch (user_record_storage(h)) {

        case USER_SUBVOLUME:
                WITH_UMASK(0077)
                        r = btrfs_subvol_make(AT_FDCWD, d);

                if (r >= 0) {
                        log_info("Subvolume created.");
                        is_subvolume = true;

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
                assert_not_reached();
        }

        temporary = TAKE_PTR(d); /* Needs to be destroyed now */

        /* Let's decouple namespaces now, so that we can possibly mount a UID map mount into
         * /run/systemd/user-home-mount/ that no one will see but us. */
        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        setup->root_fd = open(temporary, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open temporary home directory: %m");

        /* Try to apply a UID shift, so that the directory is actually owned by "nobody", and is only mapped
         * to the proper UID while active. — Well, that's at least the theory. Unfortunately, only btrfs does
         * per-subvolume quota. The others do per-uid quota. Which means mapping all home directories to the
         * same UID of "nobody" makes quota impossible. Hence unless we actually managed to create a btrfs
         * subvolume for this user we'll map the user's UID to itself. Now you might ask: why bother mapping
         * at all? It's because we want to restrict the UIDs used on the home directory: we leave all other
         * UIDs of the homed UID range unmapped, thus making them unavailable to programs accessing the
         * mount. */
        r = home_shift_uid(setup->root_fd, HOME_RUNTIME_WORK_DIR, is_subvolume ? UID_NOBODY : h->uid, h->uid, &mount_fd);
        if (r > 0)
                setup->undo_mount = true; /* If uidmaps worked we have a mount to undo again */

        if (mount_fd >= 0) {
                /* If we have established a new mount, then we can use that as new root fd to our home directory. */
                safe_close(setup->root_fd);

                setup->root_fd = fd_reopen(mount_fd, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (setup->root_fd < 0)
                        return log_error_errno(setup->root_fd, "Unable to convert mount fd into proper directory fd: %m");

                mount_fd = safe_close(mount_fd);
        }

        r = home_populate(h, setup->root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &new_home);
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

        setup->root_fd = safe_close(setup->root_fd);

        /* Unmount mapped mount before we move the dir into place */
        r = home_setup_undo_mount(setup, LOG_ERR);
        if (r < 0)
                return r;

        if (rename(temporary, ip) < 0)
                return log_error_errno(errno, "Failed to rename %s to %s: %m", temporary, ip);

        temporary = mfree(temporary);

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_resize_directory(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *embedded_home = NULL, *new_home = NULL;
        int r, reconciled;

        assert(h);
        assert(setup);
        assert(ret_home);
        assert(IN_SET(user_record_storage(h), USER_DIRECTORY, USER_SUBVOLUME, USER_FSCRYPT));

        r = home_setup(h, flags, setup, cache, NULL);
        if (r < 0)
                return r;

        reconciled = home_load_embedded_identity(h, setup->root_fd, NULL, USER_RECONCILE_REQUIRE_NEWER_OR_EQUAL, cache, &embedded_home, &new_home);
        if (reconciled < 0)
                return reconciled;

        r = home_maybe_shift_uid(h, flags, setup);
        if (r < 0)
                return r;

        r = home_update_quota_auto(h, NULL);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return -ESOCKTNOSUPPORT; /* make recognizable */
        if (r < 0)
                return r;

        r = home_store_embedded_identity(new_home, setup->root_fd, embedded_home);
        if (r < 0)
                return r;

        r = home_reconcile_bulk_dirs(new_home, setup->root_fd, reconciled);
        if (r < 0)
                return r;

        r = home_extend_embedded_identity(new_home, h, setup);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = home_setup_done(setup);
        if (r < 0)
                return r;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}
