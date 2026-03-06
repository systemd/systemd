/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "discover-image.h"
#include "log.h"
#include "mountpoint-util.h"
#include "runtime-scope.h"
#include "snapshot-util.h"
#include "signal-util.h"
#include "tmpfile-util.h"

int create_ephemeral_snapshot(
                const char *directory,
                RuntimeScope scope,
                bool read_only,
                LockFile *tree_global_lock,
                LockFile *tree_local_lock,
                char **ret_new_path) {

        _cleanup_free_ char *np = NULL;
        int r;

        /* If the specified path is a mount point we generate the new snapshot immediately
         * inside it under a random name. However if the specified is not a mount point we
         * create the new snapshot in the parent directory, just next to it. */
        r = path_is_mount_point(directory);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine whether directory %s is mount point: %m", directory);
        if (r > 0)
                r = tempfn_random_child(directory, "snapshot.", &np);
        else
                r = tempfn_random(directory, "snapshot.", &np);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate name for directory snapshot: %m");

        /* We take an exclusive lock on this image, since it's our private, ephemeral copy
         * only owned by us and no one else. */
        r = image_path_lock(
                        scope,
                        np,
                        LOCK_EX|LOCK_NB,
                        scope == RUNTIME_SCOPE_SYSTEM ? tree_global_lock : NULL,
                        tree_local_lock);
        if (r < 0)
                return log_debug_errno(r, "Failed to lock %s: %m", np);

        {
                BLOCK_SIGNALS(SIGINT);
                r = btrfs_subvol_snapshot_at(AT_FDCWD, directory, AT_FDCWD, np,
                                             (read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                             BTRFS_SNAPSHOT_FALLBACK_COPY |
                                             BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                             BTRFS_SNAPSHOT_RECURSIVE |
                                             BTRFS_SNAPSHOT_QUOTA |
                                             BTRFS_SNAPSHOT_SIGINT);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to create snapshot %s from %s: %m", np, directory);

        *ret_new_path = TAKE_PTR(np);

        return 0;
}
