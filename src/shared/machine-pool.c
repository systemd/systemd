/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "btrfs-util.h"
#include "label.h"
#include "machine-pool.h"
#include "missing_magic.h"
#include "stat-util.h"

static int check_btrfs(void) {
        struct statfs sfs;

        if (statfs("/var/lib/machines", &sfs) < 0) {
                if (errno != ENOENT)
                        return -errno;

                if (statfs("/var/lib", &sfs) < 0)
                        return -errno;
        }

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

int setup_machine_directory(sd_bus_error *error, bool use_btrfs_subvol, bool use_btrfs_quota) {
        int r;

        r = check_btrfs();
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine whether /var/lib/machines is located on btrfs: %m");
        if (r == 0)
                return 0;

        if (!use_btrfs_subvol)
                return 0;

        (void) btrfs_subvol_make_label("/var/lib/machines");

        if (!use_btrfs_quota)
                return 0;

        r = btrfs_quota_enable("/var/lib/machines", true);
        if (r < 0)
                log_warning_errno(r, "Failed to enable quota for /var/lib/machines, ignoring: %m");

        r = btrfs_subvol_auto_qgroup("/var/lib/machines", 0, true);
        if (r < 0)
                log_warning_errno(r, "Failed to set up default quota hierarchy for /var/lib/machines, ignoring: %m");

        return 0;
}
