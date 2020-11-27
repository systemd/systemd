/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "label.h"
#include "machine-pool.h"
#include "missing_magic.h"
#include "sd-path.h"
#include "stat-util.h"

char *machines_path(bool system) {
        char *machines_path;

        if (system)
                return strdup("/var/lib/machines");

        if (sd_path_lookup(SD_PATH_USER_SHARED, "machines", &machines_path) < 0)
                return NULL;

        return machines_path;
}

static int check_btrfs(bool system) {
        _cleanup_free_ char *machinesp = machines_path(system);
        struct statfs sfs;

        if (statfs(machinesp, &sfs) < 0) {
                char *p;
                if (errno != ENOENT)
                        return -errno;

                /* check parent */
                p = strrchr(machinesp, '/');
                if (!p)
                        return -EINVAL;

                *p = '\0';
                if (statfs(machinesp, &sfs) < 0)
                        return -errno;
        }

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

int setup_machine_directory(bool system, sd_bus_error *error) {
        _cleanup_free_ char *machinesp = machines_path(system);
        int r;

        r = check_btrfs(system);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine whether %s is located on btrfs: %m", machinesp);
        if (r == 0)
                return 0;

        (void) btrfs_subvol_make_label(machinesp);

        r = btrfs_quota_enable(machinesp, true);
        if (r < 0)
                log_warning_errno(r, "Failed to enable quota for %s, ignoring: %m", machinesp);

        r = btrfs_subvol_auto_qgroup(machinesp, 0, true);
        if (r < 0)
                log_warning_errno(r, "Failed to set up default quota hierarchy for %s, ignoring: %m", machinesp);

        return 1;
}
