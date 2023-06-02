/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <sys/swap.h>

#include "alloc-util.h"
#include "detach-swap.h"
#include "libmount-util.h"

int swap_list_get(const char *swaps, MountPoint **head) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *t = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *i = NULL;
        int r;

        assert(head);

        t = mnt_new_table();
        i = mnt_new_iter(MNT_ITER_FORWARD);
        if (!t || !i)
                return log_oom();

        r = mnt_table_parse_swaps(t, swaps);
        if (r == -ENOENT) /* no /proc/swaps is fine */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s: %m", swaps ?: "/proc/swaps");

        for (;;) {
                struct libmnt_fs *fs;
                _cleanup_free_ MountPoint *swap = NULL;
                const char *source;

                r = mnt_table_next_fs(t, i, &fs);
                if (r == 1) /* EOF */
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from %s: %m", swaps ?: "/proc/swaps");

                source = mnt_fs_get_source(fs);
                if (!source)
                        continue;

                swap = new0(MountPoint, 1);
                if (!swap)
                        return log_oom();

                swap->path = strdup(source);
                if (!swap->path)
                        return log_oom();

                LIST_PREPEND(mount_point, *head, TAKE_PTR(swap));
        }

        return 0;
}

static int swap_points_list_off(MountPoint **head, bool *changed) {
        int n_failed = 0;

        assert(head);
        assert(changed);

        LIST_FOREACH(mount_point, m, *head) {
                log_info("Deactivating swap %s.", m->path);
                if (swapoff(m->path) < 0) {
                        log_warning_errno(errno, "Could not deactivate swap %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

int swapoff_all(bool *changed) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, swap_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(swap_list_head);

        r = swap_list_get(NULL, &swap_list_head);
        if (r < 0)
                return r;

        return swap_points_list_off(&swap_list_head, changed);
}
