/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dev-setup.h"
#include "label.h"
#include "log.h"
#include "path-util.h"
#include "user-util.h"
#include "util.h"

int dev_setup(const char *prefix, uid_t uid, gid_t gid) {
        static const char symlinks[] =
                "-/proc/kcore\0"     "/dev/core\0"
                "/proc/self/fd\0"    "/dev/fd\0"
                "/proc/self/fd/0\0"  "/dev/stdin\0"
                "/proc/self/fd/1\0"  "/dev/stdout\0"
                "/proc/self/fd/2\0"  "/dev/stderr\0";

        const char *j, *k;
        int r;

        NULSTR_FOREACH_PAIR(j, k, symlinks) {
                _cleanup_free_ char *link_name = NULL;
                const char *n;

                if (j[0] == '-') {
                        j++;

                        if (access(j, F_OK) < 0)
                                continue;
                }

                if (prefix) {
                        link_name = prefix_root(prefix, k);
                        if (!link_name)
                                return -ENOMEM;

                        n = link_name;
                } else
                        n = k;

                r = symlink_label(j, n);
                if (r < 0)
                        log_debug_errno(r, "Failed to symlink %s to %s: %m", j, n);

                if (uid != UID_INVALID || gid != GID_INVALID)
                        if (lchown(n, uid, gid) < 0)
                                log_debug_errno(errno, "Failed to chown %s: %m", n);
        }

        return 0;
}
