/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dev-setup.h"
#include "label.h"
#include "log.h"
#include "mkdir-label.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "umask-util.h"
#include "user-util.h"

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
                        link_name = path_join(prefix, k);
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

int make_inaccessible_nodes(
                const char *parent_dir,
                uid_t uid,
                gid_t gid) {

        static const struct {
                const char *name;
                mode_t mode;
        } table[] = {
                { "inaccessible",      S_IFDIR  | 0755 },
                { "inaccessible/reg",  S_IFREG  | 0000 },
                { "inaccessible/dir",  S_IFDIR  | 0000 },
                { "inaccessible/fifo", S_IFIFO  | 0000 },
                { "inaccessible/sock", S_IFSOCK | 0000 },

                /* The following two are likely to fail if we lack the privs for it (for example in an userns
                 * environment, if CAP_SYS_MKNOD is missing, or if a device node policy prohibits creation of
                 * device nodes with a major/minor of 0). But that's entirely fine. Consumers of these files
                 * should implement falling back to use a different node then, for example
                 * <root>/inaccessible/sock, which is close enough in behaviour and semantics for most uses.
                 */
                { "inaccessible/chr",  S_IFCHR  | 0000 },
                { "inaccessible/blk",  S_IFBLK  | 0000 },
        };

        int r;

        if (!parent_dir)
                parent_dir = "/run/systemd";

        BLOCK_WITH_UMASK(0000);

        /* Set up inaccessible (and empty) file nodes of all types. This are used to as mount sources for over-mounting
         * ("masking") file nodes that shall become inaccessible and empty for specific containers or services. We try
         * to lock down these nodes as much as we can, but otherwise try to match them as closely as possible with the
         * underlying file, i.e. in the best case we offer the same node type as the underlying node. */

        for (size_t i = 0; i < ELEMENTSOF(table); i++) {
                _cleanup_free_ char *path = NULL;

                path = path_join(parent_dir, table[i].name);
                if (!path)
                        return log_oom();

                if (S_ISDIR(table[i].mode))
                        r = mkdir_label(path, table[i].mode & 07777);
                else
                        r = mknod_label(path, table[i].mode, makedev(0, 0));
                if (r < 0) {
                        log_debug_errno(r, "Failed to create '%s', ignoring: %m", path);
                        continue;
                }

                if (uid != UID_INVALID || gid != GID_INVALID) {
                        if (lchown(path, uid, gid) < 0)
                                log_debug_errno(errno, "Failed to chown '%s': %m", path);
                }
        }

        return 0;
}
