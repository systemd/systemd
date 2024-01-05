/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dev-setup.h"
#include "fd-util.h"
#include "fs-util.h"
#include "label-util.h"
#include "lock-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "terminal-util.h"
#include "umask-util.h"
#include "user-util.h"

int lock_dev_console(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = open_terminal("/dev/console", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return fd;

        r = lock_generic(fd, LOCK_BSD, LOCK_EX);
        if (r < 0)
                return log_error_errno(r, "Failed to lock /dev/console: %m");

        return TAKE_FD(fd);
}

int dev_setup(const char *prefix, uid_t uid, gid_t gid) {
        static const char symlinks[] =
                "-/proc/kcore\0"     "/dev/core\0"
                "/proc/self/fd\0"    "/dev/fd\0"
                "/proc/self/fd/0\0"  "/dev/stdin\0"
                "/proc/self/fd/1\0"  "/dev/stdout\0"
                "/proc/self/fd/2\0"  "/dev/stderr\0";

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

        static const mode_t table[] = {
                S_IFREG,
                S_IFDIR,
                S_IFIFO,
                S_IFSOCK,

                /* The following two are likely to fail if we lack the privs for it (for example in an userns
                 * environment, if CAP_SYS_MKNOD is missing, or if a device node policy prohibits creation of
                 * device nodes with a major/minor of 0). But that's entirely fine. Consumers of these files
                 * should implement falling back to use a different node then, for example
                 * <root>/inaccessible/sock, which is close enough in behaviour and semantics for most uses.
                 */
                S_IFCHR,
                S_IFBLK,

                /* NB: S_IFLNK is not listed here, as there is no such thing as an inaccessible symlink */
        };

        _cleanup_close_ int parent_fd = -EBADF, inaccessible_fd = -EBADF;
        int r;

        if (!parent_dir)
                parent_dir = "/run/systemd";

        BLOCK_WITH_UMASK(0000);

        parent_fd = open(parent_dir, O_DIRECTORY|O_CLOEXEC, 0);
        if (parent_fd < 0)
                return -errno;

        inaccessible_fd = open_mkdir_at(parent_fd, "inaccessible", O_CLOEXEC, 0755);
        if (inaccessible_fd < 0)
                return inaccessible_fd;

        /* Set up inaccessible (and empty) file nodes of all types. This are used to as mount sources for over-mounting
         * ("masking") file nodes that shall become inaccessible and empty for specific containers or services. We try
         * to lock down these nodes as much as we can, but otherwise try to match them as closely as possible with the
         * underlying file, i.e. in the best case we offer the same node type as the underlying node. */

        FOREACH_ARRAY(m, table, ELEMENTSOF(table)) {
                const char *fn = inode_type_to_string(*m);
                _cleanup_free_ char *path = NULL;
                mode_t inode_type = *m;

                path = path_join(parent_dir, fn);
                if (!path)
                        return log_oom();

                if (S_ISDIR(inode_type))
                        r = mkdirat_label(inaccessible_fd, fn, 0000);
                else
                        r = RET_NERRNO(mknodat(inaccessible_fd, fn, inode_type | 0000, makedev(0, 0)));
                if (r == -EEXIST) {
                        if (fchmodat(inaccessible_fd, fn, 0000, AT_SYMLINK_NOFOLLOW) < 0)
                                log_debug_errno(errno, "Failed to adjust access mode of existing inode '%s', ignoring: %m", path);
                } else if (r < 0) {
                        log_debug_errno(r, "Failed to create '%s', ignoring: %m", path);
                        continue;
                }

                if (uid_is_valid(uid) || gid_is_valid(gid))
                        if (fchownat(inaccessible_fd, fn, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
                                log_debug_errno(errno, "Failed to chown '%s', ignoring: %m", path);
        }

        if (fchmod(inaccessible_fd, 0555) < 0)
                log_debug_errno(errno, "Failed to mark inaccessible directory read-only, ignoring: %m");

        return 0;
}
