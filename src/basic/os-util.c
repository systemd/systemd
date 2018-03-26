/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "os-util.h"
#include "strv.h"
#include "fileio.h"
#include "string-util.h"

int path_is_os_tree(const char *path) {
        int r;

        assert(path);

        /* Does the path exist at all? If not, generate an error immediately. This is useful so that a missing root dir
         * always results in -ENOENT, and we can properly distuingish the case where the whole root doesn't exist from
         * the case where just the os-release file is missing. */
        if (laccess(path, F_OK) < 0)
                return -errno;

        /* We use {/etc|/usr/lib}/os-release as flag file if something is an OS */
        r = open_os_release(path, NULL, NULL);
        if (r == -ENOENT) /* We got nothing */
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int open_os_release(const char *root, char **ret_path, int *ret_fd) {
        _cleanup_free_ char *q = NULL;
        const char *p;
        int k;

        FOREACH_STRING(p, "/etc/os-release", "/usr/lib/os-release") {
                k = chase_symlinks(p, root, CHASE_PREFIX_ROOT|(ret_fd ? CHASE_OPEN : 0), (ret_path ? &q : NULL));
                if (k != -ENOENT)
                        break;
        }
        if (k < 0)
                return k;

        if (ret_fd) {
                int real_fd;

                /* Convert the O_PATH fd into a proper, readable one */
                real_fd = fd_reopen(k, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                safe_close(k);
                if (real_fd < 0)
                        return real_fd;

                *ret_fd = real_fd;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(q);

        return 0;
}

int fopen_os_release(const char *root, char **ret_path, FILE **ret_file) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        FILE *f;
        int r;

        if (!ret_file)
                return open_os_release(root, ret_path, NULL);

        r = open_os_release(root, ret_path ? &p : NULL, &fd);
        if (r < 0)
                return r;

        f = fdopen(fd, "re");
        if (!f)
                return -errno;
        fd = -1;

        *ret_file = f;

        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return 0;
}

int parse_os_release(const char *root, ...) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        va_list ap;
        int r;

        r = fopen_os_release(root, &p, &f);
        if (r < 0)
                return r;

        va_start(ap, root);
        r = parse_env_filev(f, p, NEWLINE, ap);
        va_end(ap);

        return r;
}

int load_os_release_pairs(const char *root, char ***ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        r = fopen_os_release(root, &p, &f);
        if (r < 0)
                return r;

        return load_env_file_pairs(f, p, NEWLINE, ret);
}
