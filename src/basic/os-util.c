/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "dirent-util.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "xattr-util.h"

bool image_name_is_valid(const char *s) {
        if (!filename_is_valid(s))
                return false;

        if (string_has_cc(s, NULL))
                return false;

        if (!utf8_is_valid(s))
                return false;

        /* Temporary files for atomically creating new files */
        if (startswith(s, ".#"))
                return false;

        return true;
}

int path_is_extension_tree(const char *path, const char *extension) {
        int r;

        assert(path);

        /* Does the path exist at all? If not, generate an error immediately. This is useful so that a missing root dir
         * always results in -ENOENT, and we can properly distinguish the case where the whole root doesn't exist from
         * the case where just the os-release file is missing. */
        if (laccess(path, F_OK) < 0)
                return -errno;

        /* We use /usr/lib/extension-release.d/extension-release[.NAME] as flag for something being a system extension,
         * and {/etc|/usr/lib}/os-release as a flag for something being an OS (when not an extension). */
        r = open_extension_release(path, extension, NULL, NULL);
        if (r == -ENOENT) /* We got nothing */
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int open_extension_release(const char *root, const char *extension, char **ret_path, int *ret_fd) {
        _cleanup_free_ char *q = NULL;
        int r, fd;

        if (extension) {
                const char *extension_full_path;

                if (!image_name_is_valid(extension))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "The extension name %s is invalid.", extension);

                extension_full_path = strjoina("/usr/lib/extension-release.d/extension-release.", extension);
                r = chase_symlinks(extension_full_path, root, CHASE_PREFIX_ROOT,
                                   ret_path ? &q : NULL,
                                   ret_fd ? &fd : NULL);
                log_full_errno_zerook(LOG_DEBUG, MIN(r, 0), "Checking for %s: %m", extension_full_path);

                /* Cannot find the expected extension-release file? The image filename might have been
                 * mangled on deployment, so fallback to checking for any file in the extension-release.d
                 * directory, and return the first one with a user.extension-release xattr instead.
                 * The user.extension-release.strict xattr is checked to ensure the author of the image
                 * considers it OK if names do not match. */
                if (r == -ENOENT) {
                        _cleanup_free_ char *extension_release_dir_path = NULL;
                        _cleanup_closedir_ DIR *extension_release_dir = NULL;

                        r = chase_symlinks_and_opendir("/usr/lib/extension-release.d/", root, CHASE_PREFIX_ROOT,
                                                       &extension_release_dir_path, &extension_release_dir);
                        if (r < 0)
                                return log_debug_errno(r, "Cannot open %s/usr/lib/extension-release.d/, ignoring: %m", root);

                        r = -ENOENT;
                        FOREACH_DIRENT(de, extension_release_dir, return -errno) {
                                int k;

                                if (!IN_SET(de->d_type, DT_REG, DT_UNKNOWN))
                                        continue;

                                const char *image_name = startswith(de->d_name, "extension-release.");
                                if (!image_name)
                                        continue;

                                if (!image_name_is_valid(image_name)) {
                                        log_debug("%s/%s is not a valid extension-release file name, ignoring.",
                                                  extension_release_dir_path, de->d_name);
                                        continue;
                                }

                                /* We already chased the directory, and checked that
                                 * this is a real file, so we shouldn't fail to open it. */
                                _cleanup_close_ int extension_release_fd = openat(dirfd(extension_release_dir),
                                                                                  de->d_name,
                                                                                  O_PATH|O_CLOEXEC|O_NOFOLLOW);
                                if (extension_release_fd < 0)
                                        return log_debug_errno(errno,
                                                               "Failed to open extension-release file %s/%s: %m",
                                                               extension_release_dir_path,
                                                               de->d_name);

                                /* Really ensure it is a regular file after we open it. */
                                if (fd_verify_regular(extension_release_fd) < 0) {
                                        log_debug("%s/%s is not a regular file, ignoring.", extension_release_dir_path, de->d_name);
                                        continue;
                                }

                                /* No xattr or cannot parse it? Then skip this. */
                                _cleanup_free_ char *extension_release_xattr = NULL;
                                k = fgetxattr_malloc(extension_release_fd, "user.extension-release.strict", &extension_release_xattr);
                                if (k < 0 && !ERRNO_IS_NOT_SUPPORTED(k) && k != -ENODATA)
                                        log_debug_errno(k,
                                                        "%s/%s: Failed to read 'user.extension-release.strict' extended attribute from file: %m",
                                                        extension_release_dir_path, de->d_name);
                                if (k < 0) {
                                        log_debug("%s/%s does not have user.extension-release.strict xattr, ignoring.", extension_release_dir_path, de->d_name);
                                        continue;
                                }

                                /* Explicitly set to request strict matching? Skip it. */
                                k = parse_boolean(extension_release_xattr);
                                if (k < 0)
                                        log_debug_errno(k,
                                                        "%s/%s: Failed to parse 'user.extension-release.strict' extended attribute from file: %m",
                                                        extension_release_dir_path, de->d_name);
                                else if (k > 0)
                                        log_debug("%s/%s: 'user.extension-release.strict' attribute is true, ignoring file.",
                                                  extension_release_dir_path, de->d_name);
                                if (k != 0)
                                        continue;

                                log_debug("%s/%s: 'user.extension-release.strict' attribute is false…",
                                          extension_release_dir_path, de->d_name);

                                /* We already found what we were looking for, but there's another candidate?
                                 * We treat this as an error, as we want to enforce that there are no ambiguities
                                 * in case we are in the fallback path.*/
                                if (r == 0) {
                                        r = -ENOTUNIQ;
                                        break;
                                }

                                r = 0; /* Found it! */

                                if (ret_fd)
                                        fd = TAKE_FD(extension_release_fd);

                                if (ret_path) {
                                        q = path_join(extension_release_dir_path, de->d_name);
                                        if (!q)
                                                return -ENOMEM;
                                }
                        }
                }
        } else {
                const char *p;

                FOREACH_STRING(p, "/etc/os-release", "/usr/lib/os-release") {
                        r = chase_symlinks(p, root, CHASE_PREFIX_ROOT,
                                           ret_path ? &q : NULL,
                                           ret_fd ? &fd : NULL);
                        if (r != -ENOENT)
                                break;
                }
        }
        if (r < 0)
                return r;

        if (ret_fd) {
                int real_fd;

                /* Convert the O_PATH fd into a proper, readable one */
                real_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                safe_close(fd);
                if (real_fd < 0)
                        return real_fd;

                *ret_fd = real_fd;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(q);

        return 0;
}

int fopen_extension_release(const char *root, const char *extension, char **ret_path, FILE **ret_file) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        FILE *f;
        int r;

        if (!ret_file)
                return open_extension_release(root, extension, ret_path, NULL);

        r = open_extension_release(root, extension, ret_path ? &p : NULL, &fd);
        if (r < 0)
                return r;

        f = take_fdopen(&fd, "r");
        if (!f)
                return -errno;

        if (ret_path)
                *ret_path = TAKE_PTR(p);
        *ret_file = f;

        return 0;
}

static int parse_release_internal(const char *root, const char *extension, va_list ap) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        r = fopen_extension_release(root, extension, &p, &f);
        if (r < 0)
                return r;

        return parse_env_filev(f, p, ap);
}

int _parse_extension_release(const char *root, const char *extension, ...) {
        va_list ap;
        int r;

        va_start(ap, extension);
        r = parse_release_internal(root, extension, ap);
        va_end(ap);

        return r;
}

int _parse_os_release(const char *root, ...) {
        va_list ap;
        int r;

        va_start(ap, root);
        r = parse_release_internal(root, NULL, ap);
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

        return load_env_file_pairs(f, p, ret);
}

int load_os_release_pairs_with_prefix(const char *root, const char *prefix, char ***ret) {
        _cleanup_strv_free_ char **os_release_pairs = NULL, **os_release_pairs_prefixed = NULL;
        char **p, **q;
        int r;

        r = load_os_release_pairs(root, &os_release_pairs);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(p, q, os_release_pairs) {
                char *line;

                /* We strictly return only the four main ID fields and ignore the rest */
                if (!STR_IN_SET(*p, "ID", "VERSION_ID", "BUILD_ID", "VARIANT_ID"))
                        continue;

                ascii_strlower(*p);
                line = strjoin(prefix, *p, "=", *q);
                if (!line)
                        return -ENOMEM;
                r = strv_consume(&os_release_pairs_prefixed, line);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(os_release_pairs_prefixed);

        return 0;
}

int load_extension_release_pairs(const char *root, const char *extension, char ***ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        r = fopen_extension_release(root, extension, &p, &f);
        if (r < 0)
                return r;

        return load_env_file_pairs(f, p, ret);
}
