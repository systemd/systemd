/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "macro.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "xattr-util.h"

static const char* const image_class_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_MACHINE]  = "machine",
        [IMAGE_PORTABLE] = "portable",
        [IMAGE_SYSEXT]   = "sysext",
        [IMAGE_CONFEXT]  = "confext",
};

DEFINE_STRING_TABLE_LOOKUP(image_class, ImageClass);

/* Helper struct for naming simplicity and reusability */
static const struct {
        const char *release_file_directory;
        const char *release_file_path_prefix;
} image_class_release_info[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT] = {
                .release_file_directory = "/usr/lib/extension-release.d/",
                .release_file_path_prefix = "/usr/lib/extension-release.d/extension-release.",
        },
        [IMAGE_CONFEXT] = {
                .release_file_directory = "/etc/extension-release.d/",
                .release_file_path_prefix = "/etc/extension-release.d/extension-release.",
        }
};

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

int path_extract_image_name(const char *path, char **ret) {
        _cleanup_free_ char *fn = NULL;
        int r;

        assert(path);
        assert(ret);

        /* Extract last component from path, without any "/" suffixes. */
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;
        if (r != O_DIRECTORY) {
                /* Chop off any image suffixes we recognize (unless we already know this must refer to some dir) */
                char *m = ENDSWITH_SET(fn, ".sysext.raw", ".confext.raw", ".raw");
                if (m)
                        *m = 0;
        }

        /* Truncate the version/counting suffixes */
        fn[strcspn(fn, "_+")] = 0;

        if (!image_name_is_valid(fn))
                return -EINVAL;

        *ret = TAKE_PTR(fn);
        return 0;
}

int path_is_extension_tree(ImageClass image_class, const char *path, const char *extension, bool relax_extension_release_check) {
        int r;

        assert(path);

        /* Does the path exist at all? If not, generate an error immediately. This is useful so that a missing root dir
         * always results in -ENOENT, and we can properly distinguish the case where the whole root doesn't exist from
         * the case where just the os-release file is missing. */
        r = access_nofollow(path, F_OK);
        if (r < 0)
                return r;

        /* We use /usr/lib/extension-release.d/extension-release[.NAME] as flag for something being a system extension,
         * /etc/extension-release.d/extension-release[.NAME] as flag for something being a system configuration, and finally,
         * and {/etc|/usr/lib}/os-release as a flag for something being an OS (when not an extension). */
        r = open_extension_release(path, image_class, extension, relax_extension_release_check, NULL, NULL);
        if (r == -ENOENT) /* We got nothing */
                return 0;
        if (r < 0)
                return r;

        return 1;
}

static int extension_release_strict_xattr_value(int extension_release_fd, const char *extension_release_dir_path, const char *filename) {
        int r;

        assert(extension_release_fd >= 0);
        assert(extension_release_dir_path);
        assert(filename);

        /* No xattr or cannot parse it? Then skip this. */
        r = getxattr_at_bool(extension_release_fd, /* path= */ NULL, "user.extension-release.strict", /* flags= */ 0);
        if (ERRNO_IS_NEG_XATTR_ABSENT(r))
                return log_debug_errno(r, "%s/%s does not have user.extension-release.strict xattr, ignoring.",
                                       extension_release_dir_path, filename);
        if (r < 0)
                return log_debug_errno(r, "%s/%s: Failed to read 'user.extension-release.strict' extended attribute from file, ignoring: %m",
                                       extension_release_dir_path, filename);

        /* Explicitly set to request strict matching? Skip it. */
        if (r > 0) {
                log_debug("%s/%s: 'user.extension-release.strict' attribute is true, ignoring file.",
                          extension_release_dir_path, filename);
                return true;
        }

        log_debug("%s/%s: 'user.extension-release.strict' attribute is false%s",
                  extension_release_dir_path, filename,
                  special_glyph(SPECIAL_GLYPH_ELLIPSIS));

        return false;
}

int open_os_release_at(int rfd, char **ret_path, int *ret_fd) {
        const char *e;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);

        e = secure_getenv("SYSTEMD_OS_RELEASE");
        if (e)
                return chaseat(rfd, e, CHASE_AT_RESOLVE_IN_ROOT, ret_path, ret_fd);

        FOREACH_STRING(path, "/etc/os-release", "/usr/lib/os-release") {
                r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT, ret_path, ret_fd);
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

int open_os_release(const char *root, char **ret_path, int *ret_fd) {
        _cleanup_close_ int rfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        rfd = open(empty_to_root(root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (rfd < 0)
                return -errno;

        r = open_os_release_at(rfd, ret_path ? &p : NULL, ret_fd ? &fd : NULL);
        if (r < 0)
                return r;

        if (ret_path) {
                r = chaseat_prefix_root(p, root, ret_path);
                if (r < 0)
                        return r;
        }

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

int open_extension_release_at(
                int rfd,
                ImageClass image_class,
                const char *extension,
                bool relax_extension_release_check,
                char **ret_path,
                int *ret_fd) {

        _cleanup_free_ char *dir_path = NULL, *path_found = NULL;
        _cleanup_close_ int fd_found = -EBADF;
        _cleanup_closedir_ DIR *dir = NULL;
        bool found = false;
        const char *p;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);
        assert(!extension || (image_class >= 0 && image_class < _IMAGE_CLASS_MAX));

        if (!extension)
                return open_os_release_at(rfd, ret_path, ret_fd);

        if (!IN_SET(image_class, IMAGE_SYSEXT, IMAGE_CONFEXT))
                return -EINVAL;

        if (!image_name_is_valid(extension))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "The extension name %s is invalid.", extension);

        p = strjoina(image_class_release_info[image_class].release_file_path_prefix, extension);
        r = chaseat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT, ret_path, ret_fd);
        log_full_errno_zerook(LOG_DEBUG, MIN(r, 0), "Checking for %s: %m", p);
        if (r != -ENOENT)
                return r;

        /* Cannot find the expected extension-release file? The image filename might have been mangled on
         * deployment, so fallback to checking for any file in the extension-release.d directory, and return
         * the first one with a user.extension-release xattr instead. The user.extension-release.strict
         * xattr is checked to ensure the author of the image considers it OK if names do not match. */

        p = image_class_release_info[image_class].release_file_directory;
        r = chase_and_opendirat(rfd, p, CHASE_AT_RESOLVE_IN_ROOT, &dir_path, &dir);
        if (r < 0)
                return log_debug_errno(r, "Cannot open %s, ignoring: %m", p);

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_close_ int fd = -EBADF;
                const char *image_name;

                if (!IN_SET(de->d_type, DT_REG, DT_UNKNOWN))
                        continue;

                image_name = startswith(de->d_name, "extension-release.");
                if (!image_name)
                        continue;

                if (!image_name_is_valid(image_name)) {
                        log_debug("%s/%s is not a valid release file name, ignoring.", dir_path, de->d_name);
                        continue;
                }

                /* We already chased the directory, and checked that this is a real file, so we shouldn't
                 * fail to open it. */
                fd = openat(dirfd(dir), de->d_name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to open release file %s/%s: %m", dir_path, de->d_name);

                /* Really ensure it is a regular file after we open it. */
                r = fd_verify_regular(fd);
                if (r < 0) {
                        log_debug_errno(r, "%s/%s is not a regular file, ignoring: %m", dir_path, de->d_name);
                        continue;
                }

                if (!relax_extension_release_check) {
                        _cleanup_free_ char *base_extension = NULL;

                        r = path_extract_image_name(extension, &base_extension);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to extract image name from %s, ignoring: %m", extension);
                                continue;
                        }

                        if (!streq(image_name, base_extension) &&
                            extension_release_strict_xattr_value(fd, dir_path, image_name) != 0)
                                continue;
                }

                /* We already found what we were looking for, but there's another candidate? We treat this as
                 * an error, as we want to enforce that there are no ambiguities in case we are in the
                 * fallback path. */
                if (found)
                        return -ENOTUNIQ;

                found = true;

                if (ret_fd)
                        fd_found = TAKE_FD(fd);

                if (ret_path) {
                        path_found = path_join(dir_path, de->d_name);
                        if (!path_found)
                                return -ENOMEM;
                }
        }
        if (!found)
                return -ENOENT;

        if (ret_fd)
                *ret_fd = TAKE_FD(fd_found);
        if (ret_path)
                *ret_path = TAKE_PTR(path_found);

        return 0;
}

int open_extension_release(
                const char *root,
                ImageClass image_class,
                const char *extension,
                bool relax_extension_release_check,
                char **ret_path,
                int *ret_fd) {

        _cleanup_close_ int rfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        rfd = open(empty_to_root(root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (rfd < 0)
                return -errno;

        r = open_extension_release_at(rfd, image_class, extension, relax_extension_release_check,
                                      ret_path ? &p : NULL, ret_fd ? &fd : NULL);
        if (r < 0)
                return r;

        if (ret_path) {
                r = chaseat_prefix_root(p, root, ret_path);
                if (r < 0)
                        return r;
        }

        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

static int parse_extension_release_atv(
                int rfd,
                ImageClass image_class,
                const char *extension,
                bool relax_extension_release_check,
                va_list ap) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);

        r = open_extension_release_at(rfd, image_class, extension, relax_extension_release_check, &p, &fd);
        if (r < 0)
                return r;

        return parse_env_file_fdv(fd, p, ap);
}

int parse_extension_release_at_sentinel(
                int rfd,
                ImageClass image_class,
                bool relax_extension_release_check,
                const char *extension,
                ...) {

        va_list ap;
        int r;

        assert(rfd >= 0 || rfd == AT_FDCWD);

        va_start(ap, extension);
        r = parse_extension_release_atv(rfd, image_class, extension, relax_extension_release_check, ap);
        va_end(ap);
        return r;
}

int parse_extension_release_sentinel(
                const char *root,
                ImageClass image_class,
                bool relax_extension_release_check,
                const char *extension,
                ...) {

        _cleanup_close_ int rfd = -EBADF;
        va_list ap;
        int r;

        rfd = open(empty_to_root(root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (rfd < 0)
                return -errno;

        va_start(ap, extension);
        r = parse_extension_release_atv(rfd, image_class, extension, relax_extension_release_check, ap);
        va_end(ap);
        return r;
}

int load_os_release_pairs_with_prefix(const char *root, const char *prefix, char ***ret) {
        _cleanup_strv_free_ char **os_release_pairs = NULL, **os_release_pairs_prefixed = NULL;
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

int load_extension_release_pairs(const char *root, ImageClass image_class, const char *extension, bool relax_extension_release_check, char ***ret) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        r = open_extension_release(root, image_class, extension, relax_extension_release_check, &p, &fd);
        if (r < 0)
                return r;

        return load_env_file_pairs_fd(fd, p, ret);
}

int os_release_support_ended(const char *support_end, bool quiet, usec_t *ret_eol) {
        _cleanup_free_ char *_support_end_alloc = NULL;
        int r;

        if (!support_end) {
                /* If the caller has the variably handy, they can pass it in. If not, we'll read it
                 * ourselves. */

                r = parse_os_release(NULL,
                                     "SUPPORT_END", &_support_end_alloc);
                if (r < 0 && r != -ENOENT)
                        return log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING, r,
                                              "Failed to read os-release file, ignoring: %m");

                support_end = _support_end_alloc;
        }

        if (isempty(support_end)) { /* An empty string is a explicit way to say "no EOL exists" */
                if (ret_eol)
                        *ret_eol = USEC_INFINITY;

                return false;  /* no end date defined */
        }

        struct tm tm = {};
        const char *k = strptime(support_end, "%Y-%m-%d", &tm);
        if (!k || *k)
                return log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING, SYNTHETIC_ERRNO(EINVAL),
                                      "Failed to parse SUPPORT_END= from os-release file, ignoring: %s", support_end);

        usec_t eol;
        r = mktime_or_timegm_usec(&tm, /* utc= */ true, &eol);
        if (r < 0)
                return log_full_errno(quiet ? LOG_DEBUG : LOG_WARNING, r,
                                      "Failed to convert SUPPORT_END= time from os-release file, ignoring: %m");

        if (ret_eol)
                *ret_eol = eol;

        return now(CLOCK_REALTIME) > eol;
}

const char* os_release_pretty_name(const char *pretty_name, const char *name) {
        /* Distills a "pretty" name to show from os-release data. First argument is supposed to be the
         * PRETTY_NAME= field, the second one the NAME= field. This function is trivial, of course, and
         * exists mostly to ensure we use the same logic wherever possible. */

        return empty_to_null(pretty_name) ?:
                empty_to_null(name) ?: "Linux";
}
