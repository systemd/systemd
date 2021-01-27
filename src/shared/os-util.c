/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "discover-image.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"

int path_is_extension_tree(const char *path, const char *extension) {
        int r;

        assert(path);

        /* Does the path exist at all? If not, generate an error immediately. This is useful so that a missing root dir
         * always results in -ENOENT, and we can properly distinguish the case where the whole root doesn't exist from
         * the case where just the os-release file is missing. */
        if (laccess(path, F_OK) < 0)
                return -errno;

        /* We use /usr/lib/extension-release.d/extension-release.NAME as flag file if something is a system extension,
         * and {/etc|/usr/lib}/os-release as flag file if something is an OS (in case extension == NULL) */
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

        *ret_file = f;

        if (ret_path)
                *ret_path = TAKE_PTR(p);

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

int parse_extension_release(const char *root, const char *extension, ...) {
        va_list ap;
        int r;

        va_start(ap, extension);
        r = parse_release_internal(root, extension, ap);
        va_end(ap);

        return r;
}

int parse_os_release(const char *root, ...) {
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

int extension_release_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_version_id,
                const char *host_os_release_sysext_level,
                char **extension_release) {

        const char *extension_release_id = NULL, *extension_release_sysext_level = NULL;

        assert(name);
        assert(!isempty(host_os_release_id));
        assert(!isempty(host_os_release_version_id) || !isempty(host_os_release_sysext_level));

        /* Now that we can look into the extension image, let's see if the OS version is compatible */
        if (strv_isempty(extension_release)) {
                log_debug("Extension '%s' carries no extension-release data, ignoring extension.", name);
                return 0;
        }

        extension_release_id = strv_env_pairs_get(extension_release, "ID");
        if (isempty(extension_release_id)) {
                log_debug("Extension '%s' does not contain ID in extension-release but requested to match '%s'",
                          name, strna(host_os_release_id));
                return 0;
        }

        if (!streq_ptr(host_os_release_id, extension_release_id)) {
                log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                          name, strna(extension_release_id), strna(host_os_release_id));
                return 0;
        }

        /* If the extension has a sysext API level declared, then it must match the host API
         * level. Otherwise, compare OS version as a whole */
        extension_release_sysext_level = strv_env_pairs_get(extension_release, "SYSEXT_LEVEL");
        if (!isempty(host_os_release_sysext_level) && !isempty(extension_release_sysext_level)) {
                if (!streq_ptr(host_os_release_sysext_level, extension_release_sysext_level)) {
                        log_debug("Extension '%s' is for sysext API level '%s', but running on sysext API level '%s'",
                                  name, strna(extension_release_sysext_level), strna(host_os_release_sysext_level));
                        return 0;
                }
        } else if (!isempty(host_os_release_version_id)) {
                const char *extension_release_version_id;

                extension_release_version_id = strv_env_pairs_get(extension_release, "VERSION_ID");
                if (isempty(extension_release_version_id)) {
                        log_debug("Extension '%s' does not contain VERSION_ID in extension-release but requested to match '%s'",
                                  name, strna(host_os_release_version_id));
                        return 0;
                }

                if (!streq_ptr(host_os_release_version_id, extension_release_version_id)) {
                        log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                                  name, strna(extension_release_version_id), strna(host_os_release_version_id));
                        return 0;
                }
        } else if (isempty(host_os_release_version_id) && isempty(host_os_release_sysext_level)) {
                /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        log_debug("Version info of extension '%s' matches host.", name);
        return 1;
}
