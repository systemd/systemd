/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/utsname.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "architecture.h"
#include "chase-symlinks.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "macro.h"
#include "os-util.h"
#include "path-util.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

/*
 * Generic infrastructure for replacing %x style specifiers in
 * strings. Will call a callback for each replacement.
 */

/* Any ASCII character or digit: our pool of potential specifiers,
 * and "%" used for escaping. */
#define POSSIBLE_SPECIFIERS ALPHANUMERICAL "%"

int specifier_printf(const char *text, size_t max_length, const Specifier table[], const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *result = NULL;
        bool percent = false;
        size_t l;
        char *t;
        int r;

        assert(ret);
        assert(text);
        assert(table);

        l = strlen(text);
        if (!GREEDY_REALLOC(result, l + 1))
                return -ENOMEM;
        t = result;

        for (const char *f = text; *f != '\0'; f++, l--) {
                if (percent) {
                        percent = false;

                        if (*f == '%')
                                *(t++) = '%';
                        else {
                                const Specifier *i;

                                for (i = table; i->specifier; i++)
                                        if (i->specifier == *f)
                                                break;

                                if (i->lookup) {
                                        _cleanup_free_ char *w = NULL;
                                        size_t k, j;

                                        r = i->lookup(i->specifier, i->data, root, userdata, &w);
                                        if (r < 0)
                                                return r;
                                        if (isempty(w))
                                                continue;

                                        j = t - result;
                                        k = strlen(w);

                                        if (!GREEDY_REALLOC(result, j + k + l + 1))
                                                return -ENOMEM;
                                        memcpy(result + j, w, k);
                                        t = result + j + k;
                                } else if (strchr(POSSIBLE_SPECIFIERS, *f))
                                        /* Oops, an unknown specifier. */
                                        return -EBADSLT;
                                else {
                                        *(t++) = '%';
                                        *(t++) = *f;
                                }
                        }
                } else if (*f == '%')
                        percent = true;
                else
                        *(t++) = *f;

                if ((size_t) (t - result) > max_length)
                        return -ENAMETOOLONG;
        }

        /* If string ended with a stray %, also end with % */
        if (percent) {
                *(t++) = '%';
                if ((size_t) (t - result) > max_length)
                        return -ENAMETOOLONG;
        }
        *(t++) = 0;

        *ret = TAKE_PTR(result);
        return 0;
}

/* Generic handler for simple string replacements */

int specifier_string(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n = NULL;

        assert(ret);

        if (!isempty(data)) {
                n = strdup(data);
                if (!n)
                        return -ENOMEM;
        }

        *ret = n;
        return 0;
}

int specifier_real_path(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *path = data;

        assert(ret);

        if (!path)
                return -ENOENT;

        return chase_symlinks(path, root, 0, ret, NULL);
}

int specifier_real_directory(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(ret);

        r = specifier_real_path(specifier, data, root, userdata, &path);
        if (r < 0)
                return r;

        assert(path);
        return path_extract_directory(path, ret);
}

int specifier_machine_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        sd_id128_t id;
        char *n;
        int r;

        assert(ret);

        if (root) {
                _cleanup_close_ int fd = -1;

                fd = chase_symlinks_and_open("/etc/machine-id", root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                if (fd < 0)
                        return fd;

                r = id128_read_fd(fd, ID128_PLAIN, &id);
        } else
                r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        n = new(char, SD_ID128_STRING_MAX);
        if (!n)
                return -ENOMEM;

        *ret = sd_id128_to_string(id, n);
        return 0;
}

int specifier_boot_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        sd_id128_t id;
        char *n;
        int r;

        assert(ret);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        n = new(char, SD_ID128_STRING_MAX);
        if (!n)
                return -ENOMEM;

        *ret = sd_id128_to_string(id, n);
        return 0;
}

int specifier_host_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n;

        assert(ret);

        n = gethostname_malloc();
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_short_host_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n;

        assert(ret);

        n = gethostname_short_malloc();
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_pretty_host_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n = NULL;

        assert(ret);

        if (get_pretty_hostname(&n) < 0) {
                n = gethostname_short_malloc();
                if (!n)
                        return -ENOMEM;
        }

        *ret = n;
        return 0;
}

int specifier_kernel_release(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        struct utsname uts;
        char *n;

        assert(ret);

        if (uname(&uts) < 0)
                return -errno;

        n = strdup(uts.release);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_architecture(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *t;

        assert(ret);

        t = strdup(architecture_to_string(uname_architecture()));
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

/* Note: fields in /etc/os-release might quite possibly be missing, even if everything is entirely valid
 * otherwise. We'll return an empty value or NULL in that case from the functions below. */

int specifier_os_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "ID", ret);
}

int specifier_os_version_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "VERSION_ID", ret);
}

int specifier_os_build_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "BUILD_ID", ret);
}

int specifier_os_variant_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "VARIANT_ID", ret);
}

int specifier_os_image_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "IMAGE_ID", ret);
}

int specifier_os_image_version(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);
        return parse_os_release(root, "IMAGE_VERSION", ret);
}

int specifier_group_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *t;

        assert(ret);

        t = gid_to_name(getgid());
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

int specifier_group_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);

        if (asprintf(ret, UID_FMT, getgid()) < 0)
                return -ENOMEM;

        return 0;
}

int specifier_user_name(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *t;

        assert(ret);

        /* If we are UID 0 (root), this will not result in NSS, otherwise it might. This is good, as we want to be able
         * to run this in PID 1, where our user ID is 0, but where NSS lookups are not allowed.

         * We don't use getusername_malloc() here, because we don't want to look at $USER, to remain consistent with
         * specifer_user_id() below.
         */

        t = uid_to_name(getuid());
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

int specifier_user_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);

        if (asprintf(ret, UID_FMT, getuid()) < 0)
                return -ENOMEM;

        return 0;
}

int specifier_user_home(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_home_dir(ret);
}

int specifier_user_shell(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        assert(ret);

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_shell(ret);
}

int specifier_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *p;
        char *copy;
        int r;

        assert(ret);

        if (root) /* If root dir is set, don't honour $TMP or similar */
                p = "/tmp";
        else {
                r = tmp_dir(&p);
                if (r < 0)
                        return r;
        }
        copy = strdup(p);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

int specifier_var_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *p;
        char *copy;
        int r;

        assert(ret);

        if (root)
                p = "/var/tmp";
        else {
                r = var_tmp_dir(&p);
                if (r < 0)
                        return r;
        }
        copy = strdup(p);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

int specifier_escape_strv(char **l, char ***ret) {
        char **z, **p, **q;

        assert(ret);

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        z = new(char*, strv_length(l)+1);
        if (!z)
                return -ENOMEM;

        for (p = l, q = z; *p; p++, q++) {

                *q = specifier_escape(*p);
                if (!*q) {
                        strv_free(z);
                        return -ENOMEM;
                }
        }

        *q = NULL;
        *ret = z;

        return 0;
}

const Specifier system_and_tmp_specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,
        COMMON_TMP_SPECIFIERS,
        {}
};
