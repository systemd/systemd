/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "fstab-util.h"
#include "initrd-util.h"
#include "macro.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"

bool fstab_enabled_full(int enabled) {
        static int cached = -1;
        bool val = true; /* If nothing specified or the check fails, then defaults to true. */
        int r;

        /* If 'enabled' is non-negative, then update the cache with it. */
        if (enabled >= 0)
                cached = enabled;

        if (cached >= 0)
                return cached;

        r = proc_cmdline_get_bool("fstab", PROC_CMDLINE_STRIP_RD_PREFIX|PROC_CMDLINE_TRUE_WHEN_MISSING, &val);
        if (r < 0)
                log_debug_errno(r, "Failed to parse fstab= kernel command line option, ignoring: %m");

        return (cached = val);
}

int fstab_has_fstype(const char *fstype) {
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        assert(fstype);

        if (!fstab_enabled())
                return false;

        f = setmntent(fstab_path(), "re");
        if (!f)
                return errno == ENOENT ? false : -errno;

        for (;;) {
                errno = 0;
                m = getmntent(f);
                if (!m)
                        return errno != 0 ? -errno : false;

                if (streq(m->mnt_type, fstype))
                        return true;
        }
        return false;
}

bool fstab_is_extrinsic(const char *mount, const char *opts) {

        /* Don't bother with the OS data itself */
        if (PATH_IN_SET(mount,
                        "/",
                        "/usr",
                        "/etc"))
                return true;

        if (PATH_STARTSWITH_SET(mount,
                                "/run/initramfs",    /* This should stay around from before we boot until after we shutdown */
                                "/run/nextroot",     /* Similar (though might be updated from the host) */
                                "/proc",             /* All of this is API VFS */
                                "/sys",              /* … ditto … */
                                "/dev"))             /* … ditto … */
                return true;

        /* If this is an initrd mount, and we are not in the initrd, then leave
         * this around forever, too. */
        if (fstab_test_option(opts, "x-initrd.mount\0") && !in_initrd())
                return true;

        return false;
}

static int fstab_is_same_node(const char *what_fstab, const char *path) {
        _cleanup_free_ char *node = NULL;

        assert(what_fstab);
        assert(path);

        node = fstab_node_to_udev_node(what_fstab);
        if (!node)
                return -ENOMEM;

        if (path_equal(node, path))
                return true;

        if (is_device_path(path) && is_device_path(node))
                return devnode_same(node, path);

        return false;
}

int fstab_has_mount_point_prefix_strv(char **prefixes) {
        _cleanup_endmntent_ FILE *f = NULL;

        assert(prefixes);

        /* This function returns true if at least one entry in fstab has a mount point that starts with one
         * of the passed prefixes. */

        if (!fstab_enabled())
                return false;

        f = setmntent(fstab_path(), "re");
        if (!f)
                return errno == ENOENT ? false : -errno;

        for (;;) {
                struct mntent *me;

                errno = 0;
                me = getmntent(f);
                if (!me)
                        return errno != 0 ? -errno : false;

                if (path_startswith_strv(me->mnt_dir, prefixes))
                        return true;
        }
}

int fstab_is_mount_point_full(const char *where, const char *path) {
        _cleanup_endmntent_ FILE *f = NULL;
        int r;

        assert(where || path);

        if (!fstab_enabled())
                return false;

        f = setmntent(fstab_path(), "re");
        if (!f)
                return errno == ENOENT ? false : -errno;

        for (;;) {
                struct mntent *me;

                errno = 0;
                me = getmntent(f);
                if (!me)
                        return errno != 0 ? -errno : false;

                if (where && !path_equal(where, me->mnt_dir))
                        continue;

                if (!path)
                        return true;

                r = fstab_is_same_node(me->mnt_fsname, path);
                if (r > 0 || (r < 0 && !ERRNO_IS_DEVICE_ABSENT(r)))
                        return r;
        }
}

int fstab_filter_options(
                const char *opts,
                const char *names,
                const char **ret_namefound,
                char **ret_value,
                char ***ret_values,
                char **ret_filtered) {

        _cleanup_strv_free_ char **values = NULL;
        _cleanup_free_ char *value = NULL, *filtered = NULL;
        const char *namefound = NULL;
        int r;

        assert(!isempty(names));
        assert(!(ret_value && ret_values));

        if (!opts)
                goto finish;

        /* Finds any options matching 'names', and returns:
         * - the last matching option name in ret_namefound,
         * - the last matching value in ret_value,
         * - any matching values in ret_values,
         * - the rest of the option string in ret_filtered.
         *
         * If !ret_value and !ret_values and !ret_filtered, this function is not allowed to fail.
         *
         * Returns negative on error, true if any matching options were found, false otherwise. */

        if (ret_value || ret_values || ret_filtered) {
                _cleanup_strv_free_ char **opts_split = NULL;
                _cleanup_free_ char **filtered_strv = NULL; /* strings are owned by 'opts_split' */

                /* For backwards compatibility, we need to pass-through escape characters.
                 * The only ones we "consume" are the ones used as "\," or "\\". */
                r = strv_split_full(&opts_split, opts, ",", EXTRACT_UNESCAPE_SEPARATORS|EXTRACT_UNESCAPE_RELAX);
                if (r < 0)
                        return r;

                STRV_FOREACH(opt, opts_split) {
                        bool found = false;
                        const char *x;

                        NULSTR_FOREACH(name, names) {
                                x = startswith(*opt, name);
                                if (!x)
                                        continue;

                                /* If ret_values, only accept settings followed by assignment. */
                                if (*x == '=' || (!ret_values && *x == '\0')) {
                                        namefound = name;
                                        found = true;
                                        break;
                                }
                        }

                        if (found) {
                                if (ret_value)
                                        r = free_and_strdup(&value, *x == '=' ? x + 1 : NULL);
                                else if (ret_values)
                                        r = strv_extend(&values, x + 1);
                                else
                                        r = 0;
                        } else
                                r = strv_push(&filtered_strv, *opt);
                        if (r < 0)
                                return r;
                }

                filtered = strv_join_full(filtered_strv, ",", NULL, /* escape_separator = */ true);
                if (!filtered)
                        return -ENOMEM;
        } else
                for (const char *word = opts;;) {
                        const char *end = word;

                        /* Look for a *non-escaped* comma separator. Only commas and backslashes can be
                         * escaped, so "\," and "\\" are the only valid escape sequences, and we can do a
                         * very simple test here. */
                        for (;;) {
                                end += strcspn(end, ",\\");

                                if (IN_SET(*end, ',', '\0'))
                                        break;
                                assert(*end == '\\');
                                end++;                 /* Skip the backslash */
                                if (*end != '\0')
                                        end++;         /* Skip the escaped char, but watch out for a trailing comma */
                        }

                        NULSTR_FOREACH(name, names) {
                                const char *x = startswith(word, name);
                                if (!x || x > end)
                                        continue;

                                /* We know that the string is NUL terminated, so *x is valid */
                                if (IN_SET(*x, '\0', '=', ',')) {
                                        namefound = name;
                                        break;
                                }
                        }

                        if (*end == '\0')
                                break;

                        word = end + 1;
                }

finish:
        if (ret_namefound)
                *ret_namefound = namefound; /* owned by 'names' (passed-in) */
        if (ret_value)
                *ret_value = TAKE_PTR(value);
        if (ret_values)
                *ret_values = TAKE_PTR(values);
        if (ret_filtered)
                *ret_filtered = TAKE_PTR(filtered);

        return !!namefound;
}

int fstab_find_pri(const char *opts, int *ret) {
        _cleanup_free_ char *v = NULL;
        int r, pri;

        assert(ret);

        r = fstab_filter_options(opts, "pri\0", NULL, &v, NULL, NULL);
        if (r < 0)
                return r;
        if (r == 0 || !v)
                return 0;

        r = safe_atoi(v, &pri);
        if (r < 0)
                return r;

        *ret = pri;
        return 1;
}

static char *unquote(const char *s, const char* quotes) {
        size_t l;
        assert(s);

        /* This is rather stupid, simply removes the heading and
         * trailing quotes if there is one. Doesn't care about
         * escaping or anything.
         *
         * DON'T USE THIS FOR NEW CODE ANYMORE! */

        l = strlen(s);
        if (l < 2)
                return strdup(s);

        if (strchr(quotes, s[0]) && s[l-1] == s[0])
                return strndup(s+1, l-2);

        return strdup(s);
}

static char *tag_to_udev_node(const char *tagvalue, const char *by) {
        _cleanup_free_ char *t = NULL, *u = NULL;
        size_t enc_len;

        u = unquote(tagvalue, QUOTES);
        if (!u)
                return NULL;

        enc_len = strlen(u) * 4 + 1;
        t = new(char, enc_len);
        if (!t)
                return NULL;

        if (encode_devnode_name(u, t, enc_len) < 0)
                return NULL;

        return strjoin("/dev/disk/by-", by, "/", t);
}

char* fstab_node_to_udev_node(const char *p) {
        const char *q;

        assert(p);

        q = startswith(p, "LABEL=");
        if (q)
                return tag_to_udev_node(q, "label");

        q = startswith(p, "UUID=");
        if (q)
                return tag_to_udev_node(q, "uuid");

        q = startswith(p, "PARTUUID=");
        if (q)
                return tag_to_udev_node(q, "partuuid");

        q = startswith(p, "PARTLABEL=");
        if (q)
                return tag_to_udev_node(q, "partlabel");

        return strdup(p);
}

bool fstab_is_bind(const char *options, const char *fstype) {

        if (fstab_test_option(options, "bind\0" "rbind\0"))
                return true;

        if (fstype && STR_IN_SET(fstype, "bind", "rbind"))
                return true;

        return false;
}
