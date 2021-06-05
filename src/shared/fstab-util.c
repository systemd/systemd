/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "fstab-util.h"
#include "macro.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

int fstab_has_fstype(const char *fstype) {
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

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
                                "/proc",             /* All of this is API VFS */
                                "/sys",              /* … dito … */
                                "/dev"))             /* … dito … */
                return true;

        /* If this is an initrd mount, and we are not in the initrd, then leave
         * this around forever, too. */
        if (opts && fstab_test_option(opts, "x-initrd.mount\0") && !in_initrd())
                return true;

        return false;
}

int fstab_is_mount_point(const char *mount) {
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        f = setmntent(fstab_path(), "re");
        if (!f)
                return errno == ENOENT ? false : -errno;

        for (;;) {
                errno = 0;
                m = getmntent(f);
                if (!m)
                        return errno != 0 ? -errno : false;

                if (path_equal(m->mnt_dir, mount))
                        return true;
        }
        return false;
}

int fstab_filter_options(
                const char *opts,
                const char *names,
                const char **ret_namefound,
                char **ret_value,
                char ***ret_values,
                char **ret_filtered) {

        const char *name, *namefound = NULL, *x;
        _cleanup_strv_free_ char **stor = NULL, **values = NULL;
        _cleanup_free_ char *value = NULL, **filtered = NULL;
        int r;

        assert(names && *names);
        assert(!(ret_value && ret_values));

        if (!opts)
                goto answer;

        /* Finds any options matching 'names', and returns:
         * - the last matching option name in ret_namefound,
         * - the last matching value in ret_value,
         * - any matching values in ret_values,
         * - the rest of the option string in ret_filtered.
         *
         * If !ret_value and !ret_values and !ret_filtered, this function is not allowed to fail.
         *
         * Returns negative on error, true if any matching options were found, false otherwise. */

        if (ret_filtered || ret_value || ret_values) {
                /* For backwards compatibility, we need to pass-through escape characters.
                 * The only ones we "consume" are the ones used as "\," or "\\". */
                r = strv_split_full(&stor, opts, ",", EXTRACT_UNESCAPE_SEPARATORS | EXTRACT_UNESCAPE_RELAX);
                if (r < 0)
                        return r;

                filtered = memdup(stor, sizeof(char*) * (strv_length(stor) + 1));
                if (!filtered)
                        return -ENOMEM;

                char **t = filtered;
                for (char **s = t; *s; s++) {
                        NULSTR_FOREACH(name, names) {
                                x = startswith(*s, name);
                                if (!x)
                                        continue;
                                /* Match name, but when ret_values, only when followed by assignment. */
                                if (*x == '=' || (!ret_values && *x == '\0'))
                                        goto found;
                        }

                        *t = *s;
                        t++;
                        continue;
                found:
                        /* Keep the last occurrence found */
                        namefound = name;

                        if (ret_value || ret_values) {
                                assert(IN_SET(*x, '=', '\0'));

                                if (ret_value) {
                                        r = free_and_strdup(&value, *x == '=' ? x + 1 : NULL);
                                        if (r < 0)
                                                return r;
                                } else if (*x) {
                                        r = strv_extend(&values, x + 1);
                                        if (r < 0)
                                                return r;
                                }
                        }
                }
                *t = NULL;
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
                                end ++;                 /* Skip the backslash */
                                if (*end != '\0')
                                        end ++;         /* Skip the escaped char, but watch out for a trailing comma */
                        }

                        NULSTR_FOREACH(name, names) {
                                if (end < word + strlen(name))
                                        continue;
                                if (!strneq(word, name, strlen(name)))
                                        continue;

                                /* We know that the string is NUL terminated, so *x is valid */
                                x = word + strlen(name);
                                if (IN_SET(*x, '\0', '=', ',')) {
                                        namefound = name;
                                        break;
                                }
                        }

                        if (*end)
                                word = end + 1;
                        else
                                break;
                }

answer:
        if (ret_namefound)
                *ret_namefound = namefound;
        if (ret_filtered) {
                char *f;

                f = strv_join_full(filtered, ",", NULL, true);
                if (!f)
                        return -ENOMEM;

                *ret_filtered = f;
        }
        if (ret_value)
                *ret_value = TAKE_PTR(value);
        if (ret_values)
                *ret_values = TAKE_PTR(values);

        return !!namefound;
}

int fstab_find_pri(const char *options, int *ret) {
        _cleanup_free_ char *opt = NULL;
        int r, pri;

        assert(ret);

        r = fstab_filter_options(options, "pri\0", NULL, &opt, NULL, NULL);
        if (r < 0)
                return r;
        if (r == 0 || !opt)
                return 0;

        r = safe_atoi(opt, &pri);
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

char *fstab_node_to_udev_node(const char *p) {
        assert(p);

        if (startswith(p, "LABEL="))
                return tag_to_udev_node(p+6, "label");

        if (startswith(p, "UUID="))
                return tag_to_udev_node(p+5, "uuid");

        if (startswith(p, "PARTUUID="))
                return tag_to_udev_node(p+9, "partuuid");

        if (startswith(p, "PARTLABEL="))
                return tag_to_udev_node(p+10, "partlabel");

        return strdup(p);
}
