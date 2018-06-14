/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "fstab-util.h"
#include "macro.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

int fstab_has_fstype(const char *fstype) {
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        f = setmntent("/etc/fstab", "re");
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

int fstab_is_mount_point(const char *mount) {
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        f = setmntent("/etc/fstab", "re");
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

int fstab_filter_options(const char *opts, const char *names,
                         const char **namefound, char **value, char **filtered) {
        const char *name, *n = NULL, *x;
        _cleanup_strv_free_ char **stor = NULL;
        _cleanup_free_ char *v = NULL, **strv = NULL;

        assert(names && *names);

        if (!opts)
                goto answer;

        /* If !value and !filtered, this function is not allowed to fail. */

        if (!filtered) {
                const char *word, *state;
                size_t l;

                FOREACH_WORD_SEPARATOR(word, l, opts, ",", state)
                        NULSTR_FOREACH(name, names) {
                                if (l < strlen(name))
                                        continue;
                                if (!strneq(word, name, strlen(name)))
                                        continue;

                                /* we know that the string is NUL
                                 * terminated, so *x is valid */
                                x = word + strlen(name);
                                if (IN_SET(*x, '\0', '=', ',')) {
                                        n = name;
                                        if (value) {
                                                free(v);
                                                if (IN_SET(*x, '\0', ','))
                                                        v = NULL;
                                                else {
                                                        assert(*x == '=');
                                                        x++;
                                                        v = strndup(x, l - strlen(name) - 1);
                                                        if (!v)
                                                                return -ENOMEM;
                                                }
                                        }
                                }
                        }
        } else {
                char **t, **s;

                stor = strv_split(opts, ",");
                if (!stor)
                        return -ENOMEM;
                strv = memdup(stor, sizeof(char*) * (strv_length(stor) + 1));
                if (!strv)
                        return -ENOMEM;

                for (s = t = strv; *s; s++) {
                        NULSTR_FOREACH(name, names) {
                                x = startswith(*s, name);
                                if (x && IN_SET(*x, '\0', '='))
                                        goto found;
                        }

                        *t = *s;
                        t++;
                        continue;
                found:
                        /* Keep the last occurence found */
                        n = name;
                        if (value) {
                                free(v);
                                if (*x == '\0')
                                        v = NULL;
                                else {
                                        assert(*x == '=');
                                        x++;
                                        v = strdup(x);
                                        if (!v)
                                                return -ENOMEM;
                                }
                        }
                }
                *t = NULL;
        }

answer:
        if (namefound)
                *namefound = n;
        if (filtered) {
                char *f;

                f = strv_join(strv, ",");
                if (!f)
                        return -ENOMEM;

                *filtered = f;
        }
        if (value)
                *value = TAKE_PTR(v);

        return !!n;
}

int fstab_extract_values(const char *opts, const char *name, char ***values) {
        _cleanup_strv_free_ char **optsv = NULL, **res = NULL;
        char **s;

        assert(opts);
        assert(name);
        assert(values);

        optsv = strv_split(opts, ",");
        if (!optsv)
                return -ENOMEM;

        STRV_FOREACH(s, optsv) {
                char *arg;
                int r;

                arg = startswith(*s, name);
                if (!arg || *arg != '=')
                        continue;
                r = strv_extend(&res, arg + 1);
                if (r < 0)
                        return r;
        }

        *values = TAKE_PTR(res);

        return !!*values;
}

int fstab_find_pri(const char *options, int *ret) {
        _cleanup_free_ char *opt = NULL;
        int r;
        unsigned pri;

        assert(ret);

        r = fstab_filter_options(options, "pri\0", NULL, &opt, NULL);
        if (r < 0)
                return r;
        if (r == 0 || !opt)
                return 0;

        r = safe_atou(opt, &pri);
        if (r < 0)
                return r;

        if ((int) pri < 0)
                return -ERANGE;

        *ret = (int) pri;
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
