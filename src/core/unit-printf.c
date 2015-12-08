/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "cgroup-util.h"
#include "formats-util.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"

static int specifier_prefix_and_instance(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;

        assert(u);

        return unit_name_to_prefix_and_instance(u->id, ret);
}

static int specifier_prefix(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;

        assert(u);

        return unit_name_to_prefix(u->id, ret);
}

static int specifier_prefix_unescaped(char specifier, void *data, void *userdata, char **ret) {
        _cleanup_free_ char *p = NULL;
        Unit *u = userdata;
        int r;

        assert(u);

        r = unit_name_to_prefix(u->id, &p);
        if (r < 0)
                return r;

        return unit_name_unescape(p, ret);
}

static int specifier_instance_unescaped(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;

        assert(u);

        return unit_name_unescape(strempty(u->instance), ret);
}

static int specifier_filename(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;

        assert(u);

        if (u->instance)
                return unit_name_path_unescape(u->instance, ret);
        else
                return unit_name_to_path(u->id, ret);
}

static int specifier_cgroup(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        if (u->cgroup_path)
                n = strdup(u->cgroup_path);
        else
                n = unit_default_cgroup_path(u);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_cgroup_root(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        n = strdup(u->manager->cgroup_root);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_cgroup_slice(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        if (UNIT_ISSET(u->slice)) {
                Unit *slice;

                slice = UNIT_DEREF(u->slice);

                if (slice->cgroup_path)
                        n = strdup(slice->cgroup_path);
                else
                        n = unit_default_cgroup_path(slice);
        } else
                n = strdup(u->manager->cgroup_root);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_runtime(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        const char *e;
        char *n = NULL;

        assert(u);

        if (u->manager->running_as == MANAGER_SYSTEM)
                e = "/run";
        else {
                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return -EOPNOTSUPP;
        }

        n = strdup(e);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_user_name(char specifier, void *data, void *userdata, char **ret) {
        char *t;

        /* If we are UID 0 (root), this will not result in NSS,
         * otherwise it might. This is good, as we want to be able to
         * run this in PID 1, where our user ID is 0, but where NSS
         * lookups are not allowed. */

        t = getusername_malloc();
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

static int specifier_user_id(char specifier, void *data, void *userdata, char **ret) {

        if (asprintf(ret, UID_FMT, getuid()) < 0)
                return -ENOMEM;

        return 0;
}

static int specifier_user_home(char specifier, void *data, void *userdata, char **ret) {

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_home_dir(ret);
}

static int specifier_user_shell(char specifier, void *data, void *userdata, char **ret) {

        /* On PID 1 (which runs as root) this will not result in NSS,
         * which is good. See above */

        return get_shell(ret);
}

int unit_name_printf(Unit *u, const char* format, char **ret) {

        /*
         * This will use the passed string as format string and
         * replace the following specifiers:
         *
         * %n: the full id of the unit                 (foo@bar.waldo)
         * %N: the id of the unit without the suffix   (foo@bar)
         * %p: the prefix                              (foo)
         * %i: the instance                            (bar)
         */

        const Specifier table[] = {
                { 'n', specifier_string,              u->id },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },
                { 'i', specifier_string,              u->instance },
                { 0, NULL, NULL }
        };

        assert(u);
        assert(format);
        assert(ret);

        return specifier_printf(format, table, u, ret);
}

int unit_full_printf(Unit *u, const char *format, char **ret) {

        /* This is similar to unit_name_printf() but also supports
         * unescaping. Also, adds a couple of additional codes:
         *
         * %f the instance if set, otherwise the id
         * %c cgroup path of unit
         * %r where units in this slice are placed in the cgroup tree
         * %R the root of this systemd's instance tree
         * %t the runtime directory to place sockets in (e.g. "/run" or $XDG_RUNTIME_DIR)
         * %U the UID of the running user
         * %u the username of the running user
         * %h the homedir of the running user
         * %s the shell of the running user
         * %m the machine ID of the running system
         * %H the host name of the running system
         * %b the boot ID of the running system
         * %v `uname -r` of the running system
         */

        const Specifier table[] = {
                { 'n', specifier_string,              u->id },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },
                { 'P', specifier_prefix_unescaped,    NULL },
                { 'i', specifier_string,              u->instance },
                { 'I', specifier_instance_unescaped,  NULL },

                { 'f', specifier_filename,            NULL },
                { 'c', specifier_cgroup,              NULL },
                { 'r', specifier_cgroup_slice,        NULL },
                { 'R', specifier_cgroup_root,         NULL },
                { 't', specifier_runtime,             NULL },

                { 'U', specifier_user_id,             NULL },
                { 'u', specifier_user_name,           NULL },
                { 'h', specifier_user_home,           NULL },
                { 's', specifier_user_shell,          NULL },

                { 'm', specifier_machine_id,          NULL },
                { 'H', specifier_host_name,           NULL },
                { 'b', specifier_boot_id,             NULL },
                { 'v', specifier_kernel_release,      NULL },
                {}
        };

        assert(u);
        assert(format);
        assert(ret);

        return specifier_printf(format, table, u, ret);
}

int unit_full_printf_strv(Unit *u, char **l, char ***ret) {
        size_t n;
        char **r, **i, **j;
        int q;

        /* Applies unit_full_printf to every entry in l */

        assert(u);

        n = strv_length(l);
        r = new(char*, n+1);
        if (!r)
                return -ENOMEM;

        for (i = l, j = r; *i; i++, j++) {
                q = unit_full_printf(u, *i, j);
                if (q < 0)
                        goto fail;
        }

        *j = NULL;
        *ret = r;
        return 0;

fail:
        for (j--; j >= r; j--)
                free(*j);

        free(r);
        return q;
}
