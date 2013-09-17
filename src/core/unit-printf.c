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

#include "systemd/sd-id128.h"
#include "unit.h"
#include "specifier.h"
#include "path-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "macro.h"
#include "cgroup-util.h"
#include "special.h"

static int specifier_prefix_and_instance(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        n = unit_name_to_prefix_and_instance(u->id);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_prefix(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        n = unit_name_to_prefix(u->id);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_prefix_unescaped(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        _cleanup_free_ char *p = NULL;
        char *n;

        assert(u);

        p = unit_name_to_prefix(u->id);
        if (!p)
                return -ENOMEM;

        n = unit_name_unescape(p);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_instance_unescaped(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        if (u->instance)
                n = unit_name_unescape(u->instance);
        else
                n = strdup("");

        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_filename(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        if (u->instance)
                n = unit_name_path_unescape(u->instance);
        else
                n = unit_name_to_path(u->id);

        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_cgroup(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n;

        assert(u);

        n = unit_default_cgroup_path(u);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_cgroup_root(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        const char *slice;
        char *n;
        int r;

        assert(u);

        slice = unit_slice_name(u);
        if (specifier == 'R' || !slice)
                n = strdup(u->manager->cgroup_root);
        else {
                _cleanup_free_ char *p = NULL;

                r = cg_slice_to_path(slice, &p);
                if (r < 0)
                        return r;

                n = strjoin(u->manager->cgroup_root, "/", p, NULL);
                if (!n)
                        return -ENOMEM;
        }

        *ret = n;
        return 0;
}

static int specifier_runtime(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        char *n = NULL;

        assert(u);

        if (u->manager->running_as == SYSTEMD_USER) {
                const char *e;

                e = getenv("XDG_RUNTIME_DIR");
                if (e) {
                        n = strdup(e);
                        if (!n)
                                return -ENOMEM;
                }
        }

        if (!n) {
                n = strdup("/run");
                if (!n)
                        return -ENOMEM;
        }

        *ret = n;
        return 0;
}

static int specifier_user_name(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        ExecContext *c;
        int r;
        const char *username;
        _cleanup_free_ char *tmp = NULL;
        uid_t uid;
        char *printed = NULL;

        assert(u);

        c = unit_get_exec_context(u);

        if (c && c->user)
                username = c->user;
        else
                /* get USER env from env or our own uid */
                username = tmp = getusername_malloc();

        /* fish username from passwd */
        r = get_user_creds(&username, &uid, NULL, NULL, NULL);
        if (r < 0)
                return r;

        switch (specifier) {
                case 'U':
                        if (asprintf(&printed, "%d", uid) < 0)
                                return -ENOMEM;
                        break;
                case 'u':
                        printed = strdup(username);
                        break;
        }

        if (!printed)
                return -ENOMEM;

        *ret = printed;
        return 0;
}

static int specifier_user_home(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        ExecContext *c;
        int r;
        const char *username, *home;
        char *n;

        assert(u);

        c = unit_get_exec_context(u);

        /* return HOME if set, otherwise from passwd */
        if (!c || !c->user) {
                char *h;

                r = get_home_dir(&h);
                if (r < 0)
                        return r;

                *ret = h;
                return 0;
        }

        username = c->user;
        r = get_user_creds(&username, NULL, NULL, &home, NULL);
        if (r < 0)
               return r;

        n = strdup(home);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

static int specifier_user_shell(char specifier, void *data, void *userdata, char **ret) {
        Unit *u = userdata;
        ExecContext *c;
        int r;
        const char *username, *shell;
        char *n;

        assert(u);

        c = unit_get_exec_context(u);

        if (c && c->user)
                username = c->user;
        else
                username = "root";

        /* return /bin/sh for root, otherwise the value from passwd */
        r = get_user_creds(&username, NULL, NULL, NULL, &shell);
        if (r < 0)
                return r;

        n = strdup(shell);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
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
         * %f the the instance if set, otherwise the id
         * %c cgroup path of unit
         * %r where units in this slice are place in the cgroup tree
         * %R the root of this systemd's instance tree
         * %t the runtime directory to place sockets in (e.g. "/run" or $XDG_RUNTIME_DIR)
         * %U the UID of the configured user or running user
         * %u the username of the configured user or running user
         * %h the homedir of the configured user or running user
         * %s the shell of the configured user or running user
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
                { 'r', specifier_cgroup_root,         NULL },
                { 'R', specifier_cgroup_root,         NULL },
                { 't', specifier_runtime,             NULL },
                { 'U', specifier_user_name,           NULL },
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
