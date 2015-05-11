/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <stdlib.h>

#include "specifier.h"
#include "unit-name.h"
#include "util.h"
#include "install-printf.h"
#include "formats-util.h"

static int specifier_prefix_and_instance(char specifier, void *data, void *userdata, char **ret) {
        UnitFileInstallInfo *i = userdata;

        assert(i);

        return unit_name_to_prefix_and_instance(i->name, ret);
}

static int specifier_prefix(char specifier, void *data, void *userdata, char **ret) {
        UnitFileInstallInfo *i = userdata;

        assert(i);

        return unit_name_to_prefix(i->name, ret);
}

static int specifier_instance(char specifier, void *data, void *userdata, char **ret) {
        UnitFileInstallInfo *i = userdata;
        char *instance;
        int r;

        assert(i);

        r = unit_name_to_instance(i->name, &instance);
        if (r < 0)
                return r;

        if (!instance) {
                instance = strdup("");
                if (!instance)
                        return -ENOMEM;
        }

        *ret = instance;
        return 0;
}

static int specifier_user_name(char specifier, void *data, void *userdata, char **ret) {
        UnitFileInstallInfo *i = userdata;
        const char *username;
        _cleanup_free_ char *tmp = NULL;
        char *printed = NULL;

        assert(i);

        if (i->user)
                username = i->user;
        else
                /* get USER env from env or our own uid */
                username = tmp = getusername_malloc();

        switch (specifier) {
        case 'u':
                printed = strdup(username);
                break;
        case 'U': {
                /* fish username from passwd */
                uid_t uid;
                int r;

                r = get_user_creds(&username, &uid, NULL, NULL, NULL);
                if (r < 0)
                        return r;

                if (asprintf(&printed, UID_FMT, uid) < 0)
                        return -ENOMEM;
                break;
        }}


        *ret = printed;
        return 0;
}


int install_full_printf(UnitFileInstallInfo *i, const char *format, char **ret) {

        /* This is similar to unit_full_printf() but does not support
         * anything path-related.
         *
         * %n: the full id of the unit                 (foo@bar.waldo)
         * %N: the id of the unit without the suffix   (foo@bar)
         * %p: the prefix                              (foo)
         * %i: the instance                            (bar)

         * %U the UID of the configured user or running user
         * %u the username of the configured user or running user
         * %m the machine ID of the running system
         * %H the host name of the running system
         * %b the boot ID of the running system
         * %v `uname -r` of the running system
         */

        const Specifier table[] = {
                { 'n', specifier_string,              i->name },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },
                { 'i', specifier_instance,            NULL },

                { 'U', specifier_user_name,           NULL },
                { 'u', specifier_user_name,           NULL },

                { 'm', specifier_machine_id,          NULL },
                { 'H', specifier_host_name,           NULL },
                { 'b', specifier_boot_id,             NULL },
                { 'v', specifier_kernel_release,      NULL },
                {}
        };

        assert(i);
        assert(format);
        assert(ret);

        return specifier_printf(format, table, i, ret);
}
