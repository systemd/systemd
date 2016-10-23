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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "formats-util.h"
#include "install-printf.h"
#include "install.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"
#include "user-util.h"

static int specifier_prefix_and_instance(char specifier, void *data, void *userdata, char **ret) {
        const UnitFileInstallInfo *i = userdata;
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(i);

        r = unit_name_to_prefix_and_instance(i->name, &prefix);
        if (r < 0)
                return r;

        if (endswith(prefix, "@") && i->default_instance) {
                char *ans;

                ans = strjoin(prefix, i->default_instance);
                if (!ans)
                        return -ENOMEM;
                *ret = ans;
        } else {
                *ret = prefix;
                prefix = NULL;
        }

        return 0;
}

static int specifier_name(char specifier, void *data, void *userdata, char **ret) {
        const UnitFileInstallInfo *i = userdata;
        char *ans;

        assert(i);

        if (unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE) && i->default_instance)
                return unit_name_replace_instance(i->name, i->default_instance, ret);

        ans = strdup(i->name);
        if (!ans)
                return -ENOMEM;
        *ret = ans;
        return 0;
}

static int specifier_prefix(char specifier, void *data, void *userdata, char **ret) {
        const UnitFileInstallInfo *i = userdata;

        assert(i);

        return unit_name_to_prefix(i->name, ret);
}

static int specifier_instance(char specifier, void *data, void *userdata, char **ret) {
        const UnitFileInstallInfo *i = userdata;
        char *instance;
        int r;

        assert(i);

        r = unit_name_to_instance(i->name, &instance);
        if (r < 0)
                return r;

        if (isempty(instance)) {
                instance = strdup(i->default_instance ?: "");
                if (!instance)
                        return -ENOMEM;
        }

        *ret = instance;
        return 0;
}

static int specifier_user_name(char specifier, void *data, void *userdata, char **ret) {
        char *t;

        /* If we are UID 0 (root), this will not result in NSS,
         * otherwise it might. This is good, as we want to be able to
         * run this in PID 1, where our user ID is 0, but where NSS
         * lookups are not allowed.

         * We don't user getusername_malloc() here, because we don't want to look
         * at $USER, to remain consistent with specifer_user_id() below.
         */

        t = uid_to_name(getuid());
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

int install_full_printf(UnitFileInstallInfo *i, const char *format, char **ret) {

        /* This is similar to unit_full_printf() but does not support
         * anything path-related.
         *
         * %n: the full id of the unit                 (foo@bar.waldo)
         * %N: the id of the unit without the suffix   (foo@bar)
         * %p: the prefix                              (foo)
         * %i: the instance                            (bar)

         * %U the UID of the running user
         * %u the username of running user
         * %m the machine ID of the running system
         * %H the host name of the running system
         * %b the boot ID of the running system
         * %v `uname -r` of the running system
         */

        const Specifier table[] = {
                { 'n', specifier_name,                NULL },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },
                { 'i', specifier_instance,            NULL },

                { 'U', specifier_user_id,             NULL },
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
