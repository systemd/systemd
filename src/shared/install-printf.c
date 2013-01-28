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

#include <assert.h>
#include <stdlib.h>

#include "specifier.h"
#include "unit-name.h"
#include "install-printf.h"

static char *specifier_prefix_and_instance(char specifier, void *data, void *userdata) {
        InstallInfo *i = userdata;
        assert(i);

        return unit_name_to_prefix_and_instance(i->name);
}

static char *specifier_prefix(char specifier, void *data, void *userdata) {
        InstallInfo *i = userdata;
        assert(i);

        return unit_name_to_prefix(i->name);
}

static char *specifier_instance(char specifier, void *data, void *userdata) {
        InstallInfo *i = userdata;
        char *instance;
        int r;

        assert(i);

        r = unit_name_to_instance(i->name, &instance);
        if (r < 0)
                return NULL;
        if (instance != NULL)
                return instance;
        else
                return strdup("");
}

char *install_full_printf(InstallInfo *i, const char *format) {

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
         */

        const Specifier table[] = {
                { 'n', specifier_string,              i->name },
                { 'N', specifier_prefix_and_instance, NULL },
                { 'p', specifier_prefix,              NULL },
                { 'i', specifier_instance,            NULL },

//                { 'U', specifier_user_name,           NULL },
//                { 'u', specifier_user_name,           NULL },

                { 'm', specifier_machine_id,          NULL },
                { 'H', specifier_host_name,           NULL },
                { 'b', specifier_boot_id,             NULL },
                { 0, NULL, NULL }
        };

        assert(i);
        assert(format);

        return specifier_printf(format, table, i);
}
