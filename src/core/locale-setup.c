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

#include <stdlib.h>
#include <errno.h>

#include "locale-setup.h"
#include "util.h"
#include "virt.h"
#include "fileio.h"
#include "strv.h"
#include "env-util.h"
#include "locale-util.h"

int locale_setup(char ***environment) {
        char **add;
        char *variables[_VARIABLE_LC_MAX] = {};
        int r = 0, i;

        if (detect_container() <= 0) {
                r = parse_env_file("/proc/cmdline", WHITESPACE,
                                   "locale.LANG",              &variables[VARIABLE_LANG],
                                   "locale.LANGUAGE",          &variables[VARIABLE_LANGUAGE],
                                   "locale.LC_CTYPE",          &variables[VARIABLE_LC_CTYPE],
                                   "locale.LC_NUMERIC",        &variables[VARIABLE_LC_NUMERIC],
                                   "locale.LC_TIME",           &variables[VARIABLE_LC_TIME],
                                   "locale.LC_COLLATE",        &variables[VARIABLE_LC_COLLATE],
                                   "locale.LC_MONETARY",       &variables[VARIABLE_LC_MONETARY],
                                   "locale.LC_MESSAGES",       &variables[VARIABLE_LC_MESSAGES],
                                   "locale.LC_PAPER",          &variables[VARIABLE_LC_PAPER],
                                   "locale.LC_NAME",           &variables[VARIABLE_LC_NAME],
                                   "locale.LC_ADDRESS",        &variables[VARIABLE_LC_ADDRESS],
                                   "locale.LC_TELEPHONE",      &variables[VARIABLE_LC_TELEPHONE],
                                   "locale.LC_MEASUREMENT",    &variables[VARIABLE_LC_MEASUREMENT],
                                   "locale.LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION],
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline: %m");
        }

        /* Hmm, nothing set on the kernel cmd line? Then let's
         * try /etc/locale.conf */
        if (r <= 0) {
                r = parse_env_file("/etc/locale.conf", NEWLINE,
                                   "LANG",              &variables[VARIABLE_LANG],
                                   "LANGUAGE",          &variables[VARIABLE_LANGUAGE],
                                   "LC_CTYPE",          &variables[VARIABLE_LC_CTYPE],
                                   "LC_NUMERIC",        &variables[VARIABLE_LC_NUMERIC],
                                   "LC_TIME",           &variables[VARIABLE_LC_TIME],
                                   "LC_COLLATE",        &variables[VARIABLE_LC_COLLATE],
                                   "LC_MONETARY",       &variables[VARIABLE_LC_MONETARY],
                                   "LC_MESSAGES",       &variables[VARIABLE_LC_MESSAGES],
                                   "LC_PAPER",          &variables[VARIABLE_LC_PAPER],
                                   "LC_NAME",           &variables[VARIABLE_LC_NAME],
                                   "LC_ADDRESS",        &variables[VARIABLE_LC_ADDRESS],
                                   "LC_TELEPHONE",      &variables[VARIABLE_LC_TELEPHONE],
                                   "LC_MEASUREMENT",    &variables[VARIABLE_LC_MEASUREMENT],
                                   "LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION],
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /etc/locale.conf: %m");
        }

        add = NULL;
        for (i = 0; i < _VARIABLE_LC_MAX; i++) {
                char *s;

                if (!variables[i])
                        continue;

                s = strjoin(locale_variable_to_string(i), "=", variables[i], NULL);
                if (!s) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (strv_consume(&add, s) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }
        }

        if (!strv_isempty(add)) {
                char **e;

                e = strv_env_merge(2, *environment, add);
                if (!e) {
                        r = -ENOMEM;
                        goto finish;
                }

                strv_free(*environment);
                *environment = e;
        }

        r = 0;

finish:
        strv_free(add);

        for (i = 0; i < _VARIABLE_LC_MAX; i++)
                free(variables[i]);

        return r;
}
