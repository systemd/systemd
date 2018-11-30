/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "env-file.h"
#include "env-util.h"
#include "locale-setup.h"
#include "locale-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"
#include "virt.h"

int locale_setup(char ***environment) {
        _cleanup_(locale_variables_freep) char *variables[_VARIABLE_LC_MAX] = {};
        _cleanup_strv_free_ char **add = NULL;
        LocaleVariable i;
        int r;

        r = proc_cmdline_get_key_many(PROC_CMDLINE_STRIP_RD_PREFIX,
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
                                      "locale.LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION]);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /proc/cmdline: %m");

        /* Hmm, nothing set on the kernel cmd line? Then let's try /etc/locale.conf */
        if (r <= 0) {
                r = parse_env_file(NULL, "/etc/locale.conf",
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
                                   "LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION]);
                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /etc/locale.conf: %m");
        }

        for (i = 0; i < _VARIABLE_LC_MAX; i++) {
                char *s;

                if (!variables[i])
                        continue;

                s = strjoin(locale_variable_to_string(i), "=", variables[i]);
                if (!s)
                        return -ENOMEM;

                if (strv_consume(&add, s) < 0)
                        return -ENOMEM;
        }

        if (strv_isempty(add)) {
                /* If no locale is configured then default to C.UTF-8. */

                add = strv_new("LANG=C.UTF-8");
                if (!add)
                        return -ENOMEM;
        }

        if (strv_isempty(*environment))
                strv_free_and_replace(*environment, add);
        else {
                char **merged;

                merged = strv_env_merge(2, *environment, add);
                if (!merged)
                        return -ENOMEM;

                strv_free_and_replace(*environment, merged);
        }

        return 0;
}
