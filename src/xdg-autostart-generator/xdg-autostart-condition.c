/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "main-func.h"
#include "strv.h"

/*
 * This binary is intended to be run as an ExecCondition= in units generated
 * by the xdg-autostart-generator. It does the appropriate checks against
 * XDG_CURRENT_DESKTOP that are too advanced for simple ConditionEnvironment=
 * matches.
 */

static int run(int argc, char *argv[]) {
        _cleanup_strv_free_ char **only_show_in = NULL, **not_show_in = NULL, **desktops = NULL;
        const char *xdg_current_desktop;

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Wrong argument count. Expected the OnlyShowIn= and NotShowIn= sets, each colon separated.");

        xdg_current_desktop = getenv("XDG_CURRENT_DESKTOP");
        if (xdg_current_desktop) {
                desktops = strv_split(xdg_current_desktop, ":");
                if (!desktops)
                        return log_oom();
        }

        only_show_in = strv_split(argv[1], ":");
        not_show_in = strv_split(argv[2], ":");
        if (!only_show_in || !not_show_in)
                return log_oom();

        /* Each desktop in XDG_CURRENT_DESKTOP needs to be matched in order. */
        STRV_FOREACH(d, desktops) {
                if (strv_contains(only_show_in, *d))
                        return 0;
                if (strv_contains(not_show_in, *d))
                        return 1;
        }

        /* non-zero exit code when only_show_in has a proper value */
        return !strv_isempty(only_show_in);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
