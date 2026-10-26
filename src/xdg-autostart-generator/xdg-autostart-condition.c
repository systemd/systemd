/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "log.h"
#include "main-func.h"
#include "strv.h"
#include "verbs.h"

COMMAND(
        "systemd-xdg-autostart-condition\0",
        "Check the OnlyShowIn= and NotShowIn= conditions of an XDG autostart entry.",
        .argspec = "ONLY-SHOW-IN NOT-SHOW-IN\0",
        .man_pages = "systemd-xdg-autostart-generator(8)\0",
        .option_namespace = "common",
);

/*
 * This binary is intended to be run as an ExecCondition= in units generated
 * by the xdg-autostart-generator. It does the appropriate checks against
 * XDG_CURRENT_DESKTOP that are too advanced for simple ConditionEnvironment=
 * matches.
 */

static int run(int argc, char *argv[]) {
        _cleanup_strv_free_ char **only_show_in = NULL, **not_show_in = NULL, **desktops = NULL;
        const char *xdg_current_desktop;
        int r;

        /* The arguments are the OnlyShowIn= and NotShowIn= lists of the .desktop file, which may well
         * start with a dash, hence only options before them are recognized. */
        char **args = NULL;
        r = common_parse_argv_mode(argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION,
                                   /* min_args= */ 2, /* max_args= */ 2, &args);
        if (r <= 0)
                return r;

        xdg_current_desktop = getenv("XDG_CURRENT_DESKTOP");
        if (xdg_current_desktop) {
                desktops = strv_split(xdg_current_desktop, ":");
                if (!desktops)
                        return log_oom();
        }

        only_show_in = strv_split(args[0], ":");
        not_show_in = strv_split(args[1], ":");
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
