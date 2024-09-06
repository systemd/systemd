/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-path.h"

#include "conf-files.h"
#include "constants.h"
#include "env-file.h"
#include "escape.h"
#include "glyph-util.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "strv.h"

static int environment_dirs(char ***ret) {
        _cleanup_strv_free_ char **dirs = NULL;
        _cleanup_free_ char *c = NULL;
        int r;

        dirs = strv_new(CONF_PATHS("environment.d"));
        if (!dirs)
                return -ENOMEM;

        /* ~/.config/systemd/environment.d */
        r = sd_path_lookup(SD_PATH_USER_CONFIGURATION, "environment.d", &c);
        if (r < 0)
                return r;

        r = strv_consume_prepend(&dirs, TAKE_PTR(c));
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *t = NULL;

                t = strv_join(dirs, "\n\t");
                log_debug("Looking for environment.d files in (higher priority first):\n\t%s", strna(t));
        }

        *ret = TAKE_PTR(dirs);
        return 0;
}

static int load_and_print(void) {
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL, **env = NULL;
        int r;

        r = environment_dirs(&dirs);
        if (r < 0)
                return r;

        r = conf_files_list_strv(&files, ".conf", NULL, 0, (const char **) dirs);
        if (r < 0)
                return r;

        /* This will mutate the existing environment, based on the presumption
         * that in case of failure, a partial update is better than none. */

        STRV_FOREACH(i, files) {
                log_debug("Reading %s%s", *i, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                r = merge_env_file(&env, NULL, *i);
                if (r == -ENOMEM)
                        return r;
        }

        STRV_FOREACH(i, env) {
                char *t;
                _cleanup_free_ char *q = NULL;

                t = strchr(*i, '=');
                assert(t);

                q = shell_maybe_quote(t + 1, 0);
                if (!q)
                        return log_oom();

                printf("%.*s=%s\n", (int) (t - *i), *i, q);
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = load_and_print();
        if (r < 0)
                return log_error_errno(r, "Failed to load environment.d: %m");
        return 0;
}

DEFINE_MAIN_FUNCTION(run);
