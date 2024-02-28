/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-cat-config.h"
#include "conf-files.h"
#include "constants.h"
#include "path-util.h"
#include "pretty-print.h"
#include "strv.h"

int verb_cat_config(int argc, char *argv[], void *userdata) {
        char **list;
        int r;

        pager_open(arg_pager_flags);

        list = strv_skip(argv, 1);
        STRV_FOREACH(arg, list) {
                const char *t = NULL;

                if (arg != list)
                        print_separator();

                if (path_is_absolute(*arg)) {
                        FOREACH_STRING(dir, CONF_PATHS("")) {
                                t = path_startswith(*arg, dir);
                                if (t)
                                        break;
                        }

                        if (!t)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Path %s does not start with any known prefix.", *arg);
                } else
                        t = *arg;

                r = conf_files_cat(arg_root, t, arg_cat_flags | CAT_FORMAT_HAS_SECTIONS);
                if (r < 0)
                        return r;
        }

        return EXIT_SUCCESS;
}
