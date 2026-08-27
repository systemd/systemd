/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "chase.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "strv.h"
#include "tests.h"
#include "verbs.h"

static const char *arg_root = NULL;
static int arg_flags = 0;
static bool arg_open = false;

COMMAND(
        "test-chase-manual\0",
        "Exercise chase() function on specified paths.",
        .argspec = "PATH…\0",
);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_LONG("root", "PATH", "Operate below specified root directory"):
                        arg_root = opts.arg;
                        break;

                OPTION_LONG("open", NULL, "Open the resolved path"):
                        arg_open = true;
                        break;

                OPTION_LONG_DATA("prefix-root",    NULL, CHASE_PREFIX_ROOT,    "Prefix path with --root"): {}
                OPTION_LONG_DATA("nonexistent",    NULL, CHASE_NONEXISTENT,    "Allow path to not exist"): {}
                OPTION_LONG_DATA("no-autofs",      NULL, CHASE_NO_AUTOFS,      "Return -EREMOTE if autofs mount point found"): {}
                OPTION_LONG_DATA("trigger-autofs", NULL, CHASE_TRIGGER_AUTOFS, "Trigger autofs mounts"): {}
                OPTION_LONG_DATA("safe",           NULL, CHASE_SAFE,           "Refuse privilege boundary crossings"): {}
                OPTION_LONG_DATA("trail-slash",    NULL, CHASE_TRAIL_SLASH,    "Preserve trailing slash"): {}
                OPTION_LONG_DATA("step",           NULL, CHASE_STEP,           "Execute a single normalization step"): {}
                OPTION_LONG_DATA("nofollow",       NULL, CHASE_NOFOLLOW,       "Do not follow the path's right-most component"): {}
                OPTION_LONG_DATA("warn",           NULL, CHASE_WARN,           "Emit a warning on error"):
                        arg_flags |= opts.opt->data;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        if (strv_isempty(*ret_args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "At least one argument is required.");

        return 1;
}

static int run(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        STRV_FOREACH(a, args) {
                _cleanup_free_ char *p = NULL;
                _cleanup_close_ int fd = -EBADF;

                printf("%s ", *a);
                fflush(stdout);

                r = chase(*a, arg_root, arg_flags, &p, arg_open ? &fd : NULL);
                if (r < 0)
                        log_error_errno(r, "failed: %m");
                else {
                        log_info("→ %s", p);
                        if (arg_open)
                                assert_se(fd >= 0);
                        else
                                assert_se(fd == -EBADF);
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
