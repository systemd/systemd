/* SPDX-License-Identifier: LGPL-2.1+ */
#include <getopt.h>

#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"

static char *arg_root = NULL;
static int arg_flags = 0;

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x1000,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "root",                required_argument, NULL, ARG_ROOT                },

                { "prefix-root",         no_argument,       NULL, CHASE_PREFIX_ROOT       },
                { "nonexistent",         no_argument,       NULL, CHASE_NONEXISTENT       },
                { "no_autofs",           no_argument,       NULL, CHASE_NO_AUTOFS         },
                { "safe",                no_argument,       NULL, CHASE_SAFE              },
                { "open",                no_argument,       NULL, CHASE_OPEN              },
                { "trail-slash",         no_argument,       NULL, CHASE_TRAIL_SLASH       },
                { "step",                no_argument,       NULL, CHASE_STEP              },
                { "nofollow",            no_argument,       NULL, CHASE_NOFOLLOW          },
                { "warn",                no_argument,       NULL, CHASE_WARN              },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        printf("Syntax:\n"
                               "  %s [OPTION...] path...\n"
                               "Options:\n"
                               , argv[0]);
                        for (size_t i = 0; i < ELEMENTSOF(options) - 1; i++)
                                printf("  --%s\n", options[i].name);
                        return 0;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case CHASE_PREFIX_ROOT:
                case CHASE_NONEXISTENT:
                case CHASE_NO_AUTOFS:
                case CHASE_SAFE:
                case CHASE_OPEN:
                case CHASE_TRAIL_SLASH:
                case CHASE_STEP:
                case CHASE_NOFOLLOW:
                case CHASE_WARN:
                        arg_flags |= c;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind == argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "At least one argument is required.");

        return 1;
}

static int run(int argc, char **argv) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        for (int i = optind; i < argc; i++) {
                _cleanup_free_ char *p = NULL;

                printf("%s ", argv[i]);
                fflush(stdout);

                r = chase_symlinks(argv[i], arg_root, arg_flags, &p);
                if (r < 0)
                        log_error_errno(r, "failed: %m");
                else
                        log_info("→ %s", p);

                if (FLAGS_SET(arg_flags, CHASE_OPEN))
                        safe_close(r);
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
