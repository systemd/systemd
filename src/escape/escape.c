/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Michael Biebl

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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

static enum {
        ACTION_ESCAPE,
        ACTION_UNESCAPE,
        ACTION_MANGLE
} arg_action = ACTION_ESCAPE;
static const char *arg_suffix = NULL;
static const char *arg_template = NULL;
static bool arg_path = false;

static void help(void) {
        printf("%s [OPTIONS...] [NAME...]\n\n"
               "Show system and user paths.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --suffix=SUFFIX      Unit suffix to append to escaped strings\n"
               "     --template=TEMPLATE  Insert strings as instance into template\n"
               "  -u --unescape           Unescape strings\n"
               "  -m --mangle             Mangle strings\n"
               "  -p --path               When escaping/unescaping assume the string is a path\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_SUFFIX,
                ARG_TEMPLATE
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "suffix",    required_argument, NULL, ARG_SUFFIX    },
                { "template",  required_argument, NULL, ARG_TEMPLATE  },
                { "unescape",  no_argument,       NULL, 'u'           },
                { "mangle",    no_argument,       NULL, 'm'           },
                { "path",      no_argument,       NULL, 'p'           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hump", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_SUFFIX:

                        if (unit_type_from_string(optarg) < 0) {
                                log_error("Invalid unit suffix type %s.", optarg);
                                return -EINVAL;
                        }

                        arg_suffix = optarg;
                        break;

                case ARG_TEMPLATE:

                        if (!unit_name_is_valid(optarg, UNIT_NAME_TEMPLATE)) {
                                log_error("Template name %s is not valid.", optarg);
                                return -EINVAL;
                        }

                        arg_template = optarg;
                        break;

                case 'u':
                        arg_action = ACTION_UNESCAPE;
                        break;

                case 'm':
                        arg_action = ACTION_MANGLE;
                        break;

                case 'p':
                        arg_path = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind >= argc) {
                log_error("Not enough arguments.");
                return -EINVAL;
        }

        if (arg_template && arg_suffix) {
                log_error("--suffix= and --template= may not be combined.");
                return -EINVAL;
        }

        if ((arg_template || arg_suffix) && arg_action != ACTION_ESCAPE) {
                log_error("--suffix= and --template= are not compatible with --unescape or --mangle.");
                return -EINVAL;
        }

        if (arg_path && !IN_SET(arg_action, ACTION_ESCAPE, ACTION_UNESCAPE)) {
                log_error("--path may not be combined with --mangle.");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        char **i;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        STRV_FOREACH(i, argv + optind) {
                _cleanup_free_ char *e = NULL;

                switch (arg_action) {

                case ACTION_ESCAPE:
                        if (arg_path) {
                                r = unit_name_path_escape(*i, &e);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to escape string: %m");
                                        goto finish;
                                }
                        } else {
                                e = unit_name_escape(*i);
                                if (!e) {
                                        r = log_oom();
                                        goto finish;
                                }
                        }

                        if (arg_template) {
                                char *x;

                                r = unit_name_replace_instance(arg_template, e, &x);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to replace instance: %m");
                                        goto finish;
                                }

                                free(e);
                                e = x;
                        } else if (arg_suffix) {
                                char *x;

                                x = strjoin(e, ".", arg_suffix, NULL);
                                if (!x) {
                                        r = log_oom();
                                        goto finish;
                                }

                                free(e);
                                e = x;
                        }

                        break;

                case ACTION_UNESCAPE:
                        if (arg_path)
                                r = unit_name_path_unescape(*i, &e);
                        else
                                r = unit_name_unescape(*i, &e);

                        if (r < 0) {
                                log_error_errno(r, "Failed to unescape string: %m");
                                goto finish;
                        }
                        break;

                case ACTION_MANGLE:
                        r = unit_name_mangle(*i, UNIT_NAME_NOGLOB, &e);
                        if (r < 0) {
                                log_error_errno(r, "Failed to mangle name: %m");
                                goto finish;
                        }
                        break;
                }

                if (i != argv+optind)
                        fputc(' ', stdout);

                fputs(e, stdout);
        }

        fputc('\n', stdout);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
