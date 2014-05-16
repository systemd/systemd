/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdio.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "util.h"
#include "def.h"
#include "build.h"
#include "readahead-common.h"

unsigned arg_files_max = 16*1024;
off_t arg_file_size_max = READAHEAD_FILE_SIZE_MAX;
usec_t arg_timeout = 2*USEC_PER_MINUTE;

static int help(void) {

        printf("%s [OPTIONS...] collect [DIRECTORY]\n\n"
               "Collect read-ahead data on early boot.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --files-max=INT        Maximum number of files to read ahead\n"
               "     --file-size-max=BYTES  Maximum size of files to read ahead\n"
               "     --timeout=USEC         Maximum time to spend collecting data\n\n\n",
               program_invocation_short_name);

        printf("%s [OPTIONS...] replay [DIRECTORY]\n\n"
               "Replay collected read-ahead data on early boot.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --file-size-max=BYTES  Maximum size of files to read ahead\n\n\n",
               program_invocation_short_name);

        printf("%s [OPTIONS...] analyze [PACK FILE]\n\n"
               "Analyze collected read-ahead data.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FILES_MAX,
                ARG_FILE_SIZE_MAX,
                ARG_TIMEOUT
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'                },
                { "version",       no_argument,       NULL, ARG_VERSION        },
                { "files-max",     required_argument, NULL, ARG_FILES_MAX      },
                { "file-size-max", required_argument, NULL, ARG_FILE_SIZE_MAX  },
                { "timeout",       required_argument, NULL, ARG_TIMEOUT        },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_FILES_MAX:
                        if (safe_atou(optarg, &arg_files_max) < 0 || arg_files_max <= 0) {
                                log_error("Failed to parse maximum number of files %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_FILE_SIZE_MAX: {
                        unsigned long long ull;

                        if (safe_atollu(optarg, &ull) < 0 || ull <= 0) {
                                log_error("Failed to parse maximum file size %s.", optarg);
                                return -EINVAL;
                        }

                        arg_file_size_max = (off_t) ull;
                        break;
                }

                case ARG_TIMEOUT:
                        if (parse_sec(optarg, &arg_timeout) < 0 || arg_timeout <= 0) {
                                log_error("Failed to parse timeout %s.", optarg);
                                return -EINVAL;
                        }

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind != argc-1 &&
            optind != argc-2) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r;

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        if (streq(argv[optind], "collect"))
                return main_collect(argv[optind+1]);
        else if (streq(argv[optind], "replay"))
                return main_replay(argv[optind+1]);
        else if (streq(argv[optind], "analyze"))
                return main_analyze(argv[optind+1]);

        log_error("Unknown verb %s.", argv[optind]);
        return EXIT_FAILURE;
}
