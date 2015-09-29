/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-path.h"

#include "log.h"
#include "macro.h"
#include "util.h"

static const char *arg_suffix = NULL;

static const char* const path_table[_SD_PATH_MAX] = {
        [SD_PATH_TEMPORARY] = "temporary",
        [SD_PATH_TEMPORARY_LARGE] = "temporary-large",
        [SD_PATH_SYSTEM_BINARIES] = "system-binaries",
        [SD_PATH_SYSTEM_INCLUDE] = "system-include",
        [SD_PATH_SYSTEM_LIBRARY_PRIVATE] = "system-library-private",
        [SD_PATH_SYSTEM_LIBRARY_ARCH] = "system-library-arch",
        [SD_PATH_SYSTEM_SHARED] = "system-shared",
        [SD_PATH_SYSTEM_CONFIGURATION_FACTORY] = "system-configuration-factory",
        [SD_PATH_SYSTEM_STATE_FACTORY] = "system-state-factory",
        [SD_PATH_SYSTEM_CONFIGURATION] = "system-configuration",
        [SD_PATH_SYSTEM_RUNTIME] = "system-runtime",
        [SD_PATH_SYSTEM_RUNTIME_LOGS] = "system-runtime-logs",
        [SD_PATH_SYSTEM_STATE_PRIVATE] = "system-state-private",
        [SD_PATH_SYSTEM_STATE_LOGS] = "system-state-logs",
        [SD_PATH_SYSTEM_STATE_CACHE] = "system-state-cache",
        [SD_PATH_SYSTEM_STATE_SPOOL] = "system-state-spool",
        [SD_PATH_USER_BINARIES] = "user-binaries",
        [SD_PATH_USER_LIBRARY_PRIVATE] = "user-library-private",
        [SD_PATH_USER_LIBRARY_ARCH] = "user-library-arch",
        [SD_PATH_USER_SHARED] = "user-shared",
        [SD_PATH_USER_CONFIGURATION] = "user-configuration",
        [SD_PATH_USER_RUNTIME] = "user-runtime",
        [SD_PATH_USER_STATE_CACHE] = "user-state-cache",
        [SD_PATH_USER] = "user",
        [SD_PATH_USER_DOCUMENTS] = "user-documents",
        [SD_PATH_USER_MUSIC] = "user-music",
        [SD_PATH_USER_PICTURES] = "user-pictures",
        [SD_PATH_USER_VIDEOS] = "user-videos",
        [SD_PATH_USER_DOWNLOAD] = "user-download",
        [SD_PATH_USER_PUBLIC] = "user-public",
        [SD_PATH_USER_TEMPLATES] = "user-templates",
        [SD_PATH_USER_DESKTOP] = "user-desktop",
        [SD_PATH_SEARCH_BINARIES] = "search-binaries",
        [SD_PATH_SEARCH_LIBRARY_PRIVATE] = "search-library-private",
        [SD_PATH_SEARCH_LIBRARY_ARCH] = "search-library-arch",
        [SD_PATH_SEARCH_SHARED] = "search-shared",
        [SD_PATH_SEARCH_CONFIGURATION_FACTORY] = "search-configuration-factory",
        [SD_PATH_SEARCH_STATE_FACTORY] = "search-state-factory",
        [SD_PATH_SEARCH_CONFIGURATION] = "search-configuration",
};

static int list_homes(void) {
        uint64_t i = 0;
        int r = 0;

        for (i = 0; i < ELEMENTSOF(path_table); i++) {
                _cleanup_free_ char *p = NULL;
                int q;

                q = sd_path_home(i, arg_suffix, &p);
                if (q == -ENXIO)
                        continue;
                if (q < 0) {
                        log_error_errno(r, "Failed to query %s: %m", path_table[i]);
                        r = q;
                        continue;
                }

                printf("%s: %s\n", path_table[i], p);
        }

        return r;
}

static int print_home(const char *n) {
        uint64_t i = 0;
        int r;

        for (i = 0; i < ELEMENTSOF(path_table); i++) {
                if (streq(path_table[i], n)) {
                        _cleanup_free_ char *p = NULL;

                        r = sd_path_home(i, arg_suffix, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query %s: %m", n);

                        printf("%s\n", p);
                        return 0;
                }
        }

        log_error("Path %s not known.", n);
        return -EOPNOTSUPP;
}

static void help(void) {
        printf("%s [OPTIONS...] [NAME...]\n\n"
               "Show system and user paths.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --suffix=SUFFIX    Suffix to append to paths\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_SUFFIX,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "suffix",    required_argument, NULL, ARG_SUFFIX    },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_SUFFIX:
                        arg_suffix = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char* argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (argc > optind) {
                int i, q;

                for (i = optind; i < argc; i++) {
                        q = print_home(argv[i]);
                        if (q < 0)
                                r = q;
                }
        } else
                r = list_homes();


finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
