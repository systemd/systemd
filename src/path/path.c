/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-path.h"

#include "alloc-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-util.h"
#include "util.h"

static const char *arg_suffix = NULL;

static const char* const path_table[_SD_PATH_MAX] = {
        [SD_PATH_TEMPORARY]                       = "temporary",
        [SD_PATH_TEMPORARY_LARGE]                 = "temporary-large",
        [SD_PATH_SYSTEM_BINARIES]                 = "system-binaries",
        [SD_PATH_SYSTEM_INCLUDE]                  = "system-include",
        [SD_PATH_SYSTEM_LIBRARY_PRIVATE]          = "system-library-private",
        [SD_PATH_SYSTEM_LIBRARY_ARCH]             = "system-library-arch",
        [SD_PATH_SYSTEM_SHARED]                   = "system-shared",
        [SD_PATH_SYSTEM_CONFIGURATION_FACTORY]    = "system-configuration-factory",
        [SD_PATH_SYSTEM_STATE_FACTORY]            = "system-state-factory",
        [SD_PATH_SYSTEM_CONFIGURATION]            = "system-configuration",
        [SD_PATH_SYSTEM_RUNTIME]                  = "system-runtime",
        [SD_PATH_SYSTEM_RUNTIME_LOGS]             = "system-runtime-logs",
        [SD_PATH_SYSTEM_STATE_PRIVATE]            = "system-state-private",
        [SD_PATH_SYSTEM_STATE_LOGS]               = "system-state-logs",
        [SD_PATH_SYSTEM_STATE_CACHE]              = "system-state-cache",
        [SD_PATH_SYSTEM_STATE_SPOOL]              = "system-state-spool",
        [SD_PATH_USER_BINARIES]                   = "user-binaries",
        [SD_PATH_USER_LIBRARY_PRIVATE]            = "user-library-private",
        [SD_PATH_USER_LIBRARY_ARCH]               = "user-library-arch",
        [SD_PATH_USER_SHARED]                     = "user-shared",
        [SD_PATH_USER_CONFIGURATION]              = "user-configuration",
        [SD_PATH_USER_RUNTIME]                    = "user-runtime",
        [SD_PATH_USER_STATE_CACHE]                = "user-state-cache",
        [SD_PATH_USER]                            = "user",
        [SD_PATH_USER_DOCUMENTS]                  = "user-documents",
        [SD_PATH_USER_MUSIC]                      = "user-music",
        [SD_PATH_USER_PICTURES]                   = "user-pictures",
        [SD_PATH_USER_VIDEOS]                     = "user-videos",
        [SD_PATH_USER_DOWNLOAD]                   = "user-download",
        [SD_PATH_USER_PUBLIC]                     = "user-public",
        [SD_PATH_USER_TEMPLATES]                  = "user-templates",
        [SD_PATH_USER_DESKTOP]                    = "user-desktop",
        [SD_PATH_SEARCH_BINARIES]                 = "search-binaries",
        [SD_PATH_SEARCH_BINARIES_DEFAULT]         = "search-binaries-default",
        [SD_PATH_SEARCH_LIBRARY_PRIVATE]          = "search-library-private",
        [SD_PATH_SEARCH_LIBRARY_ARCH]             = "search-library-arch",
        [SD_PATH_SEARCH_SHARED]                   = "search-shared",
        [SD_PATH_SEARCH_CONFIGURATION_FACTORY]    = "search-configuration-factory",
        [SD_PATH_SEARCH_STATE_FACTORY]            = "search-state-factory",
        [SD_PATH_SEARCH_CONFIGURATION]            = "search-configuration",

        [SD_PATH_SYSTEMD_UTIL]                    = "systemd-util",
        [SD_PATH_SYSTEMD_SYSTEM_UNIT]             = "systemd-system-unit",
        [SD_PATH_SYSTEMD_SYSTEM_PRESET]           = "systemd-system-preset",
        [SD_PATH_SYSTEMD_SYSTEM_CONF]             = "systemd-system-conf",
        [SD_PATH_SYSTEMD_SEARCH_SYSTEM_UNIT]      = "systemd-search-system-unit",
        [SD_PATH_SYSTEMD_SYSTEM_GENERATOR]        = "systemd-system-generator",
        [SD_PATH_SYSTEMD_SEARCH_SYSTEM_GENERATOR] = "systemd-search-system-generator",
        [SD_PATH_SYSTEMD_USER_UNIT]               = "systemd-user-unit",
        [SD_PATH_SYSTEMD_USER_PRESET]             = "systemd-user-preset",
        [SD_PATH_SYSTEMD_USER_CONF]               = "systemd-user-conf",
        [SD_PATH_SYSTEMD_SEARCH_USER_UNIT]        = "systemd-search-user-unit",
        [SD_PATH_SYSTEMD_SEARCH_USER_GENERATOR]   = "systemd-search-user-generator",
        [SD_PATH_SYSTEMD_USER_GENERATOR]          = "systemd-user-generator",
        [SD_PATH_SYSTEMD_SLEEP]                   = "systemd-sleep",
        [SD_PATH_SYSTEMD_SHUTDOWN]                = "systemd-shutdown",

        [SD_PATH_TMPFILES]                        = "tmpfiles",
        [SD_PATH_SYSUSERS]                        = "sysusers",
        [SD_PATH_SYSCTL]                          = "sysctl",
        [SD_PATH_BINFMT]                          = "binfmt",
        [SD_PATH_MODULES_LOAD]                    = "modules-load",
        [SD_PATH_CATALOG]                         = "catalog",

        [SD_PATH_SYSTEMD_SEARCH_NETWORK]          = "systemd-search-network",
};

static int list_homes(void) {
        uint64_t i = 0;
        int r = 0;

        for (i = 0; i < ELEMENTSOF(path_table); i++) {
                _cleanup_free_ char *p = NULL;
                int q;

                q = sd_path_lookup(i, arg_suffix, &p);
                if (q < 0) {
                        log_full_errno(q == -ENXIO ? LOG_DEBUG : LOG_ERR,
                                       q, "Failed to query %s: %m", path_table[i]);
                        if (q != -ENXIO)
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

                        r = sd_path_lookup(i, arg_suffix, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query %s: %m", n);

                        printf("%s\n", p);
                        return 0;
                }
        }

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Path %s not known.", n);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-path", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [NAME...]\n\n"
               "Show system and user paths.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --suffix=SUFFIX    Suffix to append to paths\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
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
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_SUFFIX:
                        arg_suffix = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char* argv[]) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (argc > optind) {
                int i, q;

                for (i = optind; i < argc; i++) {
                        q = print_home(argv[i]);
                        if (q < 0)
                                r = q;
                }

                return r;
        } else
                return list_homes();
}

DEFINE_MAIN_FUNCTION(run);
