/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "sd-path.h"

#include "alloc-util.h"
#include "build.h"
#include "errno-util.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "pretty-print.h"
#include "sort-util.h"
#include "string-util.h"

static const char *arg_suffix = NULL;
static PagerFlags arg_pager_flags = 0;

static const char* const path_table[_SD_PATH_MAX] = {
        [SD_PATH_TEMPORARY]                                   = "temporary",
        [SD_PATH_TEMPORARY_LARGE]                             = "temporary-large",

        [SD_PATH_SYSTEM_SEARCH_CONFIGURATION]                 = "system-search-configuration",

        [SD_PATH_SYSTEM_BINARIES]                             = "system-binaries",
        [SD_PATH_SYSTEM_INCLUDE]                              = "system-include",
        [SD_PATH_SYSTEM_LIBRARY_PRIVATE]                      = "system-library-private",
        [SD_PATH_SYSTEM_LIBRARY_ARCH]                         = "system-library-arch",
        [SD_PATH_SYSTEM_SHARED]                               = "system-shared",
        [SD_PATH_SYSTEM_CONFIGURATION_FACTORY]                = "system-configuration-factory",
        [SD_PATH_SYSTEM_STATE_FACTORY]                        = "system-state-factory",

        [SD_PATH_SYSTEM_CONFIGURATION]                        = "system-configuration",
        [SD_PATH_SYSTEM_RUNTIME]                              = "system-runtime",
        [SD_PATH_SYSTEM_RUNTIME_LOGS]                         = "system-runtime-logs",
        [SD_PATH_SYSTEM_STATE_PRIVATE]                        = "system-state-private",
        [SD_PATH_SYSTEM_STATE_LOGS]                           = "system-state-logs",
        [SD_PATH_SYSTEM_STATE_CACHE]                          = "system-state-cache",
        [SD_PATH_SYSTEM_STATE_SPOOL]                          = "system-state-spool",

        [SD_PATH_USER_BINARIES]                               = "user-binaries",
        [SD_PATH_USER_LIBRARY_PRIVATE]                        = "user-library-private",
        [SD_PATH_USER_LIBRARY_ARCH]                           = "user-library-arch",
        [SD_PATH_USER_SHARED]                                 = "user-shared",

        [SD_PATH_USER_CONFIGURATION]                          = "user-configuration",
        [SD_PATH_USER_RUNTIME]                                = "user-runtime",
        [SD_PATH_USER_STATE_CACHE]                            = "user-state-cache",
        [SD_PATH_USER_STATE_PRIVATE]                          = "user-state-private",

        [SD_PATH_USER]                                        = "user",
        [SD_PATH_USER_DOCUMENTS]                              = "user-documents",
        [SD_PATH_USER_MUSIC]                                  = "user-music",
        [SD_PATH_USER_PICTURES]                               = "user-pictures",
        [SD_PATH_USER_VIDEOS]                                 = "user-videos",
        [SD_PATH_USER_DOWNLOAD]                               = "user-download",
        [SD_PATH_USER_PUBLIC]                                 = "user-public",
        [SD_PATH_USER_TEMPLATES]                              = "user-templates",
        [SD_PATH_USER_DESKTOP]                                = "user-desktop",

        [SD_PATH_SEARCH_BINARIES]                             = "search-binaries",
        [SD_PATH_SEARCH_BINARIES_DEFAULT]                     = "search-binaries-default",
        [SD_PATH_SEARCH_LIBRARY_PRIVATE]                      = "search-library-private",
        [SD_PATH_SEARCH_LIBRARY_ARCH]                         = "search-library-arch",
        [SD_PATH_SEARCH_SHARED]                               = "search-shared",
        [SD_PATH_SEARCH_CONFIGURATION_FACTORY]                = "search-configuration-factory",
        [SD_PATH_SEARCH_STATE_FACTORY]                        = "search-state-factory",
        [SD_PATH_SEARCH_CONFIGURATION]                        = "search-configuration",

        [SD_PATH_SYSTEMD_UTIL]                                = "systemd-util",

        [SD_PATH_SYSTEMD_SYSTEM_UNIT]                         = "systemd-system-unit",
        [SD_PATH_SYSTEMD_SYSTEM_PRESET]                       = "systemd-system-preset",
        [SD_PATH_SYSTEMD_SYSTEM_CONF]                         = "systemd-system-conf",
        [SD_PATH_SYSTEMD_USER_UNIT]                           = "systemd-user-unit",
        [SD_PATH_SYSTEMD_USER_PRESET]                         = "systemd-user-preset",
        [SD_PATH_SYSTEMD_USER_CONF]                           = "systemd-user-conf",
        [SD_PATH_SYSTEMD_INITRD_PRESET]                       = "systemd-initrd-preset",

        [SD_PATH_SYSTEMD_SEARCH_SYSTEM_UNIT]                  = "systemd-search-system-unit",
        [SD_PATH_SYSTEMD_SEARCH_USER_UNIT]                    = "systemd-search-user-unit",

        [SD_PATH_SYSTEMD_SYSTEM_GENERATOR]                    = "systemd-system-generator",
        [SD_PATH_SYSTEMD_USER_GENERATOR]                      = "systemd-user-generator",
        [SD_PATH_SYSTEMD_SEARCH_SYSTEM_GENERATOR]             = "systemd-search-system-generator",
        [SD_PATH_SYSTEMD_SEARCH_USER_GENERATOR]               = "systemd-search-user-generator",

        [SD_PATH_SYSTEMD_SLEEP]                               = "systemd-sleep",
        [SD_PATH_SYSTEMD_SHUTDOWN]                            = "systemd-shutdown",

        [SD_PATH_TMPFILES]                                    = "tmpfiles",
        [SD_PATH_SYSUSERS]                                    = "sysusers",
        [SD_PATH_SYSCTL]                                      = "sysctl",
        [SD_PATH_BINFMT]                                      = "binfmt",
        [SD_PATH_MODULES_LOAD]                                = "modules-load",
        [SD_PATH_CATALOG]                                     = "catalog",

        [SD_PATH_SYSTEMD_SEARCH_NETWORK]                      = "systemd-search-network",

        [SD_PATH_SYSTEMD_SYSTEM_ENVIRONMENT_GENERATOR]        = "systemd-system-environment-generator",
        [SD_PATH_SYSTEMD_USER_ENVIRONMENT_GENERATOR]          = "systemd-user-environment-generator",
        [SD_PATH_SYSTEMD_SEARCH_SYSTEM_ENVIRONMENT_GENERATOR] = "systemd-search-system-environment-generator",
        [SD_PATH_SYSTEMD_SEARCH_USER_ENVIRONMENT_GENERATOR]   = "systemd-search-user-environment-generator",

        [SD_PATH_SYSTEM_CREDENTIAL_STORE]                     = "system-credential-store",
        [SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE]              = "system-search-credential-store",
        [SD_PATH_SYSTEM_CREDENTIAL_STORE_ENCRYPTED]           = "system-credential-store-encrypted",
        [SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE_ENCRYPTED]    = "system-search-credential-store-encrypted",
        [SD_PATH_USER_CREDENTIAL_STORE]                       = "user-credential-store",
        [SD_PATH_USER_SEARCH_CREDENTIAL_STORE]                = "user-search-credential-store",
        [SD_PATH_USER_CREDENTIAL_STORE_ENCRYPTED]             = "user-credential-store-encrypted",
        [SD_PATH_USER_SEARCH_CREDENTIAL_STORE_ENCRYPTED]      = "user-search-credential-store-encrypted",
};

static int order_cmp(const size_t *a, const size_t *b) {
        assert(*a < ELEMENTSOF(path_table));
        assert(*b < ELEMENTSOF(path_table));
        return strcmp(path_table[*a], path_table[*b]);
}

static int list_paths(void) {
        int ret = 0, r;

        pager_open(arg_pager_flags);

        size_t order[ELEMENTSOF(path_table)];

        for (size_t i = 0; i < ELEMENTSOF(order); i++)
                order[i] = i;

        typesafe_qsort(order, ELEMENTSOF(order), order_cmp);

        for (size_t i = 0; i < ELEMENTSOF(order); i++) {
                size_t j = order[i];
                const char *t = ASSERT_PTR(path_table[j]);

                _cleanup_free_ char *p = NULL;
                r = sd_path_lookup(j, arg_suffix, &p);
                if (r < 0) {
                        log_full_errno(r == -ENXIO ? LOG_DEBUG : LOG_ERR, r, "Failed to query %s, proceeding: %m", t);
                        if (r != -ENXIO)
                                RET_GATHER(ret, r);
                        continue;
                }

                printf("%s%s:%s %s\n", ansi_highlight(), t, ansi_normal(), p);
        }

        return ret;
}

static int print_path(const char *n) {
        int r;

        for (size_t i = 0; i < ELEMENTSOF(path_table); i++)
                if (streq(path_table[i], n)) {
                        _cleanup_free_ char *p = NULL;

                        r = sd_path_lookup(i, arg_suffix, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query %s: %m", n);

                        printf("%s\n", p);
                        return 0;
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

        printf("%s [OPTIONS...] [NAME...]\n"
               "\n%sShow system and user paths.%s\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --suffix=SUFFIX    Suffix to append to paths\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_SUFFIX,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "suffix",    required_argument, NULL, ARG_SUFFIX    },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
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

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
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

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (optind >= argc)
                return list_paths();

        for (int i = optind; i < argc; i++)
                RET_GATHER(r, print_path(argv[i]));
        return r;
}

DEFINE_MAIN_FUNCTION(run);
