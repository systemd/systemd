/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "pager.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

static bool arg_cat_config = false;
static bool arg_no_pager = false;

static int delete_rule(const char *rule) {
        _cleanup_free_ char *x = NULL, *fn = NULL;
        char *e;

        assert(rule[0]);

        x = strdup(rule);
        if (!x)
                return log_oom();

        e = strchrnul(x+1, x[0]);
        *e = 0;

        fn = strappend("/proc/sys/fs/binfmt_misc/", x+1);
        if (!fn)
                return log_oom();

        return write_string_file(fn, "-1", 0);
}

static int apply_rule(const char *rule) {
        int r;

        delete_rule(rule);

        r = write_string_file("/proc/sys/fs/binfmt_misc/register", rule, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add binary format: %m");

        return 0;
}

static int apply_file(const char *path, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(path);

        r = search_and_fopen(path, "re", NULL, (const char**) CONF_PATHS_STRV("binfmt.d"), &f);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open file '%s', ignoring: %m", path);
        }

        log_debug("apply: %s", path);
        for (;;) {
                char l[LINE_MAX], *p;
                int k;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        return log_error_errno(errno, "Failed to read file '%s', ignoring: %m", path);
                }

                p = strstrip(l);
                if (!*p)
                        continue;
                if (strchr(COMMENTS "\n", *p))
                        continue;

                k = apply_rule(p);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-binfmt.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Registers binary formats with the kernel.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --cat-config       Show configuration files\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",       no_argument, NULL, 'h'            },
                { "version",    no_argument, NULL, ARG_VERSION    },
                { "cat-config", no_argument, NULL, ARG_CAT_CONFIG },
                { "no-pager",   no_argument, NULL, ARG_NO_PAGER   },
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

                case ARG_CAT_CONFIG:
                        arg_cat_config = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_cat_config && argc > optind) {
                log_error("Positional arguments are not allowed with --cat-config");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, k;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = 0;

        if (argc > optind) {
                int i;

                for (i = optind; i < argc; i++) {
                        k = apply_file(argv[i], false);
                        if (k < 0 && r == 0)
                                r = k;
                }
        } else {
                _cleanup_strv_free_ char **files = NULL;
                char **f;

                r = conf_files_list_strv(&files, ".conf", NULL, 0, (const char**) CONF_PATHS_STRV("binfmt.d"));
                if (r < 0) {
                        log_error_errno(r, "Failed to enumerate binfmt.d files: %m");
                        goto finish;
                }

                if (arg_cat_config) {
                        (void) pager_open(arg_no_pager, false);

                        r = cat_files(NULL, files, 0);
                        goto finish;
                }

                /* Flush out all rules */
                write_string_file("/proc/sys/fs/binfmt_misc/status", "-1", 0);

                STRV_FOREACH(f, files) {
                        k = apply_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
