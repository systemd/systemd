/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <getopt.h>

#include "log.h"
#include "strv.h"
#include "util.h"
#include "conf-files.h"
#include "fileio.h"
#include "build.h"

static const char conf_file_dirs[] = CONF_DIRS_NULSTR("binfmt");

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

        return write_string_file(fn, "-1");
}

static int apply_rule(const char *rule) {
        int r;

        delete_rule(rule);

        r = write_string_file("/proc/sys/fs/binfmt_misc/register", rule);
        if (r < 0)
                return log_error_errno(r, "Failed to add binary format: %m");

        return 0;
}

static int apply_file(const char *path, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f);
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

                        log_error_errno(errno, "Failed to read file '%s', ignoring: %m", path);
                        return -errno;
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

static void help(void) {
        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Registers binary formats.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
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
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
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

                r = conf_files_list_nulstr(&files, ".conf", NULL, conf_file_dirs);
                if (r < 0) {
                        log_error_errno(r, "Failed to enumerate binfmt.d files: %m");
                        goto finish;
                }

                /* Flush out all rules */
                write_string_file("/proc/sys/fs/binfmt_misc/status", "-1");

                STRV_FOREACH(f, files) {
                        k = apply_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
