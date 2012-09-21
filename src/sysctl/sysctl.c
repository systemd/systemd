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
#include "strv.h"
#include "hashmap.h"
#include "path-util.h"
#include "conf-files.h"

#define PROC_SYS_PREFIX "/proc/sys/"

static char **arg_prefixes;
static Hashmap *sysctl_options;

static int apply_sysctl(const char *property, const char *value) {
        char *p, *n;
        int r = 0, k;

        log_debug("Setting '%s' to '%s'", property, value);

        p = new(char, sizeof(PROC_SYS_PREFIX) + strlen(property));
        if (!p)
                return log_oom();

        n = stpcpy(p, PROC_SYS_PREFIX);
        strcpy(n, property);

        for (; *n; n++)
                if (*n == '.')
                        *n = '/';

        if (!strv_isempty(arg_prefixes)) {
                char **i;
                bool good = false;

                STRV_FOREACH(i, arg_prefixes)
                        if (path_startswith(p, *i)) {
                                good = true;
                                break;
                        }

                if (!good) {
                        log_debug("Skipping %s", p);
                        free(p);
                        return 0;
                }
        }

        k = write_one_line_file(p, value);
        if (k < 0) {

                log_full(k == -ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to write '%s' to '%s': %s", value, p, strerror(-k));

                if (k != -ENOENT && r == 0)
                        r = k;
        }

        free(p);

        return r;
}

static int apply_all(void) {
        int r = 0;
        char *property, *value;
        Iterator i;

        HASHMAP_FOREACH_KEY(value, property, sysctl_options, i) {
                int k;

                k = apply_sysctl(property, value);
                if (k < 0 && r == 0)
                        r = k;
        }
        return r;
}

static int parse_file(const char *path, bool ignore_enoent) {
        FILE *f;
        int r = 0;

        assert(path);

        f = fopen(path, "re");
        if (!f) {
                if (ignore_enoent && errno == ENOENT)
                        return 0;

                log_error("Failed to open file '%s', ignoring: %m", path);
                return -errno;
        }

        log_debug("parse: %s\n", path);
        while (!feof(f)) {
                char l[LINE_MAX], *p, *value, *new_value, *property;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        log_error("Failed to read file '%s', ignoring: %m", path);
                        r = -errno;
                        goto finish;
                }

                p = strstrip(l);

                if (!*p)
                        continue;

                if (strchr(COMMENTS, *p))
                        continue;

                value = strchr(p, '=');
                if (!value) {
                        log_error("Line is not an assignment in file '%s': %s", path, value);

                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                *value = 0;
                value++;

                property = strdup(strstrip(p));
                if (!property) {
                        r = log_oom();
                        goto finish;
                }

                new_value = strdup(strstrip(value));
                if (!new_value) {
                        free(property);
                        r = log_oom();
                        goto finish;
                }

                r = hashmap_put(sysctl_options, property, new_value);
                if (r < 0) {
                        if (r == -EEXIST)
                                log_debug("Skipping previously assigned sysctl variable %s", property);
                        else
                                log_error("Failed to add sysctl variable %s to hashmap: %s", property, strerror(-r));

                        free(property);
                        free(new_value);
                        if (r != -EEXIST)
                                goto finish;
                }
        }

finish:
        fclose(f);

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Applies kernel sysctl settings.\n\n"
               "  -h --help             Show this help\n"
               "     --prefix=PATH      Only apply rules that apply to paths with the specified prefix\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_PREFIX
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "prefix",    required_argument, NULL, ARG_PREFIX    },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_PREFIX: {
                        char *p;
                        char **l;

                        for (p = optarg; *p; p++)
                                if (*p == '.')
                                        *p = '/';

                        l = strv_append(arg_prefixes, optarg);
                        if (!l)
                                return log_oom();

                        strv_free(arg_prefixes);
                        arg_prefixes = l;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r = 0, k;
        char *property, *value;
        Iterator it;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        sysctl_options = hashmap_new(string_hash_func, string_compare_func);
        if (!sysctl_options) {
                r = log_oom();
                goto finish;
        }

        r = 0;

        if (argc > optind) {
                int i;

                for (i = optind; i < argc; i++) {
                        k = parse_file(argv[i], false);
                        if (k < 0)
                                r = k;
                }
        } else {
                char **files, **f;

                r = conf_files_list(&files, ".conf",
                                    "/etc/sysctl.d",
                                    "/run/sysctl.d",
                                    "/usr/local/lib/sysctl.d",
                                    "/usr/lib/sysctl.d",
#ifdef HAVE_SPLIT_USR
                                    "/lib/sysctl.d",
#endif
                                    NULL);
                if (r < 0) {
                        log_error("Failed to enumerate sysctl.d files: %s", strerror(-r));
                        goto finish;
                }

                /* We parse the files in decreasing order of precedence.
                 * parse_file() will skip keys that were already assigned. */

                r = parse_file("/etc/sysctl.conf", true);

                f = files + strv_length(files) - 1;
                STRV_FOREACH_BACKWARDS(f, files) {
                        k = parse_file(*f, true);
                        if (k < 0)
                                r = k;
                }

                strv_free(files);
        }

        k = apply_all();
        if (k < 0)
                r = k;

finish:
        HASHMAP_FOREACH_KEY(value, property, sysctl_options, it) {
                hashmap_remove(sysctl_options, property);
                free(property);
                free(value);
        }
        hashmap_free(sysctl_options);

        strv_free(arg_prefixes);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
