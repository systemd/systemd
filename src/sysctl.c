/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "log.h"
#include "strv.h"
#include "util.h"

#define PROC_SYS_PREFIX "/proc/sys/"

static int apply_sysctl(const char *property, const char *value) {
        char *p, *n;
        int r = 0, k;

        log_debug("Setting '%s' to '%s'", property, value);

        if (!(p = new(char, sizeof(PROC_SYS_PREFIX) + strlen(property)))) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        n = stpcpy(p, PROC_SYS_PREFIX);
        strcpy(n, property);

        for (; *n; n++)
                if (*n == '.')
                        *n = '/';

        if ((k = write_one_line_file(p, value)) < 0) {

                log_full(k == -ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to write '%s' to '%s': %s", value, p, strerror(-k));

                if (k != -ENOENT && r == 0)
                        r = k;
        }

        free(p);

        return r;
}

static int apply_file(const char *path, bool ignore_enoent) {
        FILE *f;
        int r = 0;

        assert(path);

        if (!(f = fopen(path, "re"))) {
                if (ignore_enoent && errno == ENOENT)
                        return 0;

                log_error("Failed to open file '%s', ignoring: %m", path);
                return -errno;
        }

        log_debug("apply: %s\n", path);
        while (!feof(f)) {
                char l[LINE_MAX], *p, *value;
                int k;

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

                if (!(value = strchr(p, '='))) {
                        log_error("Line is not an assignment in file '%s': %s", path, value);

                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                *value = 0;
                value++;

                if ((k = apply_sysctl(strstrip(p), strstrip(value))) < 0 && r == 0)
                        r = k;
        }

finish:
        fclose(f);

        return r;
}

int main(int argc, char *argv[]) {
        int r = 0;

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc > 1)
                r = apply_file(argv[1], false);
        else {
                char **files, **f;

                apply_file("/etc/sysctl.conf", true);

                r = conf_files_list(&files, ".conf",
                                    "/run/sysctl.d",
                                    "/etc/sysctl.d",
                                    "/usr/lib/sysctl.d",
                                    NULL);
                if (r < 0) {
                        log_error("Failed to enumerate sysctl.d files: %s", strerror(-r));
                        goto finish;
                }

                STRV_FOREACH(f, files) {
                        int k;

                        k = apply_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }

                strv_free(files);
        }
finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
