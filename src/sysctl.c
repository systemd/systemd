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

static int scandir_filter(const struct dirent *d) {
        assert(d);

        if (ignore_file(d->d_name))
                return 0;

        if (d->d_type != DT_REG &&
            d->d_type != DT_LNK &&
            d->d_type != DT_UNKNOWN)
                return 0;

        return endswith(d->d_name, ".conf");
}

static int apply_tree(const char *path) {
        struct dirent **de = NULL;
        int n, i, r = 0;

        if ((n = scandir(path, &de, scandir_filter, alphasort)) < 0) {

                if (errno == ENOENT)
                        return 0;

                log_error("Failed to enumerate %s files: %m", path);
                return -errno;
        }

        for (i = 0; i < n; i++) {
                char *fn;
                int k;

                k = asprintf(&fn, "%s/%s", path, de[i]->d_name);
                free(de[i]);

                if (k < 0) {
                        log_error("Failed to allocate file name.");

                        if (r == 0)
                                r = -ENOMEM;
                        continue;
                }

                if ((k = apply_file(fn, true)) < 0 && r == 0)
                        r = k;
        }

        free(de);

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
                int k;

                r = apply_file("/etc/sysctl.conf", true);

                if ((k = apply_tree("/etc/sysctl.d")) < 0 && r == 0)
                        r = k;
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
