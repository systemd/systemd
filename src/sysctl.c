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
#include <ftw.h>
#include <stdio.h>
#include <limits.h>

#include "log.h"
#include "util.h"

#define PROC_SYS_PREFIX "/proc/sys/"

static int exit_code = 0;

static void apply_sysctl(const char *property, const char *value) {
        char *p, *n;
        int r;

        log_debug("Setting '%s' to '%s'", property, value);

        if (!(p = new(char, sizeof(PROC_SYS_PREFIX) + strlen(property)))) {
                log_error("Out of memory");
                exit_code = -ENOMEM;
                return;
        }

        n = stpcpy(p, PROC_SYS_PREFIX);
        strcpy(n, property);

        for (; *n; n++)
                if (*n == '.')
                        *n = '/';

        if ((r = write_one_line_file(p, value)) < 0) {

                log_full(r == -ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to write '%s' to '%s': %s", value, p, strerror(-r));

                if (r != -ENOENT)
                        exit_code = r;
        }

        free(p);
}

static void apply_file(const char *path) {
        FILE *f;

        assert(path);

        if (!(f = fopen(path, "re"))) {
                log_error("Failed to open file '%s', ignoring: %m", path);
                exit_code = -errno;
                return;
        }

        while (!feof(f)) {
                char l[LINE_MAX], *p, *value;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        log_error("Failed to read file '%s', ignoring: %m", path);
                        exit_code = -errno;
                        goto finish;
                }

                p = strstrip(l);

                if (!*p)
                        continue;

                if (strchr(COMMENTS, *p))
                        continue;

                if (!(value = strchr(p, '='))) {
                        log_error("Line is not an assignment in file '%s': %s", path, value);
                        exit_code = -EINVAL;
                        continue;
                }

                *value = 0;
                value++;

                apply_sysctl(strstrip(p), strstrip(value));
        }

finish:
        fclose(f);
}

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        if (tflag != FTW_F)
                return 0;

        if (ignore_file(fpath + ftwbuf->base))
                return 0;

        if (!endswith(fpath, ".conf"))
                return 0;

        apply_file(fpath);
        return 0;
};

int main(int argc, char *argv[]) {

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc > 1)
                nftw(argv[1], nftw_cb, 64, FTW_MOUNT|FTW_PHYS);
        else {
                nftw("/etc/sysctl.conf", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);
                nftw("/etc/sysctl.d", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);
        }

        return exit_code < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
