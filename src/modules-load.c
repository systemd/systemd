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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

#include "log.h"
#include "util.h"
#include "strv.h"

/* This reads all module names listed in /etc/modules.d/?*.modules and
 * loads them into the kernel. This follows roughly Debian's way to
 * handle modules, but uses a directory of fragments instead of a
 * single /etc/modules file. */

static int scandir_filter(const struct dirent *d) {
        assert(d);

        if (ignore_file(d->d_name))
                return 0;

        if (d->d_type != DT_REG &&
            d->d_type != DT_LNK)
                return 0;

        return endswith(d->d_name, ".modules");
}

int main(int argc, char *argv[]) {
        struct dirent **de = NULL;
        int r = 1, n, i;
        char **arguments = NULL;
        unsigned n_arguments = 0, n_allocated = 0;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return 1;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (!(arguments = strv_new("/sbin/modprobe", "-sab", "--", NULL))) {
                log_error("Failed to allocate string array");
                goto finish;
        }

        n_arguments = n_allocated = 3;

        if ((n = scandir("/etc/modules.d/", &de, scandir_filter, alphasort)) < 0) {

                if (errno == ENOENT)
                        r = 0;
                else
                        log_error("Failed to enumerate /etc/modules.d/ files: %m");

                goto finish;
        }

        r = 0;

        for (i = 0; i < n; i++) {
                int k;
                char *fn;
                FILE *f;

                k = asprintf(&fn, "/etc/modules.d/%s", de[i]->d_name);
                free(de[i]);

                if (k < 0) {
                        log_error("Failed to allocate file name.");
                        r = 1;
                        continue;
                }

                f = fopen(fn, "re");
                free(fn);

                if (!f) {
                        log_error("Failed to open %s: %m", fn);
                        r = 1;
                        continue;
                }

                for (;;) {
                        char line[LINE_MAX], *l, *t;

                        if (!(fgets(line, sizeof(line), f)))
                                break;

                        l = strstrip(line);
                        if (*l == '#' || *l == 0)
                                continue;

                        if (!(t = strdup(l))) {
                                log_error("Failed to allocate module name.");
                                continue;
                        }

                        if (n_arguments >= n_allocated) {
                                char **a;
                                unsigned m;

                                m = MAX(16U, n_arguments*2);

                                if (!(a = realloc(arguments, sizeof(char*) * (m+1)))) {
                                        log_error("Failed to increase module array size.");
                                        free(t);
                                        r = 1;
                                        continue;
                                }

                                arguments = a;
                                n_allocated = m;
                        }

                        arguments[n_arguments++] = t;
                }

                if (ferror(f)) {
                        r = 1;
                        log_error("Failed to read from file: %m");
                }

                fclose(f);
        }

        free(de);

finish:

        if (n_arguments > 3) {
                arguments[n_arguments] = NULL;
                execv("/sbin/modprobe", arguments);

                log_error("Failed to execute /sbin/modprobe: %m");
                r = 1;
        }

        strv_free(arguments);

        return r;
}
