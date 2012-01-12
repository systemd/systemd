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

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE;
        char **arguments = NULL;
        unsigned n_arguments = 0, n_allocated = 0;
        char **files, **fn;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (!(arguments = strv_new("/sbin/modprobe", "-sab", "--", NULL))) {
                log_error("Failed to allocate string array");
                goto finish;
        }

        n_arguments = n_allocated = 3;

        if (conf_files_list(&files, ".conf",
                            "/run/modules-load.d",
                            "/etc/modules-load.d",
                            "/usr/local/lib/modules-load.d",
                            "/usr/lib/modules-load.d",
                            "/lib/modules-load.d",
                            NULL) < 0) {
                log_error("Failed to enumerate modules-load.d files: %s", strerror(-r));
                goto finish;
        }

        r = EXIT_SUCCESS;

        STRV_FOREACH(fn, files) {
                FILE *f;

                f = fopen(*fn, "re");
                if (!f) {
                        if (errno == ENOENT)
                                continue;

                        log_error("Failed to open %s: %m", *fn);
                        r = EXIT_FAILURE;
                        continue;
                }

                log_debug("apply: %s\n", *fn);
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
                                        r = EXIT_FAILURE;
                                        continue;
                                }

                                arguments = a;
                                n_allocated = m;
                        }

                        arguments[n_arguments++] = t;
                }

                if (ferror(f)) {
                        r = EXIT_FAILURE;
                        log_error("Failed to read from file: %m");
                }

                fclose(f);
        }

        strv_free(files);
finish:

        if (n_arguments > 3) {
                arguments[n_arguments] = NULL;
                strv_uniq(arguments);
                execv("/sbin/modprobe", arguments);

                log_error("Failed to execute /sbin/modprobe: %m");
                r = EXIT_FAILURE;
        }

        strv_free(arguments);

        return r;
}
