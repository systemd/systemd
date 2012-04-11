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
#include <stdarg.h>

#include "log.h"
#include "hashmap.h"
#include "strv.h"
#include "util.h"

static int delete_rule(const char *rule) {
        char *x, *fn = NULL, *e;
        int r;

        assert(rule[0]);

        if (!(x = strdup(rule)))
                return -ENOMEM;

        e = strchrnul(x+1, x[0]);
        *e = 0;

        asprintf(&fn, "/proc/sys/fs/binfmt_misc/%s", x+1);
        free(x);

        if (!fn)
                return -ENOMEM;

        r = write_one_line_file(fn, "-1");
        free(fn);

        return r;
}

static int apply_rule(const char *rule) {
        int r;

        delete_rule(rule);

        if ((r = write_one_line_file("/proc/sys/fs/binfmt_misc/register", rule)) < 0) {
                log_error("Failed to add binary format: %s", strerror(-r));
                return r;
        }

        return 0;
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
                char l[LINE_MAX], *p;
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

                if ((k = apply_rule(p)) < 0 && r == 0)
                        r = k;
        }

finish:
        fclose(f);

        return r;
}

int main(int argc, char *argv[]) {
        int r = 0;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc > 1) {
                int i;

                for (i = 1; i < argc; i++) {
                        int k;

                        k = apply_file(argv[i], false);
                        if (k < 0 && r == 0)
                                r = k;
                }
        } else {
                char **files, **f;

                r = conf_files_list(&files, ".conf",
                                    "/etc/binfmt.d",
                                    "/run/binfmt.d",
                                    "/usr/local/lib/binfmt.d",
                                    "/usr/lib/binfmt.d",
#ifdef HAVE_SPLIT_USR
                                    "/lib/binfmt.d",
#endif
                                    NULL);
                if (r < 0) {
                        log_error("Failed to enumerate binfmt.d files: %s", strerror(-r));
                        goto finish;
                }

                /* Flush out all rules */
                write_one_line_file("/proc/sys/fs/binfmt_misc/status", "-1");

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
