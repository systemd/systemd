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
#include <libkmod.h>

#include "log.h"
#include "util.h"
#include "strv.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static void systemd_kmod_log(void *data, int priority, const char *file, int line,
                             const char *fn, const char *format, va_list args)
{
        log_meta(priority, file, line, fn, format, args);
}
#pragma GCC diagnostic pop

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE;
        char **files, **fn;
        struct kmod_ctx *ctx;
        const int probe_flags = KMOD_PROBE_APPLY_BLACKLIST|KMOD_PROBE_IGNORE_LOADED;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        ctx = kmod_new(NULL, NULL);
        if (!ctx) {
                log_error("Failed to allocate memory for kmod.");
                goto finish;
        }

        kmod_load_resources(ctx);

        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

        if (conf_files_list(&files, ".conf",
                            "/etc/modules-load.d",
                            "/run/modules-load.d",
                            "/usr/local/lib/modules-load.d",
                            "/usr/lib/modules-load.d",
#ifdef HAVE_SPLIT_USR
                            "/lib/modules-load.d",
#endif
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
                        char line[LINE_MAX], *l;
                        struct kmod_list *itr, *modlist = NULL;
                        int err;

                        if (!fgets(line, sizeof(line), f))
                                break;

                        l = strstrip(line);
                        if (*l == '#' || *l == 0)
                                continue;

                        err = kmod_module_new_from_lookup(ctx, l, &modlist);
                        if (err < 0) {
                                log_error("Failed to lookup alias '%s'", l);
                                r = EXIT_FAILURE;
                                continue;
                        }

                        kmod_list_foreach(itr, modlist) {
                                struct kmod_module *mod;

                                mod = kmod_module_get_module(itr);
                                err = kmod_module_probe_insert_module(mod, probe_flags,
                                                                      NULL, NULL, NULL, NULL);

                                if (err == 0)
                                        log_info("Inserted module '%s'", kmod_module_get_name(mod));
                                else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                                        log_info("Module '%s' is blacklisted", kmod_module_get_name(mod));
                                else {
                                        log_error("Failed to insert '%s': %s", kmod_module_get_name(mod),
                                                        strerror(-err));
                                        r = EXIT_FAILURE;
                                }

                                kmod_module_unref(mod);
                        }

                        kmod_module_unref_list(modlist);
                }

                if (ferror(f)) {
                        log_error("Failed to read from file: %m");
                        r = EXIT_FAILURE;
                }

                fclose(f);
        }

finish:
        strv_free(files);
        kmod_unref(ctx);

        return r;
}
