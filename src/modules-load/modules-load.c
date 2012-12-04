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
#include "conf-files.h"
#include "virt.h"

static char **arg_proc_cmdline_modules = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static void systemd_kmod_log(void *data, int priority, const char *file, int line,
                             const char *fn, const char *format, va_list args)
{
        log_metav(priority, file, line, fn, format, args);
}
#pragma GCC diagnostic pop

static int add_modules(const char *p) {
        char **t, **k;

        k = strv_split(p, ",");
        if (!k)
                return log_oom();

        t = strv_merge(arg_proc_cmdline_modules, k);
        strv_free(k);
        if (!t)
                return log_oom();

        strv_free(arg_proc_cmdline_modules);
        arg_proc_cmdline_modules = t;

        return 0;
}

static int parse_proc_cmdline(void) {
        char _cleanup_free_ *line = NULL;
        char *w, *state;
        int r;
        size_t l;

        if (detect_container(NULL) > 0)
                return 0;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char _cleanup_free_ *word;

                word = strndup(w, l);
                if (!word)
                        return log_oom();

                if (startswith(word, "modules-load=")) {

                        r = add_modules(word + 13);
                        if (r < 0)
                                return r;

                } else if (startswith(word, "rd.modules-load=")) {

                        if (in_initrd()) {
                                r = add_modules(word + 16);
                                if (r < 0)
                                        return r;
                        }

                }
        }

        return 0;
}

static int load_module(struct kmod_ctx *ctx, const char *m) {
        const int probe_flags = KMOD_PROBE_APPLY_BLACKLIST;
        struct kmod_list *itr, *modlist = NULL;
        int r = 0;

        log_debug("load: %s\n", m);

        r = kmod_module_new_from_lookup(ctx, m, &modlist);
        if (r < 0) {
                log_error("Failed to lookup alias '%s': %s", m, strerror(-r));
                return r;
        }

        if (!modlist) {
                log_error("Failed to find module '%s'", m);
                return -ENOENT;
        }

        kmod_list_foreach(itr, modlist) {
                struct kmod_module *mod;
                int state, err;

                mod = kmod_module_get_module(itr);
                state = kmod_module_get_initstate(mod);

                switch (state) {
                case KMOD_MODULE_BUILTIN:
                        log_info("Module '%s' is builtin", kmod_module_get_name(mod));
                        break;

                case KMOD_MODULE_LIVE:
                        log_info("Module '%s' is already loaded", kmod_module_get_name(mod));
                        break;

                default:
                        err = kmod_module_probe_insert_module(mod, probe_flags,
                                                              NULL, NULL, NULL, NULL);

                        if (err == 0)
                                log_info("Inserted module '%s'", kmod_module_get_name(mod));
                        else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                                log_info("Module '%s' is blacklisted", kmod_module_get_name(mod));
                        else {
                                log_error("Failed to insert '%s': %s", kmod_module_get_name(mod),
                                          strerror(-err));
                                r = err;
                        }
                }

                kmod_module_unref(mod);
        }

        kmod_module_unref_list(modlist);

        return r;
}

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE, k;
        char **files = NULL, **fn, **i;
        struct kmod_ctx *ctx;

        if (argc > 1) {
                log_error("This program takes no argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (parse_proc_cmdline() < 0)
                return EXIT_FAILURE;

        ctx = kmod_new(NULL, NULL);
        if (!ctx) {
                log_error("Failed to allocate memory for kmod.");
                goto finish;
        }

        kmod_load_resources(ctx);
        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

        r = EXIT_SUCCESS;

        STRV_FOREACH(i, arg_proc_cmdline_modules) {
                k = load_module(ctx, *i);
                if (k < 0)
                        r = EXIT_FAILURE;
        }

        k = conf_files_list(&files, ".conf",
                            "/etc/modules-load.d",
                            "/run/modules-load.d",
                            "/usr/local/lib/modules-load.d",
                            "/usr/lib/modules-load.d",
#ifdef HAVE_SPLIT_USR
                            "/lib/modules-load.d",
#endif
                            NULL);
        if (k < 0) {
                log_error("Failed to enumerate modules-load.d files: %s", strerror(-k));
                r = EXIT_FAILURE;
                goto finish;
        }

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

                        if (!fgets(line, sizeof(line), f))
                                break;

                        l = strstrip(line);
                        if (*l == '#' || *l == 0)
                                continue;

                        k = load_module(ctx, l);
                        if (k < 0)
                                r = EXIT_FAILURE;
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
        strv_free(arg_proc_cmdline_modules);

        return r;
}
