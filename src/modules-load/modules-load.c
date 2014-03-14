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
#include <getopt.h>
#include <libkmod.h>

#include "log.h"
#include "util.h"
#include "strv.h"
#include "conf-files.h"
#include "fileio.h"
#include "build.h"

static char **arg_proc_cmdline_modules = NULL;

static const char conf_file_dirs[] =
        "/etc/modules-load.d\0"
        "/run/modules-load.d\0"
        "/usr/local/lib/modules-load.d\0"
        "/usr/lib/modules-load.d\0"
#ifdef HAVE_SPLIT_USR
        "/lib/modules-load.d\0"
#endif
        ;

static void systemd_kmod_log(void *data, int priority, const char *file, int line,
                             const char *fn, const char *format, va_list args) {

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_metav(priority, file, line, fn, format, args);
        REENABLE_WARNING;
}

static int add_modules(const char *p) {
        _cleanup_strv_free_ char **k = NULL;

        k = strv_split(p, ",");
        if (!k)
                return log_oom();

        if (strv_extend_strv(&arg_proc_cmdline_modules, k) < 0)
                return log_oom();

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value) {
        int r;

        if (STR_IN_SET(key, "modules-load", "rd.modules-load") && value) {
                r = add_modules(value);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int load_module(struct kmod_ctx *ctx, const char *m) {
        const int probe_flags = KMOD_PROBE_APPLY_BLACKLIST;
        struct kmod_list *itr, *modlist = NULL;
        int r = 0;

        log_debug("load: %s", m);

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
                        log_debug("Module '%s' is already loaded", kmod_module_get_name(mod));
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

static int apply_file(struct kmod_ctx *ctx, const char *path, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(ctx);
        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                log_error("Failed to open %s, ignoring: %s", path, strerror(-r));
                return r;
        }

        log_debug("apply: %s", path);
        for (;;) {
                char line[LINE_MAX], *l;
                int k;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                break;

                        log_error("Failed to read file '%s', ignoring: %m", path);
                        return -errno;
                }

                l = strstrip(line);
                if (!*l)
                        continue;
                if (strchr(COMMENTS "\n", *l))
                        continue;

                k = load_module(ctx, l);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Loads statically configured kernel modules.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n",
               program_invocation_short_name);

        return 0;
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

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, k;
        struct kmod_ctx *ctx;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (parse_proc_cmdline(parse_proc_cmdline_item) < 0)
                return EXIT_FAILURE;

        ctx = kmod_new(NULL, NULL);
        if (!ctx) {
                log_error("Failed to allocate memory for kmod.");
                goto finish;
        }

        kmod_load_resources(ctx);
        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

        r = 0;

        if (argc > optind) {
                int i;

                for (i = optind; i < argc; i++) {
                        k = apply_file(ctx, argv[i], false);
                        if (k < 0 && r == 0)
                                r = k;
                }

        } else {
                _cleanup_free_ char **files = NULL;
                char **fn, **i;

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        k = load_module(ctx, *i);
                        if (k < 0 && r == 0)
                                r = k;
                }

                k = conf_files_list_nulstr(&files, ".conf", NULL, conf_file_dirs);
                if (k < 0) {
                        log_error("Failed to enumerate modules-load.d files: %s", strerror(-k));
                        if (r == 0)
                                r = k;
                        goto finish;
                }

                STRV_FOREACH(fn, files) {
                        k = apply_file(ctx, *fn, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

finish:
        kmod_unref(ctx);
        strv_free(arg_proc_cmdline_modules);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
