/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <libkmod.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#include "conf-files.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "module-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static char **arg_proc_cmdline_modules = NULL;

static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

static void systemd_kmod_log(void *data, int priority, const char *file, int line,
                             const char *fn, const char *format, va_list args) {

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(priority, 0, file, line, fn, format, args);
        REENABLE_WARNING;
}

static int add_modules(const char *p) {
        _cleanup_strv_free_ char **k = NULL;

        k = strv_split(p, ",");
        if (!k)
                return log_oom();

        if (strv_extend_strv(&arg_proc_cmdline_modules, k, true) < 0)
                return log_oom();

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "modules_load")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = add_modules(value);
                if (r < 0)
                        return r;
        }

        return 0;
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

                return log_error_errno(r, "Failed to open %s, ignoring: %m", path);
        }

        log_debug("apply: %s", path);
        for (;;) {
                char line[LINE_MAX], *l;
                int k;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                break;

                        return log_error_errno(errno, "Failed to read file '%s', ignoring: %m", path);
                }

                l = strstrip(line);
                if (!*l)
                        continue;
                if (strchr(COMMENTS "\n", *l))
                        continue;

                k = module_load_and_warn(ctx, l);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static void help(void) {
        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Loads statically configured kernel modules.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n",
               program_invocation_short_name);
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

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, k;
        _cleanup_(kmod_unrefp) struct kmod_ctx *ctx = NULL;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

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
                _cleanup_strv_free_ char **files = NULL;
                char **fn, **i;

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        k = module_load_and_warn(ctx, *i);
                        if (k < 0 && r == 0)
                                r = k;
                }

                k = conf_files_list_nulstr(&files, ".conf", NULL, 0, conf_file_dirs);
                if (k < 0) {
                        log_error_errno(k, "Failed to enumerate modules-load.d files: %m");
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
        strv_free(arg_proc_cmdline_modules);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
