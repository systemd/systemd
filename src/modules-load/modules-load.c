/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>

#include "conf-files.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "module-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static char **arg_proc_cmdline_modules = NULL;
static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

STATIC_DESTRUCTOR_REGISTER(arg_proc_cmdline_modules, strv_freep);

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
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(ctx);
        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f, &pp);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open %s: %m", path);
        }

        log_debug("apply: %s", pp);
        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *l;
                int k;

                k = read_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read file '%s': %m", pp);
                if (k == 0)
                        break;

                l = strstrip(line);
                if (isempty(l))
                        continue;
                if (strchr(COMMENTS, *l))
                        continue;

                k = module_load_and_warn(ctx, l, true);
                if (k == -ENOENT)
                        continue;
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-modules-load.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Loads statically configured kernel modules.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

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

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(kmod_unrefp) struct kmod_ctx *ctx = NULL;
        int r, k;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        ctx = kmod_new(NULL, NULL);
        if (!ctx) {
                log_error("Failed to allocate memory for kmod.");
                return -ENOMEM;
        }

        kmod_load_resources(ctx);
        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

        r = 0;

        if (argc > optind) {
                for (int i = optind; i < argc; i++) {
                        k = apply_file(ctx, argv[i], false);
                        if (k < 0 && r == 0)
                                r = k;
                }

        } else {
                _cleanup_strv_free_ char **files = NULL;

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        k = module_load_and_warn(ctx, *i, true);
                        if (k == -ENOENT)
                                continue;
                        if (k < 0 && r == 0)
                                r = k;
                }

                k = conf_files_list_nulstr(&files, ".conf", NULL, 0, conf_file_dirs);
                if (k < 0) {
                        log_error_errno(k, "Failed to enumerate modules-load.d files: %m");
                        if (r == 0)
                                r = k;
                        return r;
                }

                STRV_FOREACH(fn, files) {
                        k = apply_file(ctx, *fn, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
