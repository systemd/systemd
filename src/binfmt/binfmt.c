/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "binfmt-util.h"
#include "bpf-link.h"
#include "bpf-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"

static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_unregister = false;

COMMAND(
        "systemd-binfmt\0",
        "Register binary formats with the kernel.",
        .argspec = "[CONFIGURATION FILE…]\0",
        .man_pages = "systemd-binfmt.service(8)\0",
        .pager_flags = &arg_pager_flags,
);

static int delete_rule(const char *rulename) {
        const char *fn = strjoina("/proc/sys/fs/binfmt_misc/", rulename);
        return write_string_file(fn, "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
}

static int register_rule(const char *filename, unsigned line, const char *rulename, const char *rule) {
        int r;

        assert(filename);
        assert(line > 0);
        assert(rulename);
        assert(rule);

        r = write_string_file("/proc/sys/fs/binfmt_misc/register", rule, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to add binary format '%s': %m",
                                       filename, line, rulename);

        log_debug("%s:%u: Binary format '%s' registered.", filename, line, rulename);
        return 0;
}

#if HAVE_LIBBPF
static int attach_bpf_handler(const char *filename, unsigned line, const char *path, struct bpf_link **ret_link) {
        _cleanup_(sym_bpf_object__closep) struct bpf_object *obj = NULL;
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        struct bpf_map *ops = NULL;
        int r;

        assert(filename);
        assert(line > 0);
        assert(path);
        assert(ret_link);

        r = dlopen_bpf(LOG_ERR);
        if (r < 0)
                return r;

        if (!sym_bpf_object__next_map)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "%s:%u: libbpf is too old to load BPF object '%s'.",
                                       filename, line, path);

        obj = sym_bpf_object__open_file(path, /* opts= */ NULL);
        r = bpf_get_error_translated(obj);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to open BPF object '%s': %m", filename, line, path);

        r = sym_bpf_object__load(obj);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to load BPF object '%s': %m", filename, line, path);

        /* The handler is the binfmt_misc_ops struct_ops map of the object. */
        for (struct bpf_map *map = sym_bpf_object__next_map(obj, /* map= */ NULL); map;
             map = sym_bpf_object__next_map(obj, map)) {

                if (sym_bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
                        continue;

                if (ops)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s:%u: BPF object '%s' contains more than one struct_ops map, refusing.",
                                               filename, line, path);
                ops = map;
        }
        if (!ops)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: BPF object '%s' contains no struct_ops map, refusing.",
                                       filename, line, path);

        /* Registers the handler under the name set in the struct_ops map. The link keeps it registered,
         * the object itself can be closed once it is attached. */
        link = sym_bpf_map__attach_struct_ops(ops);
        r = bpf_get_error_translated(link);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to register BPF handler from '%s': %m",
                                       filename, line, path);

        log_debug("%s:%u: BPF handler from '%s' registered.", filename, line, path);
        *ret_link = TAKE_PTR(link);
        return 0;
}
#endif

static int apply_bpf_rule(const char *filename, unsigned line, const BinfmtRule *parsed, const char *rule) {
#if HAVE_LIBBPF
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
#endif
        _cleanup_free_ char *fn = NULL, *path = NULL;
        const char *handler;
        int r;

        assert(filename);
        assert(line > 0);
        assert(parsed);
        assert(parsed->type == BINFMT_RULE_BPF);
        assert(rule);

        /* The handler a bpf-backed rule names has to be registered before the rule can be. If one of the
         * binfmt.d directories carries a "<handler>.bpf.o" object, register the handler from it. Otherwise
         * assume something else registered it already. See
         * https://docs.kernel.org/admin-guide/binfmt-misc.html#bpf-backed-handlers */
        handler = parsed->bpf_handler;
        if (!filename_is_valid(handler))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: BPF handler name '%s' of rule '%s' is not valid, refusing.",
                                       filename, line, handler, parsed->name);

        fn = strjoin(handler, ".bpf.o");
        if (!fn)
                return log_oom();

        r = search_and_access(fn, F_OK, /* root= */ NULL, CONF_PATHS_STRV("binfmt.d"), &path);
        if (r == -ENOENT) {
                log_debug("%s:%u: No BPF object '%s' found, assuming handler '%s' is registered already.",
                          filename, line, fn, handler);
                return register_rule(filename, line, parsed->name, rule);
        }
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to look for BPF object '%s': %m", filename, line, fn);

#if HAVE_LIBBPF
        r = attach_bpf_handler(filename, line, path, &link);
        if (r < 0)
                return r;

        /* The rule takes its own reference on the handler. The link, and with it the registration of the
         * handler's name, is dropped again once the rule is written, so that nothing but the rule is left
         * behind and the handler can be registered again on the next run. */
        return register_rule(filename, line, parsed->name, rule);
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "%s:%u: Found BPF object '%s' for handler '%s', but libbpf support is not compiled in.",
                               filename, line, path, handler);
#endif
}

static int apply_rule(const char *filename, unsigned line, const char *rule) {
        assert(filename);
        assert(line > 0);
        assert(rule);
        assert(rule[0]);

        _cleanup_(binfmt_rule_done) BinfmtRule parsed = {};
        int r;

        r = binfmt_rule_parse(rule, &parsed);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to parse rule: %m", filename, line);

        if (!filename_is_valid(parsed.name) ||
            STR_IN_SET(parsed.name, "register", "status"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: Rule name '%s' is not valid, refusing.",
                                       filename, line, parsed.name);
        r = delete_rule(parsed.name);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "%s:%u: Failed to delete rule '%s', ignoring: %m",
                                  filename, line, parsed.name);
        if (r >= 0)
                log_debug("%s:%u: Rule '%s' deleted.", filename, line, parsed.name);

        if (parsed.type == BINFMT_RULE_BPF)
                return apply_bpf_rule(filename, line, &parsed, rule);

        return register_rule(filename, line, parsed.name, rule);
}

static int apply_file(const char *filename, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(filename);

        r = search_and_fopen(filename, "re", /* root= */ NULL, (const char**) CONF_PATHS_STRV("binfmt.d"), &f, &pp);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open file '%s': %m", filename);
        }

        log_debug("Applying %s%s", pp, glyph(GLYPH_ELLIPSIS));
        for (unsigned line = 1;; line++) {
                _cleanup_free_ char *text = NULL;
                int k;

                k = read_stripped_line(f, LONG_LINE_MAX, &text);
                if (k < 0)
                        return log_error_errno(k, "Failed to read file '%s': %m", pp);
                if (k == 0)
                        break;

                if (isempty(text))
                        continue;
                if (strchr(COMMENTS, text[0]))
                        continue;

                RET_GATHER(r, apply_rule(filename, line, text));
        }

        return r;
}

static int cat_config(char **files) {
        pager_open(arg_pager_flags);

        return cat_files(/* file= */ NULL, files, arg_cat_flags);
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_CAT_CONFIG:
                        arg_cat_flags = CAT_CONFIG_ON;
                        break;

                OPTION_COMMON_TLDR:
                        arg_cat_flags = CAT_TLDR;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_LONG("unregister", NULL, "Unregister all existing entries"):
                        arg_unregister = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        char **args = option_parser_get_args(&opts);

        if ((arg_unregister || arg_cat_flags != CAT_CONFIG_OFF) && !strv_isempty(args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Positional arguments are not allowed with --cat-config/--tldr or --unregister.");

        *ret_args = args;
        return 1;
}

static int binfmt_mounted_and_writable_warn(void) {
        int r;

        r = binfmt_mounted_and_writable();
        if (r < 0)
                return log_error_errno(r, "Failed to check if /proc/sys/fs/binfmt_misc is mounted: %m");
        if (r == 0)
                log_debug("/proc/sys/fs/binfmt_misc is not mounted in read-write mode, skipping.");

        return r;
}

static int run(int argc, char *argv[]) {
        int r;

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        r = 0;

        if (arg_unregister)
                return disable_binfmt();

        if (!strv_isempty(args)) {
                r = binfmt_mounted_and_writable_warn();
                if (r <= 0)
                        return r;

                STRV_FOREACH(f, args)
                        RET_GATHER(r, apply_file(*f, /* ignore_enoent= */ false));

        } else {
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".conf", /* root= */ NULL, CONF_FILES_WARN, (const char**) CONF_PATHS_STRV("binfmt.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate binfmt.d files: %m");

                if (arg_cat_flags != CAT_CONFIG_OFF)
                        return cat_config(files);

                r = binfmt_mounted_and_writable_warn();
                if (r <= 0)
                        return r;

                /* Flush out all rules */
                r = write_string_file("/proc/sys/fs/binfmt_misc/status", "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        log_warning_errno(r, "Failed to flush binfmt_misc rules, ignoring: %m");
                else
                        log_debug("Flushed all binfmt_misc rules.");

                r = 0;

                STRV_FOREACH(f, files)
                        RET_GATHER(r, apply_file(*f, /* ignore_enoent= */ true));
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
