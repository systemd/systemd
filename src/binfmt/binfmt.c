/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
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
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"

static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_unregister = false;

COMMAND(
        "systemd-binfmt\0",
        "Register binary formats with the kernel.",
        .argspec = "[CONFIGURATION FILE|BPF OBJECT…]\0",
        .man_pages = "systemd-binfmt.service(8)\0",
        .pager_flags = &arg_pager_flags,
);

static int delete_rule(const char *rulename) {
        const char *fn = strjoina("/proc/sys/fs/binfmt_misc/", rulename);
        return write_string_file(fn, "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
}

/* A BPF object "<name>.bpf.o" in one of these directories is registered as the binfmt_misc handler <name>,
 * together with a rule <name> that hands binaries to it. */
#define BPF_OBJECT_DIRS ((const char* const*) CONF_PATHS_STRV("systemd/binfmt"))
#define BPF_OBJECT_SUFFIX ".bpf.o"

static bool rule_name_is_valid(const char *name) {
        return filename_is_valid(name) && !STR_IN_SET(name, "register", "status");
}

/* The kernel takes at most 15 characters for the name of a handler, each alphanumeric, '_' or '.'. See
 * bpf_obj_name_cpy() in the kernel's kernel/bpf/syscall.c. */
#define HANDLER_NAME_MAX 15U
#define HANDLER_NAME_CHARS ALPHANUMERICAL "_."

static bool handler_name_is_valid(const char *name) {
        return rule_name_is_valid(name) &&
                strlen(name) <= HANDLER_NAME_MAX &&
                in_charset(name, HANDLER_NAME_CHARS);
}

static int bpf_object_rule(const char *path, char **ret_name, char **ret_rule) {
        _cleanup_free_ char *name = NULL;
        char *rule;
        int r;

        assert(path);
        assert(ret_name);
        assert(ret_rule);

        /* The rule and the handler are both named after the file. */
        r = path_extract_filename(path, &name);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name from '%s': %m", path);

        *ASSERT_PTR(endswith(name, BPF_OBJECT_SUFFIX)) = 0;
        if (!handler_name_is_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Name '%s' of BPF object '%s' is not a valid handler name, refusing. "
                                       "It must have at most %u characters, each alphanumeric, '_' or '.'.",
                                       name, path, HANDLER_NAME_MAX);

        rule = strjoin(":", name, ":B::::", name, ":");
        if (!rule)
                return log_oom();

        *ret_name = TAKE_PTR(name);
        *ret_rule = rule;
        return 0;
}

#if HAVE_LIBBPF
/* The struct_ops type a binfmt_misc handler is an instance of, and its member holding the handler's name. See
 * https://docs.kernel.org/admin-guide/binfmt-misc.html#bpf-backed-handlers */
#define BINFMT_MISC_OPS_TYPE "binfmt_misc_ops"
#define BINFMT_MISC_OPS_NAME_MEMBER "name"

/* The kernel emits this type into its BTF when it registers binfmt_misc_ops as a struct_ops, which it does
 * only when built with CONFIG_BINFMT_MISC_BPF. */
#define BINFMT_MISC_OPS_VALUE_TYPE "bpf_struct_ops_" BINFMT_MISC_OPS_TYPE

static int find_handler_map(struct bpf_object *obj, const char *path, struct bpf_map **ret) {
        struct bpf_map *found = NULL;

        assert(obj);
        assert(path);
        assert(ret);

        /* The handler is the one struct_ops map of the object. */
        for (struct bpf_map *map = sym_bpf_object__next_map(obj, /* map= */ NULL); map;
             map = sym_bpf_object__next_map(obj, map)) {

                if (sym_bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
                        continue;

                if (found)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "BPF object '%s' contains more than one struct_ops map, refusing.",
                                               path);
                found = map;
        }
        if (!found)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "BPF object '%s' contains no struct_ops map, refusing.", path);

        *ret = found;
        return 0;
}

static int check_handler_map(struct bpf_object *obj, struct bpf_map *map, const char *path, const char *handler) {
        const struct btf_member *member;
        const struct btf_type *type;
        const char *data, *name;
        struct btf *btf;
        size_t size, offset;

        assert(obj);
        assert(map);
        assert(path);
        assert(handler);

        /* Only a binfmt_misc_ops map is a handler. Any other struct_ops, a scheduler say, is refused rather
         * than registered. */
        btf = sym_bpf_object__btf(obj);
        if (!btf)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "BPF object '%s' carries no BTF, refusing.", path);

        type = sym_btf__type_by_id(btf, sym_bpf_map__btf_value_type_id(map));
        if (!type || !streq_ptr(sym_btf__name_by_offset(btf, type->name_off), BINFMT_MISC_OPS_TYPE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "struct_ops map '%s' in BPF object '%s' is not a " BINFMT_MISC_OPS_TYPE ", refusing.",
                                       sym_bpf_map__name(map), path);

        /* The kernel registers the handler under the name in the map, but the rule references it by the
         * file name. Check that both agree, so that a mismatch is reported here rather than as a missing
         * handler when the rule is written. */
        member = btf_members(type);
        for (unsigned i = 0; i < btf_vlen(type); i++, member++) {
                if (!streq_ptr(sym_btf__name_by_offset(btf, member->name_off), BINFMT_MISC_OPS_NAME_MEMBER))
                        continue;

                data = sym_bpf_map__initial_value(map, &size);
                offset = btf_member_bit_offset(type, i) / 8;
                if (!data || offset >= size)
                        break;

                name = data + offset;
                if (strnlen(name, size - offset) >= size - offset)
                        break;

                if (!streq(name, handler))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Handler name '%s' in BPF object '%s' does not match the file name, refusing.",
                                               name, path);
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Failed to read the handler name from BPF object '%s', refusing.", path);
}
#endif

static int apply_bpf_object(const char *path) {
#if HAVE_LIBBPF
        /* The object is declared first so that it is closed last. Without a BPF link libbpf registers the
         * handler by updating the map, and freeing the link unregisters it through the map's file
         * descriptor, which closing the object closes. */
        _cleanup_(sym_bpf_object__closep) struct bpf_object *obj = NULL;
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        _cleanup_free_ char *handler = NULL, *rule = NULL;
        struct bpf_map *map;
        int r;

        assert(path);

        r = bpf_object_rule(path, &handler, &rule);
        if (r < 0)
                return r;

        LIBBPF_NOTE(suggested);
        r = dlopen_bpf(LOG_ERR);
        if (r < 0)
                return r;

        if (!sym_bpf_object__next_map || !sym_bpf_object__btf || !sym_bpf_map__btf_value_type_id ||
            !sym_bpf_map__initial_value || !sym_btf__type_by_id || !sym_btf__name_by_offset)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libbpf is too old to load BPF object '%s'.", path);

        obj = sym_bpf_object__open_file(path, /* opts= */ NULL);
        r = bpf_get_error_translated(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to open BPF object '%s': %m", path);

        /* Check the object before loading it, so that nothing of an object that is refused reaches the
         * kernel. */
        r = find_handler_map(obj, path, &map);
        if (r < 0)
                return r;

        r = check_handler_map(obj, map, path, handler);
        if (r < 0)
                return r;

        r = sym_bpf_object__load(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to load BPF object '%s': %m", path);

        /* Registers the handler under its name. If a handler of that name is registered already, by another
         * service or by hand, the rule is written for that one. */
        link = sym_bpf_map__attach_struct_ops(map);
        r = bpf_get_error_translated(link);
        if (r == -EEXIST)
                log_notice("Handler '%s' is registered already, writing rule for it instead of the one in '%s'.",
                           handler, path);
        else if (r < 0)
                return log_error_errno(r, "Failed to register handler from BPF object '%s': %m", path);
        else
                log_debug("Handler '%s' registered from '%s'.", handler, path);

        /* Replace a rule of the same name. Only needed when the object was named on the command line, a full
         * run flushes all rules first. */
        r = delete_rule(handler);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to delete rule '%s', ignoring: %m", handler);
        if (r >= 0)
                log_debug("Rule '%s' deleted.", handler);

        /* The rule takes its own reference on the handler. The link, and with it the registration of the
         * handler's name, is dropped again once the rule is written, so that nothing but the rule is left
         * behind and the handler can be registered again on the next run. */
        r = write_string_file("/proc/sys/fs/binfmt_misc/register", rule, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to add binary format '%s' for BPF object '%s': %m", handler, path);

        log_debug("Binary format '%s' registered for BPF object '%s'.", handler, path);
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Found BPF object '%s', but libbpf support is not compiled in.", path);
#endif
}

static bool bpf_handlers_supported(void) {
#if HAVE_LIBBPF
        _cleanup_(sym_btf__freep) struct btf *btf = NULL;
        int r;

        /* Objects shipped by packages are skipped rather than failing the service on systems that cannot
         * register them. */
        r = dlopen_bpf(LOG_DEBUG);
        if (r < 0) {
                log_notice_errno(r, "libbpf is not available, skipping BPF objects: %m");
                return false;
        }

        if (!sym_btf__load_vmlinux_btf || !sym_btf__find_by_name_kind || !sym_btf__free) {
                log_notice("libbpf is too old to probe the kernel for bpf-backed binfmt_misc handlers, skipping BPF objects.");
                return false;
        }

        /* libbpf < 1.0 returns error pointers, not NULL; btf__free() copes with both */
        btf = sym_btf__load_vmlinux_btf();
        r = bpf_get_error_translated(btf);
        if (r != 0) {
                log_notice_errno(r, "Failed to load kernel BTF, skipping BPF objects: %m");
                return false;
        }

        if (sym_btf__find_by_name_kind(btf, BINFMT_MISC_OPS_VALUE_TYPE, BTF_KIND_STRUCT) <= 0) {
                log_notice("Kernel does not support bpf-backed binfmt_misc handlers, skipping BPF objects.");
                return false;
        }

        return true;
#else
        log_notice("libbpf support is not compiled in, skipping BPF objects.");
        return false;
#endif
}

static int apply_bpf_object_arg(const char *name) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(name);

        /* Like a configuration file, an object named on the command line is looked up in the search path
         * unless it is given as a path, and the first match wins, so a mask in /etc/ applies to it too. */
        r = search_and_access(name, F_OK, /* root= */ NULL, (char**) BPF_OBJECT_DIRS, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to find BPF object '%s': %m", name);

        r = null_or_empty_path(path);
        if (r < 0)
                return log_error_errno(r, "Failed to check if BPF object '%s' is masked: %m", path);
        if (r > 0) {
                log_debug("BPF object '%s' is masked, skipping.", path);
                return 0;
        }

        return apply_bpf_object(path);
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

        if (!rule_name_is_valid(parsed.name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s:%u: Rule name '%s' is not valid, refusing.",
                                       filename, line, parsed.name);
        r = delete_rule(parsed.name);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "%s:%u: Failed to delete rule '%s', ignoring: %m",
                                  filename, line, parsed.name);
        if (r >= 0)
                log_debug("%s:%u: Rule '%s' deleted.", filename, line, parsed.name);

        r = write_string_file("/proc/sys/fs/binfmt_misc/register", rule, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "%s:%u: Failed to add binary format '%s': %m",
                                       filename, line, parsed.name);

        log_debug("%s:%u: Binary format '%s' registered.", filename, line, parsed.name);
        return 0;
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

static int cat_config(char **files, char **objects) {
        int r;

        pager_open(arg_pager_flags);

        r = cat_files(/* file= */ NULL, files, arg_cat_flags);

        /* A BPF object is not shown itself, but as the rule it registers, under the object's path. */
        STRV_FOREACH(o, objects) {
                _cleanup_free_ char *name = NULL, *rule = NULL;

                if (o != objects || !strv_isempty(files))
                        putc('\n', stdout);

                printf("%s# %s%s\n", ansi_highlight_blue(), *o, ansi_normal());

                RET_GATHER(r, bpf_object_rule(*o, &name, &rule));
                if (rule)
                        puts(rule);
        }

        return r;
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
                        if (endswith(*f, BPF_OBJECT_SUFFIX))
                                RET_GATHER(r, apply_bpf_object_arg(*f));
                        else
                                RET_GATHER(r, apply_file(*f, /* ignore_enoent= */ false));

        } else {
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".conf", /* root= */ NULL, CONF_FILES_WARN, (const char**) CONF_PATHS_STRV("binfmt.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate binfmt.d files: %m");

                /* A /dev/null symlink or an empty file masks an object of the same name. */
                _cleanup_strv_free_ char **objects = NULL;
                r = conf_files_list_strv(&objects, BPF_OBJECT_SUFFIX, /* root= */ NULL,
                                         CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
                                         (const char**) BPF_OBJECT_DIRS);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate BPF objects: %m");

                if (arg_cat_flags != CAT_CONFIG_OFF)
                        return cat_config(files, objects);

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

                /* The kernel tries the rule registered last first. BPF objects are registered before the
                 * rules from binfmt.d, so that those rules are matched first. */
                if (!strv_isempty(objects) && bpf_handlers_supported())
                        STRV_FOREACH(o, objects)
                                RET_GATHER(r, apply_bpf_object(*o));

                STRV_FOREACH(f, files)
                        RET_GATHER(r, apply_file(*f, /* ignore_enoent= */ true));
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
