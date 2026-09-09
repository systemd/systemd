/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "creds-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "options.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

static char **arg_prefixes = NULL;
static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static bool arg_strict = false;
static bool arg_verify = false;
static bool arg_inline = false;
static PagerFlags arg_pager_flags = 0;
static char *arg_save_file = NULL;
static char *arg_revert_file = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_prefixes, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_save_file, freep);
STATIC_DESTRUCTOR_REGISTER(arg_revert_file, freep);

COMMAND(
        "systemd-sysctl\0",
        "Apply kernel sysctl settings.",
        .argspec = "[CONFIGURATION FILE…]\0",
        .man_pages = "systemd-sysctl.service(8)\0",
        .pager_flags = &arg_pager_flags,
);

typedef struct SysctlOption {
        char *key;
        char *value;
        bool ignore_failure;
} SysctlOption;

static SysctlOption* sysctl_option_free(SysctlOption *o) {
        if (!o)
                return NULL;

        free(o->key);
        free(o->value);

        return mfree(o);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SysctlOption*, sysctl_option_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                sysctl_option_hash_ops,
                char, string_hash_func, string_compare_func,
                SysctlOption, sysctl_option_free);

static bool test_prefix(const char *p) {
        if (strv_isempty(arg_prefixes))
                return true;

        return path_startswith_strv(p, arg_prefixes);
}

static SysctlOption* sysctl_option_new(
                const char *key,
                const char *value,
                bool ignore_failure) {

        _cleanup_(sysctl_option_freep) SysctlOption *o = NULL;

        assert(key);

        o = new(SysctlOption, 1);
        if (!o)
                return NULL;

        *o = (SysctlOption) {
                .key = strdup(key),
                .value = value ? strdup(value) : NULL,
                .ignore_failure = ignore_failure,
        };

        if (!o->key)
                return NULL;
        if (value && !o->value)
                return NULL;

        return TAKE_PTR(o);
}

static int sysctl_write_or_warn(const char *key, const char *value, bool ignore_failure, bool ignore_enoent) {
        int r;

        if (arg_verify)
                r = sysctl_write_verify(key, value);
        else
                r = sysctl_write(key, value);
        if (r < 0) {
                /* Proceed without failing if ignore_failure is true.
                 * If the sysctl is not available in the kernel or we are running with reduced privileges and
                 * cannot write it, then log about the issue, and proceed without failing. Unless strict mode
                 * (arg_strict = true) is enabled, in which case we should fail. (EROFS is treated as a
                 * permission problem here, since that's how container managers usually protected their
                 * sysctls.)
                 * In all other cases log an error and make the tool fail. */
                if (ignore_failure || (!arg_strict && ERRNO_IS_NEG_FS_WRITE_REFUSED(r)))
                        log_debug_errno(r, "Couldn't write '%s' to '%s', ignoring: %m", value, key);
                else if (ignore_enoent && r == -ENOENT)
                        log_warning_errno(r, "Couldn't write '%s' to '%s', ignoring: %m", value, key);
                else
                        return log_error_errno(r, "Couldn't write '%s' to '%s': %m", value, key);
        }

        return 0;
}

static int apply_glob_option_with_prefix(OrderedHashmap *sysctl_options, SysctlOption *option, const char *prefix) {
        _cleanup_strv_free_ char **paths = NULL;
        _cleanup_free_ char *pattern = NULL;
        int r;

        assert(sysctl_options);
        assert(option);

        if (prefix) {
                _cleanup_free_ char *key = NULL;

                r = path_glob_can_match(option->key, prefix, &key);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if the glob '%s' matches prefix '%s': %m",
                                               option->key, prefix);
                if (r == 0) {
                        log_debug("The glob '%s' does not match prefix '%s'.", option->key, prefix);
                        return 0;
                }

                log_debug("The glob '%s' is prefixed with '%s': '%s'", option->key, prefix, key);

                if (!string_is_glob(key)) {
                        /* The prefixed pattern is not glob anymore. Let's skip to call glob(). */
                        if (ordered_hashmap_contains(sysctl_options, key)) {
                                log_debug("Not setting %s (explicit setting exists).", key);
                                return 0;
                        }

                        return sysctl_write_or_warn(key, option->value,
                                                    /* ignore_failure= */ option->ignore_failure,
                                                    /* ignore_enoent= */ true);
                }

                pattern = path_join("/proc/sys", key);
        } else
                pattern = path_join("/proc/sys", option->key);
        if (!pattern)
                return log_oom();

        r = glob_extend(&paths, pattern, GLOB_NOCHECK);
        if (r < 0) {
                if (r == -ENOENT) {
                        log_debug("No match for glob: %s", option->key);
                        return 0;
                }
                if (option->ignore_failure || ERRNO_IS_PRIVILEGE(r)) {
                        log_debug_errno(r, "Failed to resolve glob '%s', ignoring: %m", option->key);
                        return 0;
                }

                return log_error_errno(r, "Couldn't resolve glob '%s': %m", option->key);
        }

        STRV_FOREACH(s, paths) {
                const char *key = ASSERT_SE_PTR(path_startswith(*s, "/proc/sys"));

                if (ordered_hashmap_contains(sysctl_options, key)) {
                        log_debug("Not setting %s (explicit setting exists).", key);
                        continue;
                }

                RET_GATHER(r,
                           sysctl_write_or_warn(key, option->value,
                                                /* ignore_failure= */ option->ignore_failure,
                                                /* ignore_enoent= */ !arg_strict));
        }

        return r;
}

static int apply_glob_option(OrderedHashmap *sysctl_options, SysctlOption *option) {
        int r = 0;

        if (strv_isempty(arg_prefixes))
                return apply_glob_option_with_prefix(sysctl_options, option, NULL);

        STRV_FOREACH(i, arg_prefixes)
                RET_GATHER(r, apply_glob_option_with_prefix(sysctl_options, option, *i));
        return r;
}

static int apply_all(OrderedHashmap *sysctl_options) {
        SysctlOption *option;
        int r = 0;

        ORDERED_HASHMAP_FOREACH(option, sysctl_options) {
                int k;

                /* Ignore "negative match" options, they are there only to exclude stuff from globs. */
                if (!option->value)
                        continue;

                if (string_is_glob(option->key))
                        k = apply_glob_option(sysctl_options, option);
                else
                        k = sysctl_write_or_warn(option->key, option->value,
                                                 /* ignore_failure= */ option->ignore_failure,
                                                 /* ignore_enoent= */ !arg_strict);
                RET_GATHER(r, k);
        }

        return r;
}

static void filter_sysctl_options(OrderedHashmap *sysctl_options) {
        SysctlOption *option;
        ORDERED_HASHMAP_FOREACH(option, sysctl_options)
                if (!string_is_glob(option->key) && !test_prefix(option->key))
                        sysctl_option_free(ordered_hashmap_remove(sysctl_options, option->key));
}

static int parse_line(const char *fname, unsigned line, const char *buffer, bool *invalid_config, void *userdata) {
        OrderedHashmap **sysctl_options = ASSERT_PTR(userdata);
        _cleanup_free_ char *k = NULL, *v = NULL;
        bool ignore_failure = false;
        int r;

        const char *eq = strchr(buffer, '=');
        if (eq) {
                if (buffer[0] == '-') {
                        ignore_failure = true;
                        buffer++;
                }

                k = strndup(buffer, eq - buffer);
                if (!k)
                        return log_oom();

                v = strdup(eq + 1);
                if (!v)
                        return log_oom();

        } else {
                if (buffer[0] == '-')
                        /* We have a "negative match" option. Let's continue with value==NULL. */
                        buffer++;
                else
                        return log_syntax(NULL, LOG_WARNING, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Line is not an assignment, ignoring: %s", buffer);

                k = strdup(buffer);
                if (!k)
                        return log_oom();
        }

        const char *key = sysctl_normalize(strstrip(k)), *value = strstrip(v);

        if (arg_save_file) {
                /* When saving the loaded rules, refuse unsafe characters, especially newlines, in keys
                 * and values. Otherwise, the saved file may not be parsed correctly. */
                if (!string_is_safe(key, STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS) ||
                    (value && !string_is_safe(value, STRING_ALLOW_EMPTY | STRING_ALLOW_BACKSLASHES | STRING_ALLOW_QUOTES | STRING_ALLOW_GLOBS)))
                        return log_syntax(NULL, LOG_WARNING, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Ignoring unsafe key and/or value for '%s'.", key);
        } else {
                /* We can't filter out globs at this point, we'll need to do that later.
                 * Keep them when saving the loaded rules, and filter them after writing. */
                if (!string_is_glob(key) && !test_prefix(key))
                        return 0;
        }

        SysctlOption *existing = ordered_hashmap_get(*sysctl_options, key);
        if (existing) {
                if (streq_ptr(value, existing->value)) {
                        existing->ignore_failure = existing->ignore_failure || ignore_failure;
                        return 0;
                }

                log_syntax(NULL, LOG_DEBUG, fname, line, 0,
                           "Overwriting earlier assignment of '%s'.", key);
                sysctl_option_free(ordered_hashmap_remove(*sysctl_options, key));
        }

        _cleanup_(sysctl_option_freep) SysctlOption *option = sysctl_option_new(key, value, ignore_failure);
        if (!option)
                return log_oom();

        r = ordered_hashmap_ensure_put(sysctl_options, &sysctl_option_hash_ops, option->key, option);
        if (r < 0)
                return log_error_errno(r, "Failed to add sysctl variable '%s' to hashmap: %m", key);

        TAKE_PTR(option);
        return 0;
}

static int parse_file(OrderedHashmap **sysctl_options, const char *path, bool ignore_enoent) {
        return conf_file_read(
                        /* root= */ NULL,
                        (const char**) CONF_PATHS_STRV("sysctl.d"),
                        path,
                        parse_line,
                        sysctl_options,
                        ignore_enoent,
                        /* invalid_config= */ NULL);
}

static int read_credential_lines(OrderedHashmap **sysctl_options) {
        _cleanup_free_ char *j = NULL;
        const char *d;
        int r;

        r = get_credentials_dir(&d);
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get credentials directory: %m");

        j = path_join(d, "sysctl.extra");
        if (!j)
                return log_oom();

        return parse_file(sysctl_options, j, /* ignore_enoent= */ true);
}

static int cat_config(char **files) {
        pager_open(arg_pager_flags);

        return cat_files(NULL, files, arg_cat_flags);
}

static int save_sysctl_options(OrderedHashmap *sysctl_options, const char *filename) {
        int r;

        assert(filename);

        if (ordered_hashmap_isempty(sysctl_options)) {
                log_info("No sysctl settings loaded, not creating '%s'.", filename);
                return 0;
        }

        r = mkdir_p("/run/sysctl.d/", 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directory '/run/sysctl.d/': %m");

        _cleanup_free_ char *path = path_join("/run/sysctl.d/", filename);
        if (!path)
                return log_oom();

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        r = fopen_temporary(path, &f, &temp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to open a temporary file for '%s': %m", path);

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to chmod '%s': %m", temp_path);

        fputs("# This is generated by systemd-sysctl.\n", f);

        SysctlOption *option;
        ORDERED_HASHMAP_FOREACH(option, sysctl_options)
                fprintf(f, "%s%s%s%s\n",
                        option->ignore_failure || !option->value ? "-" : "",
                        option->key,
                        option->value ? " = " : "",
                        strempty(option->value));

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to flush '%s': %m", temp_path);

        r = conservative_rename(temp_path, path);
        if (r < 0)
                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", temp_path, path);

        temp_path = mfree(temp_path);
        return 0;
}

static int parse_conf_filename(const char *src, const char *option, char **dest) {
        assert(option);
        assert(dest);

        if (isempty(src))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use an empty filename for %s.", option);

        if (startswith(src, "."))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Dot-prefixed filenames are not allowed for %s.", option);

        _cleanup_free_ char *name = NULL;
        if (!endswith(src, ".conf"))
                name = strjoin(src, ".conf");
        else
                name = strdup(src);
        if (!name)
                return log_oom();

        if (!filename_is_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid file name '%s' specified for %s.", name, option);

        return free_and_replace(*dest, name);
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_GROUP("Commands"): {}

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

                OPTION_GROUP("Options"): {}

                OPTION_LONG("prefix", "PATH",
                            "Only apply rules with the specified prefix"): {
                        _cleanup_free_ char *normalized = strdup(opts.arg);
                        if (!normalized)
                                return log_oom();
                        sysctl_normalize(normalized);

                        /* We used to require people to specify absolute paths
                         * in /proc/sys in the past. This is kinda useless, but
                         * we need to keep compatibility. We now support any
                         * sysctl name available. */
                        const char *s = path_startswith(normalized, "/proc/sys");

                        if (strv_extend(&arg_prefixes, s ?: normalized) < 0)
                                return log_oom();

                        break;
                }

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_LONG("strict", NULL,
                            "Fail on any kind of failures"):
                        arg_strict = true;
                        break;

                OPTION_LONG("verify", NULL,
                            "Verify sysctl values after write"):
                        arg_verify = true;
                        break;

                OPTION_LONG("inline", NULL,
                            "Treat arguments as configuration lines"):
                        arg_inline = true;
                        break;

                OPTION_LONG("save", "FILENAME",
                            "Write loaded settings to the specified file"):
                        r = parse_conf_filename(opts.arg, "--save=", &arg_save_file);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("revert", "FILENAME",
                            "Remove the specified file from /run/sysctl.d/"):
                        r = parse_conf_filename(opts.arg, "--revert=", &arg_revert_file);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *remaining_args = option_parser_get_args(&opts);

        if (arg_cat_flags != CAT_CONFIG_OFF && !strv_isempty(*remaining_args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Positional arguments are not allowed with --cat-config/--tldr.");

        if (arg_inline && strv_isempty(*remaining_args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--inline requires positional arguments.");

        if (arg_save_file && strv_isempty(*remaining_args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--save= requires positional arguments.");

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        umask(0022);

        if (arg_revert_file) {
                _cleanup_free_ char *path = path_join("/run/sysctl.d/", arg_revert_file);
                if (!path)
                        return log_oom();

                if (unlink(path) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove '%s': %m", path);
        }

        _cleanup_ordered_hashmap_free_ OrderedHashmap *sysctl_options = NULL;
        if (!strv_isempty(args)) {
                unsigned pos = 0;

                STRV_FOREACH(arg, args) {
                        if (arg_inline) {
                                pos++;

                                const char *s = skip_leading_chars(*arg, /* bad= */ NULL);
                                if (IN_SET(*s, '\0', '#'))
                                        continue;

                                /* Use (argument):n, where n==1 for the first positional arg */
                                RET_GATHER(r, parse_line("(argument)", pos, s, /* invalid_config= */ NULL, &sysctl_options));
                        } else
                                RET_GATHER(r, parse_file(&sysctl_options, *arg, false));
                }

                if (arg_save_file) {
                        r = save_sysctl_options(sysctl_options, arg_save_file);
                        if (r < 0)
                                return r;

                        filter_sysctl_options(sysctl_options);
                }
        } else {
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".conf", /* root= */ NULL, CONF_FILES_WARN,
                                         (const char**) CONF_PATHS_STRV("sysctl.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate sysctl.d files: %m");

                if (arg_cat_flags != CAT_CONFIG_OFF)
                        return cat_config(files);

                STRV_FOREACH(f, files)
                        RET_GATHER(r, parse_file(&sysctl_options, *f, true));

                RET_GATHER(r, read_credential_lines(&sysctl_options));
        }

        return RET_GATHER(r, apply_all(sysctl_options));
}

DEFINE_MAIN_FUNCTION(run);
