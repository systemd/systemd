/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "creds-util.h"
#include "errno-util.h"
#include "format-table.h"
#include "glob-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "varlink-io.systemd.Sysctl.h"
#include "varlink-util.h"

static char **arg_prefixes = NULL;
static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static bool arg_strict = false;
static bool arg_inline = false;
static bool arg_varlink = false;
static PagerFlags arg_pager_flags = 0;

STATIC_DESTRUCTOR_REGISTER(arg_prefixes, strv_freep);

typedef struct SysctlOption {
        char *key;
        char *value;
        bool ignore_failure;
        bool verify;
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

static int sysctl_write_or_warn(const SysctlOption *option, bool ignore_enoent) {
        int r;

        assert(option);

        if (option->verify)
                r = sysctl_write_verify(option->key, option->value);
        else
                r = sysctl_write(option->key, option->value);
        if (r < 0) {
                /* Proceed without failing if ignore_failure is true.
                 * If the sysctl is not available in the kernel or we are running with reduced privileges and
                 * cannot write it, then log about the issue, and proceed without failing. Unless strict mode
                 * is enabled (ignore_enoent == false), in which case we should fail. (EROFS is treated as a
                 * permission problem here, since that's how container managers usually protected their
                 * sysctls.)
                 * In all other cases log an error and make the tool fail. */
                if (option->ignore_failure || (ignore_enoent && ERRNO_IS_NEG_FS_WRITE_REFUSED(r)))
                        log_debug_errno(r, "Couldn't write '%s' to '%s', ignoring: %m", option->value, option->key);
                else if (ignore_enoent && r == -ENOENT)
                        log_warning_errno(r, "Couldn't write '%s' to '%s', ignoring: %m", option->value, option->key);
                else
                        return log_error_errno(r, "Couldn't write '%s' to '%s': %m", option->value, option->key);
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

                        return sysctl_write_or_warn(
                                        &(const SysctlOption) {
                                                .key = key,
                                                .value = option->value,
                                                .ignore_failure = option->ignore_failure,
                                                .verify = option->verify,
                                        },
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
                           sysctl_write_or_warn(
                                        &(const SysctlOption) {
                                                .key = (char*) key,
                                                .value = option->value,
                                                .ignore_failure = option->ignore_failure,
                                                .verify = option->verify,
                                        },
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
                        k = sysctl_write_or_warn(option, /* ignore_enoent= */ !arg_strict);
                RET_GATHER(r, k);
        }

        return r;
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

        /* We can't filter out globs at this point, we'll need to do that later. */
        if (!string_is_glob(key) && !test_prefix(key))
                return 0;

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

static int dispatch_setting(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        OrderedHashmap **sysctl_options = ASSERT_PTR(userdata);
        int r;

        _cleanup_(sysctl_option_freep) SysctlOption *option = new0(SysctlOption, 1);
        if (!option)
                return log_oom();

        static const sd_json_dispatch_field dispatch_table[] = {
                { "key",           SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(SysctlOption, key),            SD_JSON_MANDATORY },
                { "value",         SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(SysctlOption, value),          0                 },
                { "ignoreFailure", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(SysctlOption, ignore_failure), 0                 },
                { "verify",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(SysctlOption, verify),         0                 },
                {},
        };

        r = sd_json_dispatch(variant, dispatch_table, flags, &option);
        if (r < 0)
                return r;

        sysctl_normalize(option->key);

        SysctlOption *existing = ordered_hashmap_get(*sysctl_options, option->key);
        if (existing) {
                if (streq_ptr(option->value, existing->value)) {
                        existing->ignore_failure = existing->ignore_failure || option->ignore_failure;
                        return 0;
                }

                log_debug("Overwriting earlier assignment of '%s'.", option->key);
                sysctl_option_free(ordered_hashmap_remove(*sysctl_options, option->key));
        }

        r = ordered_hashmap_ensure_put(sysctl_options, &sysctl_option_hash_ops, option->key, option);
        if (r < 0)
                return log_error_errno(r, "Failed to add sysctl variable '%s' to hashmap: %m", option->key);

        TAKE_PTR(option);
        return 0;
}

static int dispatch_settings(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                r = dispatch_setting(name, v, flags, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_apply(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "settings", SD_JSON_VARIANT_ARRAY, dispatch_settings, 0, SD_JSON_MANDATORY},
                {}
        };

        _cleanup_ordered_hashmap_free_ OrderedHashmap *sysctl_options = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sysctl_options);
        if (r != 0)
                return r;

        return apply_all(sysctl_options);
}

static int vl_server(void) {
        int r;

        /* Invocation as Varlink service */

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY |
                        SD_VARLINK_SERVER_MYSELF_ONLY,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        varlink_server,
                        &vl_interface_io_systemd_Sysctl);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Sysctl.Apply", vl_method_apply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int cat_config(char **files) {
        pager_open(arg_pager_flags);

        return cat_files(NULL, files, arg_cat_flags);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *commands = NULL, *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysctl.service", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&commands);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("Options", &options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, commands, options);

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n"
               "\n%sApplies kernel sysctl settings.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(commands);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n", ansi_underline(), ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

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

                OPTION_LONG("inline", NULL,
                            "Treat arguments as configuration lines"):
                        arg_inline = true;
                        break;
                }

        *remaining_args = option_parser_get_args(&opts);

        if (arg_cat_flags != CAT_CONFIG_OFF && !strv_isempty(*remaining_args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Positional arguments are not allowed with --cat-config/--tldr.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                if (arg_cat_flags != CAT_CONFIG_OFF)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--cat-config/--tldr cannot be used on Varlink mode.");
                if (!strv_isempty(arg_prefixes))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--prefix= cannot be used on Varlink mode.");
                if (arg_inline)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--inline cannot be used on Varlink mode.");
                if (!strv_isempty(*remaining_args))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Positional arguments are not allowed on Varlink mode.");

                arg_varlink = true;
        }

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

        if (arg_varlink)
                return vl_server();

        _cleanup_ordered_hashmap_free_ OrderedHashmap *sysctl_options = NULL;
        if (!strv_isempty(args)) {
                unsigned pos = 0;

                STRV_FOREACH(arg, args) {
                        if (arg_inline)
                                /* Use (argument):n, where n==1 for the first positional arg */
                                RET_GATHER(r, parse_line("(argument)", ++pos, *arg, /* invalid_config= */ NULL, &sysctl_options));
                        else
                                RET_GATHER(r, parse_file(&sysctl_options, *arg, false));
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
