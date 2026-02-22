/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "creds-util.h"
#include "errno-util.h"
#include "glob-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"

static char **arg_prefixes = NULL;
static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static bool arg_strict = false;
static bool arg_inline = false;
static PagerFlags arg_pager_flags = 0;

STATIC_DESTRUCTOR_REGISTER(arg_prefixes, strv_freep);

typedef struct Option {
        char *key;
        char *value;
        bool ignore_failure;
} Option;

static Option* option_free(Option *o) {
        if (!o)
                return NULL;

        free(o->key);
        free(o->value);

        return mfree(o);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Option*, option_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                option_hash_ops,
                char, string_hash_func, string_compare_func,
                Option, option_free);

static bool test_prefix(const char *p) {
        if (strv_isempty(arg_prefixes))
                return true;

        return path_startswith_strv(p, arg_prefixes);
}

static Option* option_new(
                const char *key,
                const char *value,
                bool ignore_failure) {

        _cleanup_(option_freep) Option *o = NULL;

        assert(key);

        o = new(Option, 1);
        if (!o)
                return NULL;

        *o = (Option) {
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

static int apply_glob_option_with_prefix(OrderedHashmap *sysctl_options, Option *option, const char *prefix) {
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

static int apply_glob_option(OrderedHashmap *sysctl_options, Option *option) {
        int r = 0;

        if (strv_isempty(arg_prefixes))
                return apply_glob_option_with_prefix(sysctl_options, option, NULL);

        STRV_FOREACH(i, arg_prefixes)
                RET_GATHER(r, apply_glob_option_with_prefix(sysctl_options, option, *i));
        return r;
}

static int apply_all(OrderedHashmap *sysctl_options) {
        Option *option;
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

        Option *existing = ordered_hashmap_get(*sysctl_options, key);
        if (existing) {
                if (streq_ptr(value, existing->value)) {
                        existing->ignore_failure = existing->ignore_failure || ignore_failure;
                        return 0;
                }

                log_syntax(NULL, LOG_DEBUG, fname, line, 0,
                           "Overwriting earlier assignment of '%s'.", key);
                option_free(ordered_hashmap_remove(*sysctl_options, key));
        }

        _cleanup_(option_freep) Option *option = option_new(key, value, ignore_failure);
        if (!option)
                return log_oom();

        r = ordered_hashmap_ensure_put(sysctl_options, &option_hash_ops, option->key, option);
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

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysctl.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [CONFIGURATION FILE...]\n"
               "\n%2$sApplies kernel sysctl settings.%4$s\n"
               "\n%3$sCommands:%4$s\n"
               "     --cat-config       Show configuration files\n"
               "     --tldr             Show non-comment parts of configuration\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --prefix=PATH      Only apply rules with the specified prefix\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "     --strict           Fail on any kind of failures\n"
               "     --inline           Treat arguments as configuration lines\n"
               "\nSee the %5$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_TLDR,
                ARG_PREFIX,
                ARG_NO_PAGER,
                ARG_STRICT,
                ARG_INLINE,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "cat-config", no_argument,       NULL, ARG_CAT_CONFIG },
                { "tldr",       no_argument,       NULL, ARG_TLDR       },
                { "prefix",     required_argument, NULL, ARG_PREFIX     },
                { "no-pager",   no_argument,       NULL, ARG_NO_PAGER   },
                { "strict",     no_argument,       NULL, ARG_STRICT     },
                { "inline",     no_argument,       NULL, ARG_INLINE     },
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

                case ARG_CAT_CONFIG:
                        arg_cat_flags = CAT_CONFIG_ON;
                        break;

                case ARG_TLDR:
                        arg_cat_flags = CAT_TLDR;
                        break;

                case ARG_PREFIX: {
                        const char *s;
                        char *p;

                        /* We used to require people to specify absolute paths
                         * in /proc/sys in the past. This is kinda useless, but
                         * we need to keep compatibility. We now support any
                         * sysctl name available. */
                        sysctl_normalize(optarg);

                        s = path_startswith(optarg, "/proc/sys");
                        p = strdup(s ?: optarg);
                        if (!p)
                                return log_oom();

                        if (strv_consume(&arg_prefixes, p) < 0)
                                return log_oom();

                        break;
                }

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_STRICT:
                        arg_strict = true;
                        break;

                case ARG_INLINE:
                        arg_inline = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_cat_flags != CAT_CONFIG_OFF && argc > optind)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Positional arguments are not allowed with --cat-config/--tldr.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *sysctl_options = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        if (argc > optind) {
                unsigned pos = 0;

                STRV_FOREACH(arg, strv_skip(argv, optind)) {
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
