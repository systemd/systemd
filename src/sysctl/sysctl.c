/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "conf-files.h"
#include "creds-util.h"
#include "def.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
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
static bool arg_cat_config = false;
static bool arg_strict = false;
static PagerFlags arg_pager_flags = 0;

STATIC_DESTRUCTOR_REGISTER(arg_prefixes, strv_freep);

typedef struct Option {
        char *key;
        char *value;
        bool ignore_failure;
} Option;

static Option *option_free(Option *o) {
        if (!o)
                return NULL;

        free(o->key);
        free(o->value);

        return mfree(o);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Option*, option_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(option_hash_ops, char, string_hash_func, string_compare_func, Option, option_free);

static bool test_prefix(const char *p) {
        if (strv_isempty(arg_prefixes))
                return true;

        return path_startswith_strv(p, arg_prefixes);
}

static Option *option_new(
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
                if (ignore_failure || (!arg_strict && (r == -EROFS || ERRNO_IS_PRIVILEGE(r))))
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
        int r, k;

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
                                                    /* ignore_failure = */ option->ignore_failure,
                                                    /* ignore_enoent = */ true);
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
                } else
                        return log_error_errno(r, "Couldn't resolve glob '%s': %m", option->key);
        }

        STRV_FOREACH(s, paths) {
                const char *key;

                assert_se(key = path_startswith(*s, "/proc/sys"));

                if (ordered_hashmap_contains(sysctl_options, key)) {
                        log_debug("Not setting %s (explicit setting exists).", key);
                        continue;
                }

                k = sysctl_write_or_warn(key, option->value,
                                         /* ignore_failure = */ option->ignore_failure,
                                         /* ignore_enoent = */ !arg_strict);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int apply_glob_option(OrderedHashmap *sysctl_options, Option *option) {
        int r = 0, k;

        if (strv_isempty(arg_prefixes))
                return apply_glob_option_with_prefix(sysctl_options, option, NULL);

        STRV_FOREACH(i, arg_prefixes) {
                k = apply_glob_option_with_prefix(sysctl_options, option, *i);
                if (k < 0 && r >= 0)
                        r = k;
        }

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
                                                 /* ignore_failure = */ option->ignore_failure,
                                                 /* ignore_enoent = */ !arg_strict);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

static int parse_file(OrderedHashmap **sysctl_options, const char *path, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        unsigned c = 0;
        int r;

        assert(path);

        r = search_and_fopen(path, "re", NULL, (const char**) CONF_PATHS_STRV("sysctl.d"), &f, &pp);
        if (r < 0) {
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open file '%s', ignoring: %m", path);
        }

        log_debug("Parsing %s", pp);
        for (;;) {
                _cleanup_(option_freep) Option *new_option = NULL;
                _cleanup_free_ char *l = NULL;
                bool ignore_failure = false;
                Option *existing;
                char *p, *value;
                int k;

                k = read_line(f, LONG_LINE_MAX, &l);
                if (k == 0)
                        break;
                if (k < 0)
                        return log_error_errno(k, "Failed to read file '%s', ignoring: %m", pp);

                c++;

                p = strstrip(l);

                if (isempty(p))
                        continue;
                if (strchr(COMMENTS "\n", *p))
                        continue;

                value = strchr(p, '=');
                if (value) {
                        if (p[0] == '-') {
                                ignore_failure = true;
                                p++;
                        }

                        *value = 0;
                        value++;
                        value = strstrip(value);

                } else {
                        if (p[0] == '-')
                                /* We have a "negative match" option. Let's continue with value==NULL. */
                                p++;
                        else {
                                log_syntax(NULL, LOG_WARNING, pp, c, 0,
                                           "Line is not an assignment, ignoring: %s", p);
                                if (r == 0)
                                        r = -EINVAL;
                                continue;
                        }
                }

                p = strstrip(p);
                p = sysctl_normalize(p);

                /* We can't filter out globs at this point, we'll need to do that later. */
                if (!string_is_glob(p) &&
                    !test_prefix(p))
                        continue;

                existing = ordered_hashmap_get(*sysctl_options, p);
                if (existing) {
                        if (streq_ptr(value, existing->value)) {
                                existing->ignore_failure = existing->ignore_failure || ignore_failure;
                                continue;
                        }

                        log_debug("Overwriting earlier assignment of %s at '%s:%u'.", p, pp, c);
                        option_free(ordered_hashmap_remove(*sysctl_options, p));
                }

                new_option = option_new(p, value, ignore_failure);
                if (!new_option)
                        return log_oom();

                k = ordered_hashmap_ensure_put(sysctl_options, &option_hash_ops, new_option->key, new_option);
                if (k < 0)
                        return log_error_errno(k, "Failed to add sysctl variable %s to hashmap: %m", p);

                TAKE_PTR(new_option);
        }

        return r;
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

        (void) parse_file(sysctl_options, j, /* ignore_enoent= */ true);
        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysctl.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Applies kernel sysctl settings.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --cat-config       Show configuration files\n"
               "     --prefix=PATH      Only apply rules with the specified prefix\n"
               "     --no-pager         Do not pipe output into a pager\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_PREFIX,
                ARG_NO_PAGER,
                ARG_STRICT,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "cat-config", no_argument,       NULL, ARG_CAT_CONFIG },
                { "prefix",     required_argument, NULL, ARG_PREFIX     },
                { "no-pager",   no_argument,       NULL, ARG_NO_PAGER   },
                { "strict",     no_argument,       NULL, ARG_STRICT     },
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
                        arg_cat_config = true;
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_cat_config && argc > optind)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Positional arguments are not allowed with --cat-config");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(ordered_hashmap_freep) OrderedHashmap *sysctl_options = NULL;
        int r, k;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        if (argc > optind) {
                int i;

                r = 0;

                for (i = optind; i < argc; i++) {
                        k = parse_file(&sysctl_options, argv[i], false);
                        if (k < 0 && r == 0)
                                r = k;
                }
        } else {
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".conf", NULL, 0, (const char**) CONF_PATHS_STRV("sysctl.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate sysctl.d files: %m");

                if (arg_cat_config) {
                        pager_open(arg_pager_flags);

                        return cat_files(NULL, files, 0);
                }

                STRV_FOREACH(f, files) {
                        k = parse_file(&sysctl_options, *f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }

                k = read_credential_lines(&sysctl_options);
                if (k < 0 && r == 0)
                        r = k;
        }

        k = apply_all(sysctl_options);
        if (k < 0 && r == 0)
                r = k;

        return r;
}

DEFINE_MAIN_FUNCTION(run);
