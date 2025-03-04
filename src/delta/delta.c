/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "nulstr-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static const char prefixes[] =
        "/etc\0"
        "/run\0"
        "/usr/local/lib\0"
        "/usr/local/share\0"
        "/usr/lib\0"
        "/usr/share\0"
        ;

static const char suffixes[] =
        "sysctl.d\0"
        "tmpfiles.d\0"
        "modules-load.d\0"
        "binfmt.d\0"
        "systemd/system\0"
        "systemd/user\0"
        "systemd/system-preset\0"
        "systemd/user-preset\0"
        "udev/rules.d\0"
        "modprobe.d\0";

static const char have_dropins[] =
        "systemd/system\0"
        "systemd/user\0";

static PagerFlags arg_pager_flags = 0;
static int arg_diff = -1;

static enum {
        SHOW_MASKED     = 1 << 0,
        SHOW_EQUIVALENT = 1 << 1,
        SHOW_REDIRECTED = 1 << 2,
        SHOW_OVERRIDDEN = 1 << 3,
        SHOW_UNCHANGED  = 1 << 4,
        SHOW_EXTENDED   = 1 << 5,

        SHOW_DEFAULTS =
        (SHOW_MASKED | SHOW_EQUIVALENT | SHOW_REDIRECTED | SHOW_OVERRIDDEN | SHOW_EXTENDED)
} arg_flags = 0;

static int equivalent(const char *a, const char *b) {
        _cleanup_free_ char *x = NULL, *y = NULL;
        int r;

        r = chase(a, NULL, CHASE_TRAIL_SLASH, &x, NULL);
        if (r < 0)
                return r;

        r = chase(b, NULL, CHASE_TRAIL_SLASH, &y, NULL);
        if (r < 0)
                return r;

        return path_equal(x, y);
}

static int notify_override_masked(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_MASKED))
                return 0;

        printf("%s%s%s     %s %s %s\n",
               ansi_highlight_red(), "[MASKED]", ansi_normal(),
               top, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), bottom);
        return 1;
}

static int notify_override_equivalent(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EQUIVALENT))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight_green(), "[EQUIVALENT]", ansi_normal(),
               top, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), bottom);
        return 1;
}

static int notify_override_redirected(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_REDIRECTED))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight(), "[REDIRECTED]", ansi_normal(),
               top, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), bottom);
        return 1;
}

static int notify_override_overridden(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_OVERRIDDEN))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight(), "[OVERRIDDEN]", ansi_normal(),
               top, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), bottom);
        return 1;
}

static int notify_override_extended(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EXTENDED))
               return 0;

        printf("%s%s%s   %s %s %s\n",
               ansi_highlight(), "[EXTENDED]", ansi_normal(),
               top, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), bottom);
        return 1;
}

static int notify_override_unchanged(const char *f) {
        if (!(arg_flags & SHOW_UNCHANGED))
                return 0;

        printf("[UNCHANGED]  %s\n", f);
        return 1;
}

static int found_override(const char *top, const char *bottom) {
        _cleanup_free_ char *dest = NULL;
        pid_t pid;
        int r;

        assert(top);
        assert(bottom);

        if (null_or_empty_path(top) > 0)
                return notify_override_masked(top, bottom);

        r = readlink_malloc(top, &dest);
        if (r >= 0) {
                if (equivalent(dest, bottom) > 0)
                        return notify_override_equivalent(top, bottom);
                else
                        return notify_override_redirected(top, bottom);
        }

        r = notify_override_overridden(top, bottom);
        if (!arg_diff)
                return r;

        putchar('\n');

        fflush(stdout);

        r = safe_fork("(diff)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execlp("diff", "diff", "-us", "--", bottom, top, NULL);
                log_open();
                log_error_errno(errno, "Failed to execute diff: %m");
                _exit(EXIT_FAILURE);
        }

        (void) wait_for_terminate_and_check("diff", pid, WAIT_LOG_ABNORMAL);
        putchar('\n');

        return r;
}

DEFINE_PRIVATE_HASH_OPS_FULL(
                drop_hash_ops,
                char, string_hash_func, string_compare_func, free,
                OrderedHashmap, ordered_hashmap_free);

static int enumerate_dir_d(
                OrderedHashmap **top,
                OrderedHashmap **bottom,
                OrderedHashmap **drops,
                const char *toppath, const char *drop) {

        _cleanup_free_ char *unit = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_strv_free_ char **list = NULL;
        char *c;
        int r;

        assert(!endswith(drop, "/"));

        path = path_join(toppath, drop);
        if (!path)
                return -ENOMEM;

        log_debug("Looking at %s", path);

        unit = strdup(drop);
        if (!unit)
                return -ENOMEM;

        c = strrchr(unit, '.');
        if (!c)
                return -EINVAL;
        *c = 0;

        r = get_files_in_directory(path, &list);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate %s: %m", path);

        strv_sort(list);

        STRV_FOREACH(file, list) {
                OrderedHashmap *h;
                char *p;
                char *d;

                if (!endswith(*file, ".conf"))
                        continue;

                p = path_join(path, *file);
                if (!p)
                        return -ENOMEM;
                d = p + strlen(toppath) + 1;

                log_debug("Adding at top: %s %s %s", d, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), p);
                r = ordered_hashmap_ensure_put(top, &string_hash_ops_value_free, d, p);
                if (r >= 0) {
                        p = strdup(p);
                        if (!p)
                                return -ENOMEM;
                        d = p + strlen(toppath) + 1;
                } else if (r != -EEXIST) {
                        free(p);
                        return r;
                }

                log_debug("Adding at bottom: %s %s %s", d, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), p);
                free(ordered_hashmap_remove(*bottom, d));
                r = ordered_hashmap_ensure_put(bottom, &string_hash_ops_value_free, d, p);
                if (r < 0) {
                        free(p);
                        return r;
                }

                h = ordered_hashmap_get(*drops, unit);
                if (!h) {
                        h = ordered_hashmap_new(&string_hash_ops_value_free);
                        if (!h)
                                return -ENOMEM;
                        r = ordered_hashmap_ensure_put(drops, &drop_hash_ops, unit, h);
                        if (r < 0) {
                                ordered_hashmap_free(h);
                                return r;
                        }
                        unit = strdup(unit);
                        if (!unit)
                                return -ENOMEM;
                }

                p = strdup(p);
                if (!p)
                        return -ENOMEM;

                log_debug("Adding to drops: %s %s %s %s %s",
                          unit, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), basename(p), special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), p);
                r = ordered_hashmap_put(h, basename(p), p);
                if (r < 0) {
                        free(p);
                        if (r != -EEXIST)
                                return r;
                }
        }
        return 0;
}

static int enumerate_dir(
                OrderedHashmap **top,
                OrderedHashmap **bottom,
                OrderedHashmap **drops,
                const char *path, bool dropins) {

        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_strv_free_ char **files = NULL, **dirs = NULL;
        size_t n_files = 0, n_dirs = 0;
        int r;

        assert(top);
        assert(bottom);
        assert(drops);
        assert(path);

        log_debug("Looking at %s", path);

        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                if (dropins && de->d_type == DT_DIR && endswith(de->d_name, ".d")) {
                        if (!GREEDY_REALLOC0(dirs, n_dirs + 2))
                                return -ENOMEM;

                        dirs[n_dirs] = strdup(de->d_name);
                        if (!dirs[n_dirs])
                                return -ENOMEM;
                        n_dirs++;
                }

                if (!dirent_is_file(de))
                        continue;

                if (!GREEDY_REALLOC0(files, n_files + 2))
                        return -ENOMEM;

                files[n_files] = strdup(de->d_name);
                if (!files[n_files])
                        return -ENOMEM;
                n_files++;
        }

        strv_sort(dirs);
        strv_sort(files);

        STRV_FOREACH(t, dirs) {
                r = enumerate_dir_d(top, bottom, drops, path, *t);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(t, files) {
                _cleanup_free_ char *p = NULL;

                p = path_join(path, *t);
                if (!p)
                        return -ENOMEM;

                log_debug("Adding at top: %s %s %s", basename(p), special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), p);
                r = ordered_hashmap_ensure_put(top, &string_hash_ops_value_free, basename(p), p);
                if (r >= 0) {
                        p = strdup(p);
                        if (!p)
                                return -ENOMEM;
                } else if (r != -EEXIST)
                        return r;

                log_debug("Adding at bottom: %s %s %s", basename(p), special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), p);
                free(ordered_hashmap_remove(*bottom, basename(p)));
                r = ordered_hashmap_ensure_put(bottom, &string_hash_ops_value_free, basename(p), p);
                if (r < 0)
                        return r;
                p = NULL;
        }

        return 0;
}

static int process_suffix(const char *suffix, const char *onlyprefix) {
        int r, ret = 0;

        assert(suffix);
        assert(!startswith(suffix, "/"));
        assert(!strstr(suffix, "//"));

        bool dropins = nulstr_contains(have_dropins, suffix);

        _cleanup_ordered_hashmap_free_ OrderedHashmap *top = NULL, *bottom = NULL, *drops = NULL;
        NULSTR_FOREACH(p, prefixes) {
                _cleanup_free_ char *t = NULL;

                t = path_join(p, suffix);
                if (!t)
                        return -ENOMEM;

                RET_GATHER(ret, enumerate_dir(&top, &bottom, &drops, t, dropins));
        }

        int n_found = 0;
        char *f, *key;
        ORDERED_HASHMAP_FOREACH_KEY(f, key, top) {
                char *o;

                o = ordered_hashmap_get(bottom, key);
                assert(o);

                if (!onlyprefix || startswith(o, onlyprefix)) {
                        if (path_equal(o, f)) {
                                notify_override_unchanged(f);
                        } else {
                                r = found_override(f, o);
                                if (r < 0)
                                        RET_GATHER(ret, r);
                                else
                                        n_found += r;
                        }
                }

                OrderedHashmap *h = ordered_hashmap_get(drops, key);
                if (h)
                        ORDERED_HASHMAP_FOREACH(o, h)
                                if (!onlyprefix || startswith(o, onlyprefix))
                                        n_found += notify_override_extended(f, o);
        }

        return ret < 0 ? ret : n_found;
}

static int process_suffixes(const char *onlyprefix) {
        int n_found = 0, r;

        NULSTR_FOREACH(n, suffixes) {
                r = process_suffix(n, onlyprefix);
                if (r < 0)
                        return r;

                n_found += r;
        }

        return n_found;
}

static int process_suffix_chop(const char *arg) {
        assert(arg);

        if (!path_is_absolute(arg))
                return process_suffix(arg, NULL);

        /* Strip prefix from the suffix */
        NULSTR_FOREACH(p, prefixes) {
                const char *suffix;

                suffix = startswith(arg, p);
                if (suffix) {
                        suffix += strspn(suffix, "/");
                        if (*suffix)
                                return process_suffix(suffix, p);
                        else
                                return process_suffixes(arg);
                }
        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Invalid suffix specification %s.", arg);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-delta", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [SUFFIX...]\n\n"
               "Find overridden configuration files.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "     --diff[=1|0]     Show a diff when overridden files differ\n"
               "  -t --type=LIST...   Only display a selected set of override types\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_flags(const char *flag_str, int flags) {
        for (;;) {
                _cleanup_free_ char *word = NULL;
                int r;

                r = extract_first_word(&flag_str, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        return flags;

                if (streq(word, "masked"))
                        flags |= SHOW_MASKED;
                else if (streq(word, "equivalent"))
                        flags |= SHOW_EQUIVALENT;
                else if (streq(word, "redirected"))
                        flags |= SHOW_REDIRECTED;
                else if (streq(word, "overridden"))
                        flags |= SHOW_OVERRIDDEN;
                else if (streq(word, "unchanged"))
                        flags |= SHOW_UNCHANGED;
                else if (streq(word, "extended"))
                        flags |= SHOW_EXTENDED;
                else if (streq(word, "default"))
                        flags |= SHOW_DEFAULTS;
                else
                        return -EINVAL;
        }
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_NO_PAGER = 0x100,
                ARG_DIFF,
                ARG_VERSION
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'          },
                { "version",   no_argument,       NULL, ARG_VERSION  },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER },
                { "diff",      optional_argument, NULL, ARG_DIFF     },
                { "type",      required_argument, NULL, 't'          },
                {}
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 't': {
                        int f;
                        f = parse_flags(optarg, arg_flags);
                        if (f < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse flags field.");
                        arg_flags = f;
                        break;
                }

                case ARG_DIFF:
                        r = parse_boolean_argument("--diff", optarg, NULL);
                        if (r < 0)
                                return r;
                        arg_diff = r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r, k, n_found = 0;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_flags == 0)
                arg_flags = SHOW_DEFAULTS;

        if (arg_diff < 0)
                arg_diff = !!(arg_flags & SHOW_OVERRIDDEN);
        else if (arg_diff)
                arg_flags |= SHOW_OVERRIDDEN;

        pager_open(arg_pager_flags);

        if (optind < argc) {
                for (int i = optind; i < argc; i++) {
                        path_simplify(argv[i]);

                        k = process_suffix_chop(argv[i]);
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }

        } else {
                k = process_suffixes(NULL);
                if (k < 0)
                        r = k;
                else
                        n_found += k;
        }

        if (r >= 0)
                printf("%s%i overridden configuration files found.\n", n_found ? "\n" : "", n_found);
        return r;
}

DEFINE_MAIN_FUNCTION(run);
