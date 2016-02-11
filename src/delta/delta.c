/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "log.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "util.h"

static const char prefixes[] =
#ifdef HAVE_SPLIT_USR
        "/lib\0"
#endif
        "/usr/share\0"
        "/usr/lib\0"
        "/usr/local/share\0"
        "/usr/local/lib\0"
        "/run\0"
        "/etc\0"
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

static bool arg_no_pager = false;
static int arg_diff = -1;

static enum {
        SHOW_MASKED = 1 << 0,
        SHOW_EQUIVALENT = 1 << 1,
        SHOW_REDIRECTED = 1 << 2,
        SHOW_OVERRIDDEN = 1 << 3,
        SHOW_UNCHANGED = 1 << 4,
        SHOW_EXTENDED = 1 << 5,

        SHOW_DEFAULTS =
        (SHOW_MASKED | SHOW_EQUIVALENT | SHOW_REDIRECTED | SHOW_OVERRIDDEN | SHOW_EXTENDED)
} arg_flags = 0;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static int equivalent(const char *a, const char *b) {
        _cleanup_free_ char *x = NULL, *y = NULL;

        x = canonicalize_file_name(a);
        if (!x)
                return -errno;

        y = canonicalize_file_name(b);
        if (!y)
                return -errno;

        return path_equal(x, y);
}

static int notify_override_masked(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_MASKED))
                return 0;

        printf("%s%s%s     %s %s %s\n",
               ansi_highlight_red(), "[MASKED]", ansi_normal(),
               top, draw_special_char(DRAW_ARROW), bottom);
        return 1;
}

static int notify_override_equivalent(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EQUIVALENT))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight_green(), "[EQUIVALENT]", ansi_normal(),
               top, draw_special_char(DRAW_ARROW), bottom);
        return 1;
}

static int notify_override_redirected(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_REDIRECTED))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight(), "[REDIRECTED]", ansi_normal(),
               top, draw_special_char(DRAW_ARROW), bottom);
        return 1;
}

static int notify_override_overridden(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_OVERRIDDEN))
                return 0;

        printf("%s%s%s %s %s %s\n",
               ansi_highlight(), "[OVERRIDDEN]", ansi_normal(),
               top, draw_special_char(DRAW_ARROW), bottom);
        return 1;
}

static int notify_override_extended(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EXTENDED))
               return 0;

        printf("%s%s%s   %s %s %s\n",
               ansi_highlight(), "[EXTENDED]", ansi_normal(),
               top, draw_special_char(DRAW_ARROW), bottom);
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
        int k;
        pid_t pid;

        assert(top);
        assert(bottom);

        if (null_or_empty_path(top) > 0)
                return notify_override_masked(top, bottom);

        k = readlink_malloc(top, &dest);
        if (k >= 0) {
                if (equivalent(dest, bottom) > 0)
                        return notify_override_equivalent(top, bottom);
                else
                        return notify_override_redirected(top, bottom);
        }

        k = notify_override_overridden(top, bottom);
        if (!arg_diff)
                return k;

        putchar('\n');

        fflush(stdout);

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork off diff: %m");
        else if (pid == 0) {

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                execlp("diff", "diff", "-us", "--", bottom, top, NULL);
                log_error_errno(errno, "Failed to execute diff: %m");
                _exit(EXIT_FAILURE);
        }

        wait_for_terminate_and_warn("diff", pid, false);
        putchar('\n');

        return k;
}

static int enumerate_dir_d(Hashmap *bottom, const char *dropdir) {
        _cleanup_free_ char *unit = NULL, *path = NULL;
        _cleanup_strv_free_ char **list = NULL;
        char **file, *c;
        int r;

        assert(dropdir);

        log_debug("Looking at %s", dropdir);

        path = strdup(dropdir);
        if (!path)
                return -ENOMEM;

        c = strrchr(path, '.');
        if (!c)
                return -EINVAL;
        *c = 0;

        r = get_files_in_directory(dropdir, &list);
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate %s: %m", dropdir);


        STRV_FOREACH(file, list) {
                int k;
                Hashmap *drops;
                char **d;
                _cleanup_free_ char *tmp = NULL, *key = NULL, *pathkey = NULL;
                bool dup_pathkey = true;

                if (!endswith(*file, ".conf"))
                        continue;

                pathkey = strdup(path);
                if (!pathkey)
                        return -ENOMEM;

                k = unit_name_template(basename(path), &tmp);
                if (k < 0 && k != -EINVAL)
                        return k;
                key = tmp ? strdup(tmp) : strdup(basename(path));
                if (!key)
                        return -ENOMEM;

                drops = hashmap_get(bottom, key);
                if (!drops) {
                        _cleanup_free_ char *p = NULL;

                        drops = hashmap_new(&string_hash_ops);
                        if (!drops)
                                return -ENOMEM;

                        p = strjoin(dropdir, "/", *file, NULL);
                        if (!p)
                                return -ENOMEM;

                        log_debug("Adding: drops[%s] %s []",
                                  p, draw_special_char(DRAW_ARROW));

                        k = hashmap_put(drops, pathkey, NULL);
                        if (k < 0)
                                return k;
                } else
                        dup_pathkey = false;

                d = hashmap_get(drops, path);
                k = strv_extend(&d, *file);
                if (k < 0)
                        return k;

                log_debug("Extending: %s %s drops[%s]", *file, draw_special_char(DRAW_ARROW), path);

                {
                        _cleanup_free_ void *oldkey = NULL;

                        (void) hashmap_get2(drops, pathkey, &oldkey);

                        if (dup_pathkey) {
                                pathkey = strdup(pathkey);
                                if (!pathkey)
                                        return -ENOMEM;
                        }

                        hashmap_replace(drops, pathkey, d);
                        pathkey = NULL;
                }

                {
                        _cleanup_free_ void *oldkey = NULL;

                        (void) hashmap_get2(bottom, key, &oldkey);
                        hashmap_replace(bottom, key, drops);
                }

                key = NULL;
        }

        return 0;
}

static int enumerate_dir(Hashmap *top, Hashmap *bottom, const char *path, bool dropins) {
        _cleanup_closedir_ DIR *d;

        assert(bottom);
        assert(path);

        log_debug("Looking at %s", path);

        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        for (;;) {
                struct dirent *de;
                _cleanup_free_ char *p = NULL, *tmp = NULL, *key = NULL;
                int k;
                Hashmap *drops;

                errno = 0;
                de = readdir(d);
                if (!de)
                        return -errno;

                dirent_ensure_type(d, de);

                p = strjoin(path, "/", de->d_name, NULL);
                if (!p)
                        return -ENOMEM;

                if (dropins && de->d_type == DT_DIR && endswith(de->d_name, ".d"))
                        enumerate_dir_d(bottom, p);

                if (!dirent_is_file(de))
                        continue;

                k = unit_name_template(basename(p), &tmp);
                if (k < 0 && k != -EINVAL)
                        return k;

                key = tmp ? strdup(tmp) : strdup(basename(p));
                if (!key)
                        return -ENOMEM;

                log_debug("Adding: top[%s] %s %s", key, draw_special_char(DRAW_ARROW), p);
                k = hashmap_put(top, key, p);

                if (k < 0) {
                        if (k == -EEXIST) {
                                bool keep_key = true;

                                drops = hashmap_get(bottom, key);
                                if (!drops) {
                                        drops = hashmap_new(&string_hash_ops);
                                        if (!drops)
                                                return -ENOMEM;
                                } else
                                        keep_key = false;

                                log_debug("Adding: bottom[%s] %s drops[%s] %s []",
                                          key, draw_special_char(DRAW_ARROW),
                                          p, draw_special_char(DRAW_ARROW));

                                k = hashmap_put(drops, p, NULL);
                                if (k < 0)
                                        return k;
                                p = NULL;

                                k = hashmap_put(bottom, key, drops);
                                if (k < 0)
                                        return k;
                                if (keep_key)
                                        key = NULL;

                        } else
                                return k;

                } else {
                        p = NULL;
                        key = NULL;
                }
        }
}

static int process_suffix(const char *suffix, const char *onlyprefix) {
        const char *p;
        char *file;
        Hashmap *bottom, *top, *drops;
        char *key, *path, **drop;
        int r = 0, k;
        Iterator i, j;
        int n_found = 0;
        bool dropins;
        _cleanup_strv_free_ char **extended = NULL;

        assert(suffix);
        assert(!startswith(suffix, "/"));
        assert(!strstr(suffix, "//"));

        dropins = nulstr_contains(have_dropins, suffix);

        top = hashmap_new(&string_hash_ops);
        if (!top) {
                r = -ENOMEM;
                goto finish;
        }

        bottom = hashmap_new(&string_hash_ops);
        if (!bottom) {
                r = -ENOMEM;
                goto finish;
        }

        NULSTR_FOREACH(p, prefixes) {
                _cleanup_free_ char *t = NULL;

                t = strjoin(p, "/", suffix, NULL);
                if (!t) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = enumerate_dir(top, bottom, t, dropins);
                if (r == 0)
                        r = k;
        }

        HASHMAP_FOREACH_KEY(file, key, top, i) {
                drops = hashmap_get(bottom, key);
                if (!drops)
                        continue;

                HASHMAP_FOREACH_KEY(drop, path, drops, j) {
                        char **dd;

                        if (!access(path, F_OK) && (!onlyprefix || startswith(file, onlyprefix))) {
                                if (path_equal(file, path)) {
                                        notify_override_unchanged(path);
                                } else {
                                        k = found_override(path, file);
                                        if (k < 0)
                                                r = k;
                                        else
                                                n_found += k;
                                }
                        }

                        STRV_FOREACH(dd, drop)
                                if (!onlyprefix || startswith(file, onlyprefix) || startswith(path, onlyprefix)) {
                                        _cleanup_free_ char *ext = NULL;

                                        ext = strjoin(path, ".d/", *dd, NULL);
                                        if (!ext) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        n_found += notify_override_extended(path, ext);
                                }
                }
        }

finish:
        if (top)
                hashmap_free_free_free(top);

        if (bottom) {
                while ((key = hashmap_first_key(bottom))) {
                        char **kk, **val;

                        drops = hashmap_steal_first(bottom);

                        while ((kk = hashmap_first_key(drops))) {
                                val = hashmap_steal_first(drops);
                                strv_free(val);
                                free(kk);
                        }
                        hashmap_free(drops);

                        free(key);
                }
                hashmap_free(bottom);
        }
        return r < 0 ? r : n_found;
}

static int process_suffixes(const char *onlyprefix) {
        const char *n;
        int n_found = 0, r;

        NULSTR_FOREACH(n, suffixes) {
                r = process_suffix(n, onlyprefix);
                if (r < 0)
                        return r;
                else
                        n_found += r;
        }
        return n_found;
}

static int process_suffix_chop(const char *arg) {
        const char *p;

        assert(arg);

        if (!path_is_absolute(arg))
                return process_suffix(arg, NULL);

        /* Strip prefix from the suffix */
        NULSTR_FOREACH(p, prefixes) {
                const char *suffix = startswith(arg, p);
                if (suffix) {
                        suffix += strspn(suffix, "/");
                        if (*suffix)
                                return process_suffix(suffix, NULL);
                        else
                                return process_suffixes(arg);
                }
        }

        log_error("Invalid suffix specification %s.", arg);
        return -EINVAL;
}

static void help(void) {
        printf("%s [OPTIONS...] [SUFFIX...]\n\n"
               "Find overridden configuration files.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "     --diff[=1|0]     Show a diff when overridden files differ\n"
               "  -t --type=LIST...   Only display a selected set of override types\n"
               , program_invocation_short_name);
}

static int parse_flags(const char *flag_str, int flags) {
        const char *word, *state;
        size_t l;

        FOREACH_WORD_SEPARATOR(word, l, flag_str, ",", state) {
                if (strneq("masked", word, l))
                        flags |= SHOW_MASKED;
                else if (strneq ("equivalent", word, l))
                        flags |= SHOW_EQUIVALENT;
                else if (strneq("redirected", word, l))
                        flags |= SHOW_REDIRECTED;
                else if (strneq("overridden", word, l))
                        flags |= SHOW_OVERRIDDEN;
                else if (strneq("unchanged", word, l))
                        flags |= SHOW_UNCHANGED;
                else if (strneq("extended", word, l))
                        flags |= SHOW_EXTENDED;
                else if (strneq("default", word, l))
                        flags |= SHOW_DEFAULTS;
                else
                        return -EINVAL;
        }
        return flags;
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

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 't': {
                        int f;
                        f = parse_flags(optarg, arg_flags);
                        if (f < 0) {
                                log_error("Failed to parse flags field.");
                                return -EINVAL;
                        }
                        arg_flags = f;
                        break;
                }

                case ARG_DIFF:
                        if (!optarg)
                                arg_diff = 1;
                        else {
                                int b;

                                b = parse_boolean(optarg);
                                if (b < 0) {
                                        log_error("Failed to parse diff boolean.");
                                        return -EINVAL;
                                } else if (b)
                                        arg_diff = 1;
                                else
                                        arg_diff = 0;
                        }
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {
        int r = 0, k;
        int n_found = 0;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_flags == 0)
                arg_flags = SHOW_DEFAULTS;

        if (arg_diff < 0)
                arg_diff = !!(arg_flags & SHOW_OVERRIDDEN);
        else if (arg_diff)
                arg_flags |= SHOW_OVERRIDDEN;

        pager_open_if_enabled();

        if (optind < argc) {
                int i;

                for (i = optind; i < argc; i++) {
                        path_kill_slashes(argv[i]);
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
                printf("%s%i overridden configurations found.\n",
                       n_found ? "\n" : "", n_found);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
