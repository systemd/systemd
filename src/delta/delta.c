/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "hashmap.h"
#include "util.h"
#include "path-util.h"
#include "log.h"
#include "pager.h"
#include "build.h"
#include "strv.h"

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

        printf("%s%s%s     %s → %s\n",
               ansi_highlight_red(), "[MASKED]", ansi_highlight_off(), top, bottom);
        return 1;
}

static int notify_override_equivalent(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EQUIVALENT))
                return 0;

        printf("%s%s%s %s → %s\n",
               ansi_highlight_green(), "[EQUIVALENT]", ansi_highlight(), top, bottom);
        return 1;
}

static int notify_override_redirected(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_REDIRECTED))
                return 0;

        printf("%s%s%s   %s → %s\n",
               ansi_highlight(), "[REDIRECTED]", ansi_highlight_off(), top, bottom);
        return 1;
}

static int notify_override_overridden(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_OVERRIDDEN))
                return 0;

        printf("%s%s%s %s → %s\n",
               ansi_highlight(), "[OVERRIDDEN]", ansi_highlight_off(), top, bottom);
        return 1;
}

static int notify_override_extended(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EXTENDED))
               return 0;

        printf("%s%s%s   %s → %s\n",
               ansi_highlight(), "[EXTENDED]", ansi_highlight_off(), top, bottom);
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
        if (pid < 0) {
                log_error("Failed to fork off diff: %m");
                return -errno;
        } else if (pid == 0) {
                execlp("diff", "diff", "-us", "--", bottom, top, NULL);
                log_error("Failed to execute diff: %m");
                _exit(1);
        }

        wait_for_terminate(pid, NULL);

        putchar('\n');

        return k;
}

static int enumerate_dir_d(Hashmap *top, Hashmap *bottom, Hashmap *drops, const char *toppath, const char *drop) {
        _cleanup_free_ char *conf = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_strv_free_ char **list = NULL;
        char **file;
        char *c;
        int r;

        path = strjoin(toppath, "/", drop, NULL);
        if (!path)
                return -ENOMEM;

        path_kill_slashes(path);

        conf = strdup(drop);
        if (!conf)
                return -ENOMEM;

        c = strrchr(conf, '.');
        if (!c)
                return -EINVAL;
        *c = 0;

        r = get_files_in_directory(path, &list);
        if (r < 0){
                log_error("Failed to enumerate %s: %s", path, strerror(-r));
                return r;
        }

        STRV_FOREACH(file, list) {
                Hashmap *h;
                int k;
                char *p;
                char *d;

                if (!endswith(*file, ".conf"))
                        continue;

                p = strjoin(path, "/", *file, NULL);
                if (!p)
                        return -ENOMEM;

                path_kill_slashes(p);

                d = strrchr(p, '/');
                if (!d || d == p) {
                        free(p);
                        return -EINVAL;
                }
                d--;
                d = strrchr(p, '/');

                if (!d || d == p) {
                        free(p);
                        return -EINVAL;
                }

                k = hashmap_put(top, d, p);
                if (k >= 0) {
                        p = strdup(p);
                        if (!p)
                                return -ENOMEM;
                        d = strrchr(p, '/');
                        d--;
                        d = strrchr(p, '/');
                } else if (k != -EEXIST) {
                        free(p);
                        return k;
                }

                free(hashmap_remove(bottom, d));
                k = hashmap_put(bottom, d, p);
                if (k < 0) {
                        free(p);
                        return k;
                }

                h = hashmap_get(drops, conf);
                if (!h) {
                        h = hashmap_new(string_hash_func, string_compare_func);
                        if (!h)
                                return -ENOMEM;
                        hashmap_put(drops, conf, h);
                        conf = strdup(conf);
                        if (!conf)
                                return -ENOMEM;
                }

                p = strdup(p);
                if (!p)
                        return -ENOMEM;

                k = hashmap_put(h, path_get_file_name(p), p);
                if (k < 0) {
                        free(p);
                        if (k != -EEXIST)
                                return k;
                }
        }
        return 0;
}

static int enumerate_dir(Hashmap *top, Hashmap *bottom, Hashmap *drops, const char *path, bool dropins) {
        _cleanup_closedir_ DIR *d;

        assert(top);
        assert(bottom);
        assert(drops);
        assert(path);

        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                log_error("Failed to enumerate %s: %m", path);
                return -errno;
        }

        for (;;) {
                struct dirent *de;
                union dirent_storage buf;
                int k;
                char *p;

                k = readdir_r(d, &buf.de, &de);
                if (k != 0)
                        return -k;

                if (!de)
                        break;

                if (dropins && de->d_type == DT_DIR && endswith(de->d_name, ".d"))
                        enumerate_dir_d(top, bottom, drops, path, de->d_name);

                if (!dirent_is_file(de))
                        continue;

                p = strjoin(path, "/", de->d_name, NULL);
                if (!p)
                        return -ENOMEM;

                path_kill_slashes(p);

                k = hashmap_put(top, path_get_file_name(p), p);
                if (k >= 0) {
                        p = strdup(p);
                        if (!p)
                                return -ENOMEM;
                } else if (k != -EEXIST) {
                        free(p);
                        return k;
                }

                free(hashmap_remove(bottom, path_get_file_name(p)));
                k = hashmap_put(bottom, path_get_file_name(p), p);
                if (k < 0) {
                        free(p);
                        return k;
                }
        }

        return 0;
}

static int process_suffix(const char *prefixes, const char *suffix, bool dropins) {
        const char *p;
        char *f;
        Hashmap *top, *bottom=NULL, *drops=NULL;
        Hashmap *h;
        char *key;
        int r = 0, k;
        Iterator i, j;
        int n_found = 0;

        assert(prefixes);
        assert(suffix);

        top = hashmap_new(string_hash_func, string_compare_func);
        if (!top) {
                r = -ENOMEM;
                goto finish;
        }

        bottom = hashmap_new(string_hash_func, string_compare_func);
        if (!bottom) {
                r = -ENOMEM;
                goto finish;
        }

        drops = hashmap_new(string_hash_func, string_compare_func);
        if (!drops) {
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

                k = enumerate_dir(top, bottom, drops, t, dropins);
                if (k < 0)
                        r = k;

                log_debug("Looking at %s", t);
        }

        HASHMAP_FOREACH_KEY(f, key, top, i) {
                char *o;

                o = hashmap_get(bottom, key);
                assert(o);

                if (path_equal(o, f))
                        notify_override_unchanged(f);
                else {
                        k = found_override(f, o);
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }

                h = hashmap_get(drops, key);
                if (h)
                        HASHMAP_FOREACH(o, h, j)
                                n_found += notify_override_extended(f, o);
        }

finish:
        if (top)
                hashmap_free_free(top);
        if (bottom)
                hashmap_free_free(bottom);
        if (drops) {
                HASHMAP_FOREACH_KEY(h, key, drops, i){
                        hashmap_free_free(hashmap_remove(drops, key));
                        hashmap_remove(drops, key);
                        free(key);
                }
                hashmap_free(drops);
        }
        return r < 0 ? r : n_found;
}

static int process_suffix_chop(const char *prefixes, const char *suffix, const char *have_dropins) {
        const char *p;

        assert(prefixes);
        assert(suffix);

        if (!path_is_absolute(suffix))
                return process_suffix(prefixes, suffix, nulstr_contains(have_dropins, suffix));

        /* Strip prefix from the suffix */
        NULSTR_FOREACH(p, prefixes) {
                if (startswith(suffix, p)) {
                        suffix += strlen(p);
                        suffix += strspn(suffix, "/");
                        return process_suffix(prefixes, suffix, nulstr_contains(have_dropins, suffix));
                }
        }

        log_error("Invalid suffix specification %s.", suffix);
        return -EINVAL;
}

static void help(void) {

        printf("%s [OPTIONS...] [SUFFIX...]\n\n"
               "Find overridden configuration files.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "     --diff[=1|0]     Show a diff when overridden files differ\n"
               "  -t --type=LIST...   Only display a selected set of override types\n",
               program_invocation_short_name);
}

static int parse_flags(const char *flag_str, int flags) {
        char *w, *state;
        size_t l;

        FOREACH_WORD(w, l, flag_str, state) {
                if (strneq("masked", w, l))
                        flags |= SHOW_MASKED;
                else if (strneq ("equivalent", w, l))
                        flags |= SHOW_EQUIVALENT;
                else if (strneq("redirected", w, l))
                        flags |= SHOW_REDIRECTED;
                else if (strneq("overridden", w, l))
                        flags |= SHOW_OVERRIDDEN;
                else if (strneq("unchanged", w, l))
                        flags |= SHOW_UNCHANGED;
                else if (strneq("extended", w, l))
                        flags |= SHOW_EXTENDED;
                else if (strneq("default", w, l))
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
                { NULL,        0,                 NULL, 0            }
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case '?':
                        return -EINVAL;

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

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {

        const char prefixes[] =
                "/etc\0"
                "/run\0"
                "/usr/local/lib\0"
                "/usr/local/share\0"
                "/usr/lib\0"
                "/usr/share\0"
#ifdef HAVE_SPLIT_USR
                "/lib\0"
#endif
                ;

        const char suffixes[] =
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

        const char have_dropins[] =
                "systemd/system\0"
                "systemd/user\0";

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

        if (!arg_no_pager)
                pager_open(false);

        if (optind < argc) {
                int i;

                for (i = optind; i < argc; i++) {
                        k = process_suffix_chop(prefixes, argv[i], have_dropins);
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }

        } else {
                const char *n;

                NULSTR_FOREACH(n, suffixes) {
                        k = process_suffix(prefixes, n, nulstr_contains(have_dropins, n));
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }
        }

        if (r >= 0)
                printf("%s%i overridden configuration files found.\n",
                       n_found ? "\n" : "", n_found);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
