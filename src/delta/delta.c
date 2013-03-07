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

static bool arg_no_pager = false;
static int arg_diff = -1;

static enum {
        SHOW_MASKED = 1 << 0,
        SHOW_EQUIVALENT = 1 << 1,
        SHOW_REDIRECTED = 1 << 2,
        SHOW_OVERRIDDEN = 1 << 3,
        SHOW_UNCHANGED = 1 << 4,

        SHOW_DEFAULTS =
        (SHOW_MASKED | SHOW_EQUIVALENT | SHOW_REDIRECTED | SHOW_OVERRIDDEN)
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

        printf(ANSI_HIGHLIGHT_RED_ON "[MASKED]" ANSI_HIGHLIGHT_OFF "     %s → %s\n", top, bottom);
        return 1;
}

static int notify_override_equivalent(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_EQUIVALENT))
                return 0;

        printf(ANSI_HIGHLIGHT_GREEN_ON "[EQUIVALENT]" ANSI_HIGHLIGHT_OFF " %s → %s\n", top, bottom);
        return 1;
}

static int notify_override_redirected(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_REDIRECTED))
                return 0;

        printf(ANSI_HIGHLIGHT_ON "[REDIRECTED]" ANSI_HIGHLIGHT_OFF "   %s → %s\n", top, bottom);
        return 1;
}

static int notify_override_overridden(const char *top, const char *bottom) {
        if (!(arg_flags & SHOW_OVERRIDDEN))
                return 0;

        printf(ANSI_HIGHLIGHT_ON "[OVERRIDDEN]" ANSI_HIGHLIGHT_OFF " %s → %s\n", top, bottom);
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

        if (null_or_empty_path(top) > 0) {
                notify_override_masked(top, bottom);
                return 0;
        }

        k = readlink_malloc(top, &dest);
        if (k >= 0) {
                if (equivalent(dest, bottom) > 0)
                        notify_override_equivalent(top, bottom);
                else
                        notify_override_redirected(top, bottom);

                return 0;
        }

        notify_override_overridden(top, bottom);
        if (!arg_diff)
                return 0;

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

        return 0;
}

static int enumerate_dir(Hashmap *top, Hashmap *bottom, const char *path) {
        _cleanup_closedir_ DIR *d;

        assert(top);
        assert(bottom);
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

static int process_suffix(const char *prefixes, const char *suffix) {
        const char *p;
        char *f;
        Hashmap *top, *bottom=NULL;
        int r = 0, k;
        Iterator i;
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

        NULSTR_FOREACH(p, prefixes) {
                _cleanup_free_ char *t = NULL;

                t = strjoin(p, "/", suffix, NULL);
                if (!t) {
                        r = -ENOMEM;
                        goto finish;
                }

                k = enumerate_dir(top, bottom, t);
                if (k < 0)
                        r = k;

                log_debug("Looking at %s", t);
        }

        HASHMAP_FOREACH(f, top, i) {
                char *o;

                o = hashmap_get(bottom, path_get_file_name(f));
                assert(o);

                if (path_equal(o, f)) {
                        notify_override_unchanged(f);
                        continue;
                }

                k = found_override(f, o);
                if (k < 0)
                        r = k;

                n_found ++;
        }

finish:
        if (top)
                hashmap_free_free(top);
        if (bottom)
                hashmap_free_free(bottom);

        return r < 0 ? r : n_found;
}

static int process_suffix_chop(const char *prefixes, const char *suffix) {
        const char *p;

        assert(prefixes);
        assert(suffix);

        if (!path_is_absolute(suffix))
                return process_suffix(prefixes, suffix);

        /* Strip prefix from the suffix */
        NULSTR_FOREACH(p, prefixes) {
                if (startswith(suffix, p)) {
                        suffix += strlen(p);
                        suffix += strspn(suffix, "/");
                        return process_suffix(prefixes, suffix);
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
                        k = process_suffix_chop(prefixes, argv[i]);
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }

        } else {
                const char *n;

                NULSTR_FOREACH(n, suffixes) {
                        k = process_suffix(prefixes, n);
                        if (k < 0)
                                r = k;
                        else
                                n_found += k;
                }
        }

        if (r >= 0)
                printf("\n%i overridden configuration files found.\n", n_found);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
