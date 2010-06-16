/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/stat.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "path-lookup.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "conf-parser.h"

static bool arg_force = false;

static enum {
        WHERE_SYSTEM,
        WHERE_SESSION,
        WHERE_GLOBAL,
} arg_where = WHERE_SYSTEM;

static enum {
        ACTION_INVALID,
        ACTION_ENABLE,
        ACTION_DISABLE,
        ACTION_TEST
} arg_action = ACTION_INVALID;

typedef struct {
        char *name;
        char *path;

        char **aliases;
        char **wanted_by;
} InstallInfo;

Hashmap *will_install = NULL, *have_installed = NULL;

static int help(void) {

        printf("%s [options]\n\n"
               "  -h --help        Show this help\n"
               "     --force       Override existing links\n"
               "     --system      Install into system\n"
               "     --session     Install into session\n"
               "     --global      Install into all sessions\n"
               "Commands:\n"
               "  enable [NAME...]    Enable one or more units\n"
               "  disable [NAME...]   Disable one or more units\n"
               "  test [NAME...]      Test whether any of the specified units are enabled\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_SESSION = 0x100,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_FORCE
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'         },
                { "session",   no_argument,       NULL, ARG_SESSION },
                { "system",    no_argument,       NULL, ARG_SYSTEM  },
                { "global",    no_argument,       NULL, ARG_GLOBAL  },
                { "force",     no_argument,       NULL, ARG_FORCE   },
                { NULL,        0,                 NULL, 0           }
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_SESSION:
                        arg_where = WHERE_SESSION;
                        break;

                case ARG_SYSTEM:
                        arg_where = WHERE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_where = WHERE_GLOBAL;
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                log_error("Missing verb.");
                return -EINVAL;
        }

        if (streq(argv[optind], "enable"))
                arg_action = ACTION_ENABLE;
        else if (streq(argv[optind], "disable"))
                arg_action = ACTION_DISABLE;
        else if (streq(argv[optind], "test"))
                arg_action = ACTION_TEST;
        else {
                log_error("Unknown verb %s", argv[optind]);
                return -EINVAL;
        }

        optind++;

        if (optind >= argc) {
                log_error("Missing unit name.");
                return -EINVAL;
        }

        return 1;
}

static void install_info_free(InstallInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->aliases);
        strv_free(i->wanted_by);
        free(i);
}

static void install_info_hashmap_free(Hashmap *m) {
        InstallInfo *i;

        while ((i = hashmap_steal_first(m)))
                install_info_free(i);

        hashmap_free(m);
}

static bool unit_name_valid(const char *name) {

        /* This is a minimal version of unit_name_valid() from
         * unit-name.c */

        if (strchr(name, '/'))
                return false;

        if (!*name)
                return false;

        if (ignore_file(name))
                return false;

        return true;
}

static int install_info_add(const char *name) {
        InstallInfo *i;
        int r;

        if (!unit_name_valid(name))
                return -EINVAL;

        if (hashmap_get(have_installed, name) ||
            hashmap_get(will_install, name))
                return 0;

        if (!(i = new0(InstallInfo, 1))) {
                r = -ENOMEM;
                goto fail;
        }

        if (!(i->name = strdup(name))) {
                r = -ENOMEM;
                goto fail;
        }

        if ((r = hashmap_put(will_install, i->name, i)) < 0)
                goto fail;

        return 0;

fail:
        if (i)
                install_info_free(i);

        return r;
}

static int config_parse_also(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                char *n;
                int r;

                if (!(n = strndup(w, l)))
                        return -ENOMEM;

                r = install_info_add(n);
                free(n);

                if (r < 0)
                        return r;
        }

        return 0;
}

static int create_symlink(const char *old_path, const char *new_path) {
        int r;

        assert(old_path);
        assert(new_path);

        if (arg_action == ACTION_ENABLE) {
                char *dest;

                mkdir_parents(new_path, 0755);

                if (symlink(old_path, new_path) >= 0)
                        return 0;

                if (errno != EEXIST) {
                        log_error("Cannot link %s to %s: %m", old_path, new_path);
                        return -errno;
                }

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {

                        if (errno == EINVAL) {
                                log_error("Cannot link %s to %s, file exists already and is not a symlink.", old_path, new_path);
                                return -EEXIST;
                        }

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (streq(dest, old_path)) {
                        free(dest);
                        return 0;
                }

                if (!arg_force) {
                        log_error("Cannot link %s to %s, symlink exists already and points to %s.", old_path, new_path, dest);
                        free(dest);
                        return -EEXIST;
                }

                free(dest);
                unlink(new_path);

                if (symlink(old_path, new_path) >= 0)
                        return 0;

                log_error("Cannot link %s to %s: %m", old_path, new_path);
                return -errno;

        } else if (arg_action == ACTION_DISABLE) {
                char *dest;

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {
                        if (errno == ENOENT)
                                return 0;

                        if (errno == EINVAL) {
                                log_warning("File %s not a symlink, ignoring.", old_path);
                                return 0;
                        }

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (!streq(dest, old_path)) {
                        log_warning("File %s not a symlink to %s but points to %s, ignoring.", new_path, old_path, dest);
                        free(dest);
                        return 0;
                }

                free(dest);
                if (unlink(new_path) >= 0)
                        return 0;

                log_error("Cannot unlink %s: %m", new_path);
                return -errno;

        } else if (arg_action == ACTION_TEST) {
                char *dest;

                if ((r = readlink_and_make_absolute(new_path, &dest)) < 0) {

                        if (errno == ENOENT || errno == EINVAL)
                                return 0;

                        log_error("readlink() failed: %s", strerror(-r));
                        return r;
                }

                if (streq(dest, old_path)) {
                        free(dest);
                        return 1;
                }

                return 0;
        }

        assert_not_reached("Unknown action.");
}

static int install_info_symlink_alias(InstallInfo *i, const char *config_path) {
        char **s;
        char *alias_path = NULL;
        int r;

        assert(i);

        STRV_FOREACH(s, i->aliases) {

                if (!unit_name_valid(*s)) {
                        log_error("Invalid name %s.", *s);
                        r = -EINVAL;
                        goto finish;
                }

                free(alias_path);
                if (!(alias_path = path_make_absolute(*s, config_path))) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = create_symlink(i->path, alias_path)) != 0)
                        goto finish;
        }

        r = 0;

finish:
        free(alias_path);

        return r;
}

static int install_info_symlink_wants(InstallInfo *i, const char *config_path) {
        char **s;
        char *alias_path = NULL;
        int r;

        assert(i);

        STRV_FOREACH(s, i->wanted_by) {
                if (!unit_name_valid(*s)) {
                        log_error("Invalid name %s.", *s);
                        r = -EINVAL;
                        goto finish;
                }

                free(alias_path);
                alias_path = NULL;

                if (asprintf(&alias_path, "%s/%s.wants/%s", config_path, *s, i->name) < 0) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = create_symlink(i->path, alias_path)) != 0)
                        goto finish;

                if (arg_action == ACTION_DISABLE) {
                        char *t;

                        /* Try to remove .wants dir if we don't need it anymore */
                        if (asprintf(&t, "%s/%s.wants", config_path, *s) >= 0) {
                                rmdir(t);
                                free(t);
                        }
                }
        }

        r = 0;

finish:
        free(alias_path);

        return r;
}

static int install_info_apply(LookupPaths *paths, InstallInfo *i, const char *config_path) {

        const ConfigItem items[] = {
                { "Alias",    config_parse_strv, &i->aliases,   "Install" },
                { "WantedBy", config_parse_strv, &i->wanted_by, "Install" },
                { "Also",     config_parse_also, NULL,          "Install" },

                { NULL, NULL, NULL, NULL }
        };

        char **p;
        char *filename = NULL;
        FILE *f = NULL;
        int r;

        assert(paths);
        assert(i);

        STRV_FOREACH(p, paths->unit_path) {

                if (!(filename = path_make_absolute(i->name, *p))) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }

                if ((f = fopen(filename, "re")))
                        break;

                free(filename);
                filename = NULL;

                if (errno != ENOENT) {
                        log_error("Failed to open %s: %m", filename);
                        return -errno;
                }
        }

        if (!f) {
                log_error("Couldn't find %s.", i->name);
                return -ENOENT;
        }

        i->path = filename;

        if ((r = config_parse(filename, f, NULL, items, true, i)) < 0) {
                fclose(f);
                return r;
        }

        fclose(f);

        if ((r = install_info_symlink_alias(i, config_path)) != 0)
                return r;

        if ((r = install_info_symlink_wants(i, config_path)) != 0)
                return r;

        return 0;
}

static char *get_config_path(void) {

        switch (arg_where) {

        case WHERE_SYSTEM:
                return strdup(SYSTEM_CONFIG_UNIT_PATH);

        case WHERE_GLOBAL:
                return strdup(SESSION_CONFIG_UNIT_PATH);

        case WHERE_SESSION: {
                char *p;

                if (session_config_home(&p) < 0)
                        return NULL;

                return p;
        }

        default:
                assert_not_reached("Unknown config path.");
        }
}

int main(int argc, char *argv[]) {
        int r, retval = 1, j;
        LookupPaths paths;
        InstallInfo *i;
        char *config_path = NULL;

        zero(paths);

        log_set_target(LOG_TARGET_CONSOLE);
        log_set_max_level(LOG_INFO);
        log_parse_environment();

        if ((r = parse_argv(argc, argv)) < 0)
                goto finish;
        else if (r == 0) {
                retval = 0;
                goto finish;
        }

        if ((r = lookup_paths_init(&paths, arg_where == WHERE_SYSTEM ? MANAGER_INIT : MANAGER_SESSION)) < 0) {
                log_error("Failed to determine lookup paths: %s", strerror(-r));
                goto finish;
        }

        if (!(config_path = get_config_path())) {
                log_error("Failed to determine config path");
                goto finish;
        }

        will_install = hashmap_new(string_hash_func, string_compare_func);
        have_installed = hashmap_new(string_hash_func, string_compare_func);

        if (!will_install || !have_installed) {
                log_error("Failed to allocate unit sets.");
                goto finish;
        }

        for (j = optind; j < argc; j++)
                if ((r = install_info_add(argv[j])) < 0)
                        goto finish;

        while ((i = hashmap_first(will_install))) {
                assert_se(hashmap_move_one(have_installed, will_install, i->name) == 0);

                if ((r = install_info_apply(&paths, i, config_path)) != 0) {

                        if (r < 0)
                                goto finish;

                        /* In test mode and found something */
                        retval = 0;
                        goto finish;
                }
        }

        retval = arg_action == ACTION_TEST ? 1 : 0;

finish:
        install_info_hashmap_free(will_install);
        install_info_hashmap_free(have_installed);

        lookup_paths_free(&paths);

        free(config_path);

        return retval;
}
