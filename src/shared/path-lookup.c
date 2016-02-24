/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "install.h"
#include "log.h"
#include "macro.h"
#include "path-lookup.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

int user_config_home(char **config_home) {
        const char *e;
        char *r;

        e = getenv("XDG_CONFIG_HOME");
        if (e) {
                r = strappend(e, "/systemd/user");
                if (!r)
                        return -ENOMEM;

                *config_home = r;
                return 1;
        } else {
                const char *home;

                home = getenv("HOME");
                if (home) {
                        r = strappend(home, "/.config/systemd/user");
                        if (!r)
                                return -ENOMEM;

                        *config_home = r;
                        return 1;
                }
        }

        return 0;
}

int user_runtime_dir(char **runtime_dir) {
        const char *e;
        char *r;

        e = getenv("XDG_RUNTIME_DIR");
        if (e) {
                r = strappend(e, "/systemd/user");
                if (!r)
                        return -ENOMEM;

                *runtime_dir = r;
                return 1;
        }

        return 0;
}

static int user_data_home_dir(char **dir, const char *suffix) {
        const char *e;
        char *res;

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that that is a link to
         * /etc/systemd/ anyway. */

        e = getenv("XDG_DATA_HOME");
        if (e)
                res = strappend(e, suffix);
        else {
                const char *home;

                home = getenv("HOME");
                if (home)
                        res = strjoin(home, "/.local/share", suffix, NULL);
                else
                        return 0;
        }
        if (!res)
                return -ENOMEM;

        *dir = res;
        return 0;
}

static char** user_dirs(
                const char *generator,
                const char *generator_early,
                const char *generator_late) {

        const char * const config_unit_paths[] = {
                USER_CONFIG_UNIT_PATH,
                "/etc/systemd/user",
                NULL
        };

        const char * const runtime_unit_path = "/run/systemd/user";

        const char * const data_unit_paths[] = {
                "/usr/local/lib/systemd/user",
                "/usr/local/share/systemd/user",
                USER_DATA_UNIT_PATH,
                "/usr/lib/systemd/user",
                "/usr/share/systemd/user",
                NULL
        };

        const char *e;
        _cleanup_free_ char *config_home = NULL, *runtime_dir = NULL, *data_home = NULL;
        _cleanup_strv_free_ char **config_dirs = NULL, **data_dirs = NULL;
        _cleanup_free_ char **res = NULL;
        char **tmp;
        int r;

        /* Implement the mechanisms defined in
         *
         * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */

        if (user_config_home(&config_home) < 0)
                return NULL;

        if (user_runtime_dir(&runtime_dir) < 0)
                return NULL;

        e = getenv("XDG_CONFIG_DIRS");
        if (e) {
                config_dirs = strv_split(e, ":");
                if (!config_dirs)
                        return NULL;
        }

        r = user_data_home_dir(&data_home, "/systemd/user");
        if (r < 0)
                return NULL;

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share",
                                     NULL);
        if (!data_dirs)
                return NULL;

        /* Now merge everything we found. */
        if (generator_early)
                if (strv_extend(&res, generator_early) < 0)
                        return NULL;

        if (config_home)
                if (strv_extend(&res, config_home) < 0)
                        return NULL;

        if (!strv_isempty(config_dirs))
                if (strv_extend_strv_concat(&res, config_dirs, "/systemd/user") < 0)
                        return NULL;

        if (strv_extend_strv(&res, (char**) config_unit_paths, false) < 0)
                return NULL;

        if (runtime_dir)
                if (strv_extend(&res, runtime_dir) < 0)
                        return NULL;

        if (strv_extend(&res, runtime_unit_path) < 0)
                return NULL;

        if (generator)
                if (strv_extend(&res, generator) < 0)
                        return NULL;

        if (data_home)
                if (strv_extend(&res, data_home) < 0)
                        return NULL;

        if (!strv_isempty(data_dirs))
                if (strv_extend_strv_concat(&res, data_dirs, "/systemd/user") < 0)
                        return NULL;

        if (strv_extend_strv(&res, (char**) data_unit_paths, false) < 0)
                return NULL;

        if (generator_late)
                if (strv_extend(&res, generator_late) < 0)
                        return NULL;

        if (path_strv_make_absolute_cwd(res) < 0)
                return NULL;

        tmp = res;
        res = NULL;
        return tmp;
}

char **generator_paths(ManagerRunningAs running_as) {
        if (running_as == MANAGER_USER)
                return strv_new("/run/systemd/user-generators",
                                "/etc/systemd/user-generators",
                                "/usr/local/lib/systemd/user-generators",
                                USER_GENERATOR_PATH,
                                NULL);
        else
                return strv_new("/run/systemd/system-generators",
                                "/etc/systemd/system-generators",
                                "/usr/local/lib/systemd/system-generators",
                                SYSTEM_GENERATOR_PATH,
                                NULL);
}

static int acquire_generator_dirs(
                ManagerRunningAs running_as,
                char **generator,
                char **generator_early,
                char **generator_late) {

        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL;
        const char *prefix;

        assert(generator);
        assert(generator_early);
        assert(generator_late);

        if (running_as == MANAGER_SYSTEM)
                prefix = "/run/systemd/";
        else {
                const char *e;

                assert(running_as == MANAGER_USER);

                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return -EINVAL;

                prefix = strjoina(e, "/systemd/", NULL);
        }

        x = strappend(prefix, "generator");
        if (!x)
                return -ENOMEM;

        y = strappend(prefix, "generator.early");
        if (!y)
                return -ENOMEM;

        z = strappend(prefix, "generator.late");
        if (!z)
                return -ENOMEM;

        *generator = x;
        *generator_early = y;
        *generator_late = z;

        x = y = z = NULL;
        return 0;
}

static int patch_root_prefix(char **p, const char *root_dir) {
        char *c;

        assert(p);

        if (!*p)
                return 0;

        if (isempty(root_dir) || path_equal(root_dir, "/"))
                return 0;

        c = prefix_root(root_dir, *p);
        if (!c)
                return -ENOMEM;

        free(*p);
        *p = c;

        return 0;
}

int lookup_paths_init(
                LookupPaths *p,
                ManagerRunningAs running_as,
                bool personal,
                const char *root_dir) {

        _cleanup_free_ char *generator = NULL, *generator_early = NULL, *generator_late = NULL;
        bool append = false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */
        char **l = NULL;
        const char *e;
        int r;

        assert(p);
        assert(running_as >= 0);
        assert(running_as < _MANAGER_RUNNING_AS_MAX);

        r = acquire_generator_dirs(running_as, &generator, &generator_early, &generator_late);
        if (r < 0)
                return r;

        /* First priority is whatever has been passed to us via env
         * vars */
        e = getenv("SYSTEMD_UNIT_PATH");
        if (e) {
                const char *k;

                k = endswith(e, ":");
                if (k) {
                        e = strndupa(e, k - e);
                        append = true;
                }

                /* FIXME: empty components in other places should be
                 * rejected. */

                r = path_split_and_make_absolute(e, &l);
                if (r < 0)
                        return r;
        } else
                l = NULL;

        if (!l || append) {
                /* Let's figure something out. */

                _cleanup_strv_free_ char **add = NULL;

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir spec.
                 * For the system stuff we avoid such nonsense. OTOH
                 * we include /lib in the search path for the system
                 * stuff but avoid it for user stuff. */

                if (running_as == MANAGER_USER) {
                        if (personal)
                                add = user_dirs(generator, generator_early, generator_late);
                        else
                                add = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemduserunitpath= in systemd.pc.in, and
                                         * the arrays in user_dirs() above! */
                                        generator_early,
                                        USER_CONFIG_UNIT_PATH,
                                        "/etc/systemd/user",
                                        "/run/systemd/user",
                                        generator,
                                        "/usr/local/lib/systemd/user",
                                        "/usr/local/share/systemd/user",
                                        USER_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/user",
                                        "/usr/share/systemd/user",
                                        generator_late,
                                        NULL);
                } else
                        add = strv_new(
                                /* If you modify this you also want to modify
                                 * systemdsystemunitpath= in systemd.pc.in! */
                                generator_early,
                                SYSTEM_CONFIG_UNIT_PATH,
                                "/etc/systemd/system",
                                "/run/systemd/system",
                                generator,
                                "/usr/local/lib/systemd/system",
                                SYSTEM_DATA_UNIT_PATH,
                                "/usr/lib/systemd/system",
#ifdef HAVE_SPLIT_USR
                                "/lib/systemd/system",
#endif
                                generator_late,
                                NULL);

                if (!add)
                        return -ENOMEM;

                if (l) {
                        r = strv_extend_strv(&l, add, false);
                        if (r < 0)
                                return r;
                } else {
                        l = add;
                        add = NULL;
                }
        }

        r = patch_root_prefix(&generator, root_dir);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_early, root_dir);
        if (r < 0)
                return r;
        r = patch_root_prefix(&generator_late, root_dir);
        if (r < 0)
                return r;

        if (!path_strv_resolve_uniq(l, root_dir))
                return -ENOMEM;

        if (strv_isempty(l)) {
                log_debug("Ignoring unit files.");
                l = strv_free(l);
        } else {
                _cleanup_free_ char *t;

                t = strv_join(l, "\n\t");
                if (!t)
                        return -ENOMEM;

                log_debug("Looking for unit files in (higher priority first):\n\t%s", t);
        }

        p->search_path = l;
        l = NULL;

        p->generator = generator;
        p->generator_early = generator_early;
        p->generator_late = generator_late;
        generator = generator_early = generator_late = NULL;

        return 0;
}

void lookup_paths_free(LookupPaths *p) {
        if (!p)
                return;

        p->search_path = strv_free(p->search_path);
        p->generator = mfree(p->generator);
        p->generator_early = mfree(p->generator_early);
        p->generator_late = mfree(p->generator_late);
}

int lookup_paths_init_from_scope(
                LookupPaths *p,
                UnitFileScope scope,
                const char *root_dir) {

        assert(p);
        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        return lookup_paths_init(
                        p,
                        scope == UNIT_FILE_SYSTEM ? MANAGER_SYSTEM : MANAGER_USER,
                        scope == UNIT_FILE_USER,
                        root_dir);
}
