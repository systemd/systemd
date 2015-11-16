/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

int lookup_paths_init(
                LookupPaths *p,
                ManagerRunningAs running_as,
                bool personal,
                const char *root_dir,
                const char *generator,
                const char *generator_early,
                const char *generator_late) {

        const char *e;
        bool append = false; /* Add items from SYSTEMD_UNIT_PATH before normal directories */
        int r;

        assert(p);

        /* First priority is whatever has been passed to us via env
         * vars */
        e = getenv("SYSTEMD_UNIT_PATH");
        if (e) {
                if (endswith(e, ":")) {
                        e = strndupa(e, strlen(e) - 1);
                        append = true;
                }

                /* FIXME: empty components in other places should be
                 * rejected. */

                r = path_split_and_make_absolute(e, &p->unit_path);
                if (r < 0)
                        return r;
        } else
                p->unit_path = NULL;

        if (!p->unit_path || append) {
                /* Let's figure something out. */

                _cleanup_strv_free_ char **unit_path;

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir spec.
                 * For the system stuff we avoid such nonsense. OTOH
                 * we include /lib in the search path for the system
                 * stuff but avoid it for user stuff. */

                if (running_as == MANAGER_USER) {
                        if (personal)
                                unit_path = user_dirs(generator, generator_early, generator_late);
                        else
                                unit_path = strv_new(
                                        /* If you modify this you also want to modify
                                         * systemduserunitpath= in systemd.pc.in, and
                                         * the arrays in user_dirs() above! */
                                        STRV_IFNOTNULL(generator_early),
                                        USER_CONFIG_UNIT_PATH,
                                        "/etc/systemd/user",
                                        "/run/systemd/user",
                                        STRV_IFNOTNULL(generator),
                                        "/usr/local/lib/systemd/user",
                                        "/usr/local/share/systemd/user",
                                        USER_DATA_UNIT_PATH,
                                        "/usr/lib/systemd/user",
                                        "/usr/share/systemd/user",
                                        STRV_IFNOTNULL(generator_late),
                                        NULL);
                } else
                        unit_path = strv_new(
                                /* If you modify this you also want to modify
                                 * systemdsystemunitpath= in systemd.pc.in! */
                                STRV_IFNOTNULL(generator_early),
                                SYSTEM_CONFIG_UNIT_PATH,
                                "/etc/systemd/system",
                                "/run/systemd/system",
                                STRV_IFNOTNULL(generator),
                                "/usr/local/lib/systemd/system",
                                SYSTEM_DATA_UNIT_PATH,
                                "/usr/lib/systemd/system",
#ifdef HAVE_SPLIT_USR
                                "/lib/systemd/system",
#endif
                                STRV_IFNOTNULL(generator_late),
                                NULL);

                if (!unit_path)
                        return -ENOMEM;

                r = strv_extend_strv(&p->unit_path, unit_path, false);
                if (r < 0)
                        return r;
        }

        if (!path_strv_resolve_uniq(p->unit_path, root_dir))
                return -ENOMEM;

        if (!strv_isempty(p->unit_path)) {
                _cleanup_free_ char *t = strv_join(p->unit_path, "\n\t");
                if (!t)
                        return -ENOMEM;
                log_debug("Looking for unit files in (higher priority first):\n\t%s", t);
        } else {
                log_debug("Ignoring unit files.");
                p->unit_path = strv_free(p->unit_path);
        }

        if (running_as == MANAGER_SYSTEM) {
#ifdef HAVE_SYSV_COMPAT
                /* /etc/init.d/ compatibility does not matter to users */

                e = getenv("SYSTEMD_SYSVINIT_PATH");
                if (e) {
                        r = path_split_and_make_absolute(e, &p->sysvinit_path);
                        if (r < 0)
                                return r;
                } else
                        p->sysvinit_path = NULL;

                if (strv_isempty(p->sysvinit_path)) {
                        strv_free(p->sysvinit_path);

                        p->sysvinit_path = strv_new(
                                        SYSTEM_SYSVINIT_PATH,     /* /etc/init.d/ */
                                        NULL);
                        if (!p->sysvinit_path)
                                return -ENOMEM;
                }

                e = getenv("SYSTEMD_SYSVRCND_PATH");
                if (e) {
                        r = path_split_and_make_absolute(e, &p->sysvrcnd_path);
                        if (r < 0)
                                return r;
                } else
                        p->sysvrcnd_path = NULL;

                if (strv_isempty(p->sysvrcnd_path)) {
                        strv_free(p->sysvrcnd_path);

                        p->sysvrcnd_path = strv_new(
                                        SYSTEM_SYSVRCND_PATH,     /* /etc/rcN.d/ */
                                        NULL);
                        if (!p->sysvrcnd_path)
                                return -ENOMEM;
                }

                if (!path_strv_resolve_uniq(p->sysvinit_path, root_dir))
                        return -ENOMEM;

                if (!path_strv_resolve_uniq(p->sysvrcnd_path, root_dir))
                        return -ENOMEM;

                if (!strv_isempty(p->sysvinit_path)) {
                        _cleanup_free_ char *t = strv_join(p->sysvinit_path, "\n\t");
                        if (!t)
                                return -ENOMEM;
                        log_debug("Looking for SysV init scripts in:\n\t%s", t);
                } else {
                        log_debug("Ignoring SysV init scripts.");
                        p->sysvinit_path = strv_free(p->sysvinit_path);
                }

                if (!strv_isempty(p->sysvrcnd_path)) {
                        _cleanup_free_ char *t =
                                strv_join(p->sysvrcnd_path, "\n\t");
                        if (!t)
                                return -ENOMEM;

                        log_debug("Looking for SysV rcN.d links in:\n\t%s", t);
                } else {
                        log_debug("Ignoring SysV rcN.d links.");
                        p->sysvrcnd_path = strv_free(p->sysvrcnd_path);
                }
#else
                log_debug("SysV init scripts and rcN.d links support disabled");
#endif
        }

        return 0;
}

void lookup_paths_free(LookupPaths *p) {
        assert(p);

        p->unit_path = strv_free(p->unit_path);

#ifdef HAVE_SYSV_COMPAT
        p->sysvinit_path = strv_free(p->sysvinit_path);
        p->sysvrcnd_path = strv_free(p->sysvrcnd_path);
#endif
}

int lookup_paths_init_from_scope(LookupPaths *paths,
                                 UnitFileScope scope,
                                 const char *root_dir) {
        assert(paths);
        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        zero(*paths);

        return lookup_paths_init(paths,
                                 scope == UNIT_FILE_SYSTEM ? MANAGER_SYSTEM : MANAGER_USER,
                                 scope == UNIT_FILE_USER,
                                 root_dir,
                                 NULL, NULL, NULL);
}
