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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "mkdir.h"
#include "strv.h"
#include "path-util.h"
#include "path-lookup.h"

static const char* const systemd_running_as_table[_SYSTEMD_RUNNING_AS_MAX] = {
        [SYSTEMD_SYSTEM] = "system",
        [SYSTEMD_USER] = "user"
};

DEFINE_STRING_TABLE_LOOKUP(systemd_running_as, SystemdRunningAs);

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

static char** user_dirs(
                const char *generator,
                const char *generator_early,
                const char *generator_late) {

        const char * const config_unit_paths[] = {
                USER_CONFIG_UNIT_PATH,
                "/etc/systemd/user",
                "/run/systemd/user",
                NULL
        };

        const char * const data_unit_paths[] = {
                "/usr/local/lib/systemd/user",
                "/usr/local/share/systemd/user",
                USER_DATA_UNIT_PATH,
                "/usr/lib/systemd/user",
                "/usr/share/systemd/user",
                NULL
        };

        const char *home, *e;
        char *config_home = NULL, *data_home = NULL;
        char **config_dirs = NULL, **data_dirs = NULL;
        char **r = NULL, **t;

        /* Implement the mechanisms defined in
         *
         * http://standards.freedesktop.org/basedir-spec/basedir-spec-0.6.html
         *
         * We look in both the config and the data dirs because we
         * want to encourage that distributors ship their unit files
         * as data, and allow overriding as configuration.
         */

        if (user_config_home(&config_home) < 0)
                goto fail;

        home = getenv("HOME");

        e = getenv("XDG_CONFIG_DIRS");
        if (e) {
                config_dirs = strv_split(e, ":");
                if (!config_dirs)
                        goto fail;
        }

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that that is a link to
         * /etc/systemd/ anyway. */

        e = getenv("XDG_DATA_HOME");
        if (e) {
                if (asprintf(&data_home, "%s/systemd/user", e) < 0)
                        goto fail;

        } else if (home) {
                if (asprintf(&data_home, "%s/.local/share/systemd/user", home) < 0)
                        goto fail;

                /* There is really no need for two unit dirs in $HOME,
                 * except to be fully compliant with the XDG spec. We
                 * now try to link the two dirs, so that we can
                 * minimize disk seeks a little. Further down we'll
                 * then filter out this link, if it is actually is
                 * one. */

                mkdir_parents_label(data_home, 0777);
                (void) symlink("../../../.config/systemd/user", data_home);
        }

        e = getenv("XDG_DATA_DIRS");
        if (e)
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share",
                                     "/usr/share",
                                     NULL);
        if (!data_dirs)
                goto fail;

        /* Now merge everything we found. */
        if (generator_early) {
                t = strv_append(r, generator_early);
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (config_home) {
                t = strv_append(r, config_home);
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!strv_isempty(config_dirs)) {
                t = strv_merge_concat(r, config_dirs, "/systemd/user");
                if (!t)
                        goto finish;
                strv_free(r);
                r = t;
        }

        t = strv_merge(r, (char**) config_unit_paths);
        if (!t)
                goto fail;
        strv_free(r);
        r = t;

        if (generator) {
                t = strv_append(r, generator);
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (data_home) {
                t = strv_append(r, data_home);
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!strv_isempty(data_dirs)) {
                t = strv_merge_concat(r, data_dirs, "/systemd/user");
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        t = strv_merge(r, (char**) data_unit_paths);
        if (!t)
                goto fail;
        strv_free(r);
        r = t;

        if (generator_late) {
                t = strv_append(r, generator_late);
                if (!t)
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!path_strv_make_absolute_cwd(r))
                goto fail;

finish:
        free(config_home);
        strv_free(config_dirs);
        free(data_home);
        strv_free(data_dirs);

        return r;

fail:
        strv_free(r);
        r = NULL;
        goto finish;
}

int lookup_paths_init(
                LookupPaths *p,
                SystemdRunningAs running_as,
                bool personal,
                const char *generator,
                const char *generator_early,
                const char *generator_late) {

        const char *e;

        assert(p);

        /* First priority is whatever has been passed to us via env
         * vars */
        e = getenv("SYSTEMD_UNIT_PATH");
        if (e) {
                p->unit_path = path_split_and_make_absolute(e);
                if (!p->unit_path)
                        return -ENOMEM;
        } else
                p->unit_path = NULL;

        if (strv_isempty(p->unit_path)) {
                /* Nothing is set, so let's figure something out. */
                strv_free(p->unit_path);

                /* For the user units we include share/ in the search
                 * path in order to comply with the XDG basedir
                 * spec. For the system stuff we avoid such
                 * nonsense. OTOH we include /lib in the search path
                 * for the system stuff but avoid it for user
                 * stuff. */

                if (running_as == SYSTEMD_USER) {

                        if (personal)
                                p->unit_path = user_dirs(generator, generator_early, generator_late);
                        else
                                p->unit_path = strv_new(
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

                        if (!p->unit_path)
                                return -ENOMEM;

                } else {
                        p->unit_path = strv_new(
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

                        if (!p->unit_path)
                                return -ENOMEM;
                }
        }

        if (!path_strv_canonicalize(p->unit_path))
                return -ENOMEM;

        strv_uniq(p->unit_path);

        if (!strv_isempty(p->unit_path)) {
                _cleanup_free_ char *t = strv_join(p->unit_path, "\n\t");
                if (!t)
                        return -ENOMEM;
                log_debug("Looking for unit files in (higher priority first):\n\t%s", t);
        } else {
                log_debug("Ignoring unit files.");
                strv_free(p->unit_path);
                p->unit_path = NULL;
        }

        if (running_as == SYSTEMD_SYSTEM) {
#ifdef HAVE_SYSV_COMPAT
                /* /etc/init.d/ compatibility does not matter to users */

                e = getenv("SYSTEMD_SYSVINIT_PATH");
                if (e) {
                        p->sysvinit_path = path_split_and_make_absolute(e);
                        if (!p->sysvinit_path)
                                return -ENOMEM;
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
                        p->sysvrcnd_path = path_split_and_make_absolute(e);
                        if (!p->sysvrcnd_path)
                                return -ENOMEM;
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

                if (!path_strv_canonicalize(p->sysvinit_path))
                        return -ENOMEM;

                if (!path_strv_canonicalize(p->sysvrcnd_path))
                        return -ENOMEM;

                strv_uniq(p->sysvinit_path);
                strv_uniq(p->sysvrcnd_path);

                if (!strv_isempty(p->sysvinit_path)) {
                        _cleanup_free_ char *t = strv_join(p->sysvinit_path, "\n\t");
                        if (!t)
                                return -ENOMEM;
                        log_debug("Looking for SysV init scripts in:\n\t%s", t);
                } else {
                        log_debug("Ignoring SysV init scripts.");
                        strv_free(p->sysvinit_path);
                        p->sysvinit_path = NULL;
                }

                if (!strv_isempty(p->sysvrcnd_path)) {
                        _cleanup_free_ char *t =
                                strv_join(p->sysvrcnd_path, "\n\t");
                        if (!t)
                                return -ENOMEM;

                        log_debug("Looking for SysV rcN.d links in:\n\t%s", t);
                } else {
                        log_debug("Ignoring SysV rcN.d links.");
                        strv_free(p->sysvrcnd_path);
                        p->sysvrcnd_path = NULL;
                }
#else
                log_debug("SysV init scripts and rcN.d links support disabled");
#endif
        }

        return 0;
}

void lookup_paths_free(LookupPaths *p) {
        assert(p);

        strv_free(p->unit_path);
        p->unit_path = NULL;

#ifdef HAVE_SYSV_COMPAT
        strv_free(p->sysvinit_path);
        strv_free(p->sysvrcnd_path);
        p->sysvinit_path = p->sysvrcnd_path = NULL;
#endif
}
