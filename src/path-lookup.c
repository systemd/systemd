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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "strv.h"

#include "path-lookup.h"

int session_config_home(char **config_home) {
        const char *e;

        if ((e = getenv("XDG_CONFIG_HOME"))) {
                if (asprintf(config_home, "%s/systemd/session", e) < 0)
                        return -ENOMEM;

                return 1;
        } else {
                const char *home;

                if ((home = getenv("HOME"))) {
                        if (asprintf(config_home, "%s/.config/systemd/session", home) < 0)
                                return -ENOMEM;

                        return 1;
                }
        }

        return 0;
}

static char** session_dirs(void) {
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

        if (session_config_home(&config_home) < 0)
                goto fail;

        home = getenv("HOME");

        if ((e = getenv("XDG_CONFIG_DIRS")))
                if (!(config_dirs = strv_split(e, ":")))
                        goto fail;

        /* We don't treat /etc/xdg/systemd here as the spec
         * suggests because we assume that that is a link to
         * /etc/systemd/ anyway. */

        if ((e = getenv("XDG_DATA_HOME"))) {
                if (asprintf(&data_home, "%s/systemd/session", e) < 0)
                        goto fail;

        } else if (home) {
                if (asprintf(&data_home, "%s/.local/share/systemd/session", home) < 0)
                        goto fail;

                /* There is really no need for two unit dirs in $HOME,
                 * except to be fully compliant with the XDG spec. We
                 * now try to link the two dirs, so that we can
                 * minimize disk seeks a little. Further down we'll
                 * then filter out this link, if it is actually is
                 * one. */

                mkdir_parents(data_home, 0777);
                symlink("../../../.config/systemd/session", data_home);
        }

        if ((e = getenv("XDG_DATA_DIRS")))
                data_dirs = strv_split(e, ":");
        else
                data_dirs = strv_new("/usr/local/share", "/usr/share", NULL);

        if (!data_dirs)
                goto fail;

        /* Now merge everything we found. */
        if (config_home) {
                if (!(t = strv_append(r, config_home)))
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!(t = strv_merge_concat(r, config_dirs, "/systemd/session")))
                goto finish;
        strv_free(r);
        r = t;

        if (!(t = strv_append(r, SESSION_CONFIG_UNIT_PATH)))
                goto fail;
        strv_free(r);
        r = t;

        if (data_home) {
                if (!(t = strv_append(r, data_home)))
                        goto fail;
                strv_free(r);
                r = t;
        }

        if (!(t = strv_merge_concat(r, data_dirs, "/systemd/session")))
                goto fail;
        strv_free(r);
        r = t;

        if (!(t = strv_append(r, SESSION_DATA_UNIT_PATH)))
                goto fail;
        strv_free(r);
        r = t;

        if (!strv_path_make_absolute_cwd(r))
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

int lookup_paths_init(LookupPaths *p, ManagerRunningAs running_as) {
        const char *e;
        char *t;

        assert(p);

        /* First priority is whatever has been passed to us via env
         * vars */
        if ((e = getenv("SYSTEMD_UNIT_PATH")))
                if (!(p->unit_path = split_path_and_make_absolute(e)))
                        return -ENOMEM;

        if (strv_isempty(p->unit_path)) {

                /* Nothing is set, so let's figure something out. */
                strv_free(p->unit_path);

                if (running_as == MANAGER_SESSION) {
                        if (!(p->unit_path = session_dirs()))
                                return -ENOMEM;
                } else
                        if (!(p->unit_path = strv_new(
                                              SYSTEM_CONFIG_UNIT_PATH,  /* /etc/systemd/system/ */
                                              SYSTEM_DATA_UNIT_PATH,    /* /lib/systemd/system/ */
                                              NULL)))
                                return -ENOMEM;
        }

        if (running_as == MANAGER_INIT) {
                /* /etc/init.d/ compatibility does not matter to users */

                if ((e = getenv("SYSTEMD_SYSVINIT_PATH")))
                        if (!(p->sysvinit_path = split_path_and_make_absolute(e)))
                                return -ENOMEM;

                if (strv_isempty(p->sysvinit_path)) {
                        strv_free(p->sysvinit_path);

                        if (!(p->sysvinit_path = strv_new(
                                              SYSTEM_SYSVINIT_PATH,     /* /etc/init.d/ */
                                              NULL)))
                                return -ENOMEM;
                }

                if ((e = getenv("SYSTEMD_SYSVRCND_PATH")))
                        if (!(p->sysvrcnd_path = split_path_and_make_absolute(e)))
                                return -ENOMEM;

                if (strv_isempty(p->sysvrcnd_path)) {
                        strv_free(p->sysvrcnd_path);

                        if (!(p->sysvrcnd_path = strv_new(
                                              SYSTEM_SYSVRCND_PATH,     /* /etc/rcN.d/ */
                                              NULL)))
                                return -ENOMEM;
                }
        }

        if (p->unit_path)
                if (!strv_path_canonicalize(p->unit_path))
                        return -ENOMEM;

        if (p->sysvinit_path)
                if (!strv_path_canonicalize(p->sysvinit_path))
                        return -ENOMEM;

        if (p->sysvrcnd_path)
                if (!strv_path_canonicalize(p->sysvrcnd_path))
                        return -ENOMEM;

        strv_uniq(p->unit_path);
        strv_uniq(p->sysvinit_path);
        strv_uniq(p->sysvrcnd_path);

        if (!strv_isempty(p->unit_path)) {

                if (!(t = strv_join(p->unit_path, "\n\t")))
                        return -ENOMEM;
                log_debug("Looking for unit files in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring unit files.");
                strv_free(p->unit_path);
                p->unit_path = NULL;
        }

        if (!strv_isempty(p->sysvinit_path)) {

                if (!(t = strv_join(p->sysvinit_path, "\n\t")))
                        return -ENOMEM;

                log_debug("Looking for SysV init scripts in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring SysV init scripts.");
                strv_free(p->sysvinit_path);
                p->sysvinit_path = NULL;
        }

        if (!strv_isempty(p->sysvrcnd_path)) {

                if (!(t = strv_join(p->sysvrcnd_path, "\n\t")))
                        return -ENOMEM;

                log_debug("Looking for SysV rcN.d links in:\n\t%s", t);
                free(t);
        } else {
                log_debug("Ignoring SysV rcN.d links.");
                strv_free(p->sysvrcnd_path);
                p->sysvrcnd_path = NULL;
        }

        return 0;
}

void lookup_paths_free(LookupPaths *p) {
        assert(p);

        strv_free(p->unit_path);
        strv_free(p->sysvinit_path);
        strv_free(p->sysvrcnd_path);

        p->unit_path = p->sysvinit_path = p->sysvrcnd_path = NULL;
}
