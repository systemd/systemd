/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include <stdlib.h>

#include "alloc-util.h"
#include "analyze-verify.h"
#include "bus-error.h"
#include "bus-util.h"
#include "log.h"
#include "manager.h"
#include "pager.h"
#include "path-util.h"
#include "strv.h"

static int generate_path(char **var, char **filenames) {
        char **filename;

        _cleanup_strv_free_ char **ans = NULL;
        int r;

        STRV_FOREACH(filename, filenames) {
                char *t;

                t = dirname_malloc(*filename);
                if (!t)
                        return -ENOMEM;

                r = strv_consume(&ans, t);
                if (r < 0)
                        return r;
        }

        assert_se(strv_uniq(ans));

        r = strv_extend(&ans, "");
        if (r < 0)
                return r;

        *var = strv_join(ans, ":");
        if (!*var)
                return -ENOMEM;

        return 0;
}

static int verify_socket(Unit *u) {
        int r;

        assert(u);

        if (u->type != UNIT_SOCKET)
                return 0;

        /* Cannot run this without the service being around */

        /* This makes sure instance is created if necessary. */
        r = socket_instantiate_service(SOCKET(u));
        if (r < 0) {
                log_unit_error_errno(u, r, "Socket cannot be started, failed to create instance: %m");
                return r;
        }

        /* This checks both type of sockets */
        if (UNIT_ISSET(SOCKET(u)->service)) {
                Service *service;

                service = SERVICE(UNIT_DEREF(SOCKET(u)->service));
                log_unit_debug(u, "Using %s", UNIT(service)->id);

                if (UNIT(service)->load_state != UNIT_LOADED) {
                        log_unit_error(u, "Service %s not loaded, %s cannot be started.", UNIT(service)->id, u->id);
                        return -ENOENT;
                }
        }

        return 0;
}

static int verify_executable(Unit *u, ExecCommand *exec) {
        if (exec == NULL)
                return 0;

        if (access(exec->path, X_OK) < 0)
                return log_unit_error_errno(u, errno, "Command %s is not executable: %m", exec->path);

        return 0;
}

static int verify_executables(Unit *u) {
        ExecCommand *exec;
        int r = 0, k;
        unsigned i;

        assert(u);

        exec =  u->type == UNIT_SOCKET ? SOCKET(u)->control_command :
                u->type == UNIT_MOUNT ? MOUNT(u)->control_command :
                u->type == UNIT_SWAP ? SWAP(u)->control_command : NULL;
        k = verify_executable(u, exec);
        if (k < 0 && r == 0)
                r = k;

        if (u->type == UNIT_SERVICE)
                for (i = 0; i < ELEMENTSOF(SERVICE(u)->exec_command); i++) {
                        k = verify_executable(u, SERVICE(u)->exec_command[i]);
                        if (k < 0 && r == 0)
                                r = k;
                }

        if (u->type == UNIT_SOCKET)
                for (i = 0; i < ELEMENTSOF(SOCKET(u)->exec_command); i++) {
                        k = verify_executable(u, SOCKET(u)->exec_command[i]);
                        if (k < 0 && r == 0)
                                r = k;
                }

        return r;
}

static int verify_documentation(Unit *u, bool check_man) {
        char **p;
        int r = 0, k;

        STRV_FOREACH(p, u->documentation) {
                log_unit_debug(u, "Found documentation item: %s", *p);

                if (check_man && startswith(*p, "man:")) {
                        k = show_man_page(*p + 4, true);
                        if (k != 0) {
                                if (k < 0)
                                        log_unit_error_errno(u, r, "Can't show %s: %m", *p);
                                else {
                                        log_unit_error_errno(u, r, "man %s command failed with code %d", *p + 4, k);
                                        k = -ENOEXEC;
                                }
                                if (r == 0)
                                        r = k;
                        }
                }
        }

        /* Check remote URLs? */

        return r;
}

static int verify_unit(Unit *u, bool check_man) {
        _cleanup_bus_error_free_ sd_bus_error err = SD_BUS_ERROR_NULL;
        int r, k;

        assert(u);

        if (log_get_max_level() >= LOG_DEBUG)
                unit_dump(u, stdout, "\t");

        log_unit_debug(u, "Creating %s/start job", u->id);
        r = manager_add_job(u->manager, JOB_START, u, JOB_REPLACE, &err, NULL);
        if (r < 0)
                log_unit_error_errno(u, r, "Failed to create %s/start: %s", u->id, bus_error_message(&err, r));

        k = verify_socket(u);
        if (k < 0 && r == 0)
                r = k;

        k = verify_executables(u);
        if (k < 0 && r == 0)
                r = k;

        k = verify_documentation(u, check_man);
        if (k < 0 && r == 0)
                r = k;

        return r;
}

int verify_units(char **filenames, ManagerRunningAs running_as, bool check_man) {
        _cleanup_bus_error_free_ sd_bus_error err = SD_BUS_ERROR_NULL;
        Manager *m = NULL;
        FILE *serial = NULL;
        FDSet *fdset = NULL;

        _cleanup_free_ char *var = NULL;

        char **filename;
        int r = 0, k;

        Unit *units[strv_length(filenames)];
        int i, count = 0;

        if (strv_isempty(filenames))
                return 0;

        /* set the path */
        r = generate_path(&var, filenames);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit load path: %m");

        assert_se(set_unit_path(var) >= 0);

        r = manager_new(running_as, true, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");

        r = manager_startup(m, serial, fdset);
        if (r < 0) {
                log_error_errno(r, "Failed to start manager: %m");
                goto finish;
        }

        manager_clear_jobs(m);

        log_debug("Loading remaining units from the command line...");

        STRV_FOREACH(filename, filenames) {
                char fname[UNIT_NAME_MAX + 2 + 1] = "./";

                log_debug("Handling %s...", *filename);

                /* manager_load_unit does not like pure basenames, so prepend
                 * the local directory, but only for valid names. manager_load_unit
                 * will print the error for other ones. */
                if (!strchr(*filename, '/') && strlen(*filename) <= UNIT_NAME_MAX) {
                        strncat(fname + 2, *filename, UNIT_NAME_MAX);
                        k = manager_load_unit(m, NULL, fname, &err, &units[count]);
                } else
                        k = manager_load_unit(m, NULL, *filename, &err, &units[count]);
                if (k < 0) {
                        log_error_errno(k, "Failed to load %s: %m", *filename);
                        if (r == 0)
                                r = k;
                } else
                        count ++;
        }

        for (i = 0; i < count; i++) {
                k = verify_unit(units[i], check_man);
                if (k < 0 && r == 0)
                        r = k;
        }

finish:
        manager_free(m);

        return r;
}
