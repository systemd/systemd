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
#include <getopt.h>

#include "manager.h"
#include "bus-util.h"
#include "log.h"
#include "strv.h"
#include "build.h"
#include "pager.h"

SystemdRunningAs arg_running_as = SYSTEMD_SYSTEM;
bool arg_no_man = false;

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
                log_error_unit(u->id, "Socket %s cannot be started, failed to create instance.",
                               u->id);
                return r;
        }

        /* This checks both type of sockets */
        if (UNIT_ISSET(SOCKET(u)->service)) {
                Service *service;

                service = SERVICE(UNIT_DEREF(SOCKET(u)->service));
                log_debug_unit(u->id, "%s uses %s", u->id, UNIT(service)->id);

                if (UNIT(service)->load_state != UNIT_LOADED) {
                        log_error_unit(u->id, "Service %s not loaded, %s cannot be started.",
                                       UNIT(service)->id, u->id);
                        return -ENOENT;
                }
        }

        return 0;
}

static int verify_executable(Unit *u, ExecCommand *exec) {
        if (exec == NULL)
                return 0;

        if (access(exec->path, X_OK) < 0) {
                log_error_unit(u->id, "%s: command %s is not executable: %m",
                               u->id, exec->path);
                return -errno;
        }

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

static int verify_documentation(Unit *u) {
        char **p;
        int r = 0, k;

        if (arg_no_man)
                return 0;

        STRV_FOREACH(p, u->documentation) {
                log_debug_unit(u->id, "%s: found documentation item %s.", u->id, *p);
                if (startswith(*p, "man:")) {
                        k = show_man_page(*p + 4, true);
                        if (k != 0) {
                                if (k < 0)
                                        log_error_unit(u->id, "%s: can't show %s: %s",
                                                       u->id, *p, strerror(-r));
                                else {
                                        log_error_unit(u->id, "%s: man %s command failed with code %d",
                                                       u->id, *p + 4, k);
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

static int test_unit(Unit *u) {
        _cleanup_bus_error_free_ sd_bus_error err = SD_BUS_ERROR_NULL;
        Job *j;
        int r, k;

        assert(u);

        if (log_get_max_level() >= LOG_DEBUG)
                unit_dump(u, stdout, "\t");

        log_debug_unit(u->id, "Creating %s/start job", u->id);
        r = manager_add_job(u->manager, JOB_START, u, JOB_REPLACE, false, &err, &j);
        if (sd_bus_error_is_set(&err))
                log_error_unit(u->id, "Error: %s: %s",
                               err.name, err.message);
        if (r < 0)
                log_error_unit(u->id, "Failed to create %s/start: %s",
                               u->id, strerror(-r));

        k = verify_socket(u);
        if (k < 0 && r == 0)
                r = k;

        k = verify_executables(u);
        if (k < 0 && r == 0)
                r = k;

        k = verify_documentation(u);
        if (k < 0 && r == 0)
                r = k;

        return r;
}

static int test_units(char **filenames) {
        _cleanup_bus_error_free_ sd_bus_error err = SD_BUS_ERROR_NULL;
        Manager *m = NULL;
        FILE *serial = NULL;
        FDSet *fdset = NULL;

        _cleanup_free_ char *var;

        char **filename;
        int r = 0, k;

        Unit *units[strv_length(filenames)];
        int i, count = 0;

        /* set the path */
        r = generate_path(&var, filenames);
        if (r < 0) {
                log_error("Failed to generate unit load path: %s", strerror(-r));
                return r;
        }

        assert_se(set_unit_path(var) >= 0);

        r = manager_new(arg_running_as, true, &m);
        if (r < 0) {
                log_error("Failed to initalize manager: %s", strerror(-r));
                return r;
        }

        log_debug("Starting manager...");

        r = manager_startup(m, serial, fdset);
        if (r < 0) {
                log_error("Failed to start manager: %s", strerror(-r));
                goto finish;
        }

        manager_clear_jobs(m);

        log_debug("Loading remaining units from the command line...");

        STRV_FOREACH(filename, filenames) {
                log_debug("Handling %s...", *filename);

                k = manager_load_unit(m, NULL, *filename, &err, &units[count]);
                if (k < 0) {
                        log_error("Failed to load %s: %s", *filename, strerror(-r));
                        if (r == 0)
                                r = k;
                }

                count ++;
        }

        for (i = 0; i < count; i++) {
                k = test_unit(units[i]);
                if (k < 0 && r == 0)
                        r = k;
        }

finish:
        manager_free(m);

        return r;
}

static void help(void) {
        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Check if unit files can be correctly loaded.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --system         Connect to system manager\n"
               "     --user           Connect to user service manager\n"
               "     --no-man         Do not check for existence of man pages\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_USER,
                ARG_SYSTEM,
                ARG_NO_MAN,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                { "user",                no_argument,       NULL, ARG_USER                },
                { "system",              no_argument,       NULL, ARG_SYSTEM              },
                {}
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        opterr = 0;

        while ((c = getopt_long(argc, argv, ":h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_running_as = SYSTEMD_USER;
                        break;

                case ARG_SYSTEM:
                        arg_running_as = SYSTEMD_SYSTEM;
                        break;

                case ARG_NO_MAN:
                        arg_no_man = true;
                        break;

                case '?':
                        log_error("Unknown option %s.", argv[optind-1]);
                        return -EINVAL;

                case ':':
                        log_error("Missing argument to %s.", argv[optind-1]);
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        return 1; /* work to do */
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = test_units(argv + optind);

finish:
        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
