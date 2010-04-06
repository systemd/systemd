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

#include <dbus/dbus.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "manager.h"
#include "log.h"
#include "mount-setup.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Unit *target = NULL;
        Job *job = NULL;
        int r, retval = 1;
        const char *default_unit;

        if (argc >= 2)
                default_unit = argv[1];
        else
                default_unit = SPECIAL_DEFAULT_TARGET;

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/")  == 0);

        /* Reset all signal handlers. */
        assert_se(reset_all_signal_handlers() == 0);

        /* Become a session leader if we aren't one yet. */
        setsid();

        /* Disable the umask logic */
        umask(0);

        /* Make sure D-Bus doesn't fiddle with the SIGPIPE handlers */
        dbus_connection_set_change_sigpipe(FALSE);

        /* Mount /dev, /sys and friends */
        mount_setup();

        /* Set up logging */
        log_set_target(LOG_TARGET_CONSOLE);

        /* Open the logging devices, if possible and necessary*/
        log_open_syslog();
        log_open_kmsg();

        if ((r = manager_new(&m)) < 0) {
                log_error("Failed to allocate manager object: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_coldplug(m)) < 0) {
                log_error("Failed to retrieve coldplug information: %s", strerror(-r));
                goto finish;
        }

        log_debug("Activating default unit: %s", default_unit);

        if ((r = manager_load_unit(m, default_unit, &target)) < 0) {
                log_error("Failed to load default target: %s", strerror(-r));
                goto finish;
        }

        printf("→ By units:\n");
        manager_dump_units(m, stdout, "\t");

        if ((r = manager_add_job(m, JOB_START, target, JOB_REPLACE, false, &job)) < 0) {
                log_error("Failed to start default target: %s", strerror(-r));
                goto finish;
        }

        printf("→ By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");

        if ((r = manager_loop(m)) < 0) {
                log_error("Failed to run mainloop: %s", strerror(-r));
                goto finish;
        }

        retval = 0;

finish:
        if (m)
                manager_free(m);

        log_debug("Exit.");

        dbus_shutdown();

        return retval;
}
