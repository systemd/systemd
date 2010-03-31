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

#include "manager.h"
#include "log.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Unit *target = NULL;
        Job *job = NULL;
        int r, retval = 1;

        assert_se(set_unit_path("test1") >= 0);

        if ((r = manager_new(&m)) < 0) {
                log_error("Failed to allocate manager object: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_coldplug(m)) < 0) {
                log_error("Failed to retrieve coldplug information: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_load_unit(m, SPECIAL_DEFAULT_TARGET, &target)) < 0) {
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
