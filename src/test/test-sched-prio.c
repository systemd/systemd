/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Holger Hans Peter Freyther

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

#include <sched.h>

#include "macro.h"
#include "manager.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Unit *idle_ok, *idle_bad, *rr_ok, *rr_bad, *rr_sched;
        Service *ser;
        FILE *serial = NULL;
        FDSet *fdset = NULL;
        int r;

        /* prepare the test */
        assert_se(set_unit_path(TEST_DIR) >= 0);
        r = manager_new(MANAGER_USER, true, &m);
        if (IN_SET(r, -EPERM, -EACCES, -EADDRINUSE, -EHOSTDOWN, -ENOENT, -ENOEXEC)) {
                printf("Skipping test: manager_new: %s", strerror(-r));
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);
        assert_se(manager_startup(m, serial, fdset) >= 0);

        /* load idle ok */
        assert_se(manager_load_unit(m, "sched_idle_ok.service", NULL, NULL, &idle_ok) >= 0);
        assert_se(idle_ok->load_state == UNIT_LOADED);
        ser = SERVICE(idle_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_OTHER);
        assert_se(ser->exec_context.cpu_sched_priority == 0);

        /*
         * load idle bad. This should print a warning but we have no way to look at it.
         */
        assert_se(manager_load_unit(m, "sched_idle_bad.service", NULL, NULL, &idle_bad) >= 0);
        assert_se(idle_bad->load_state == UNIT_LOADED);
        ser = SERVICE(idle_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_OTHER);
        assert_se(ser->exec_context.cpu_sched_priority == 0);

        /*
         * load rr ok.
         * Test that the default priority is moving from 0 to 1.
         */
        assert_se(manager_load_unit(m, "sched_rr_ok.service", NULL, NULL, &rr_ok) >= 0);
        assert_se(rr_ok->load_state == UNIT_LOADED);
        ser = SERVICE(rr_ok);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 1);

        /*
         * load rr bad.
         * Test that the value of 0 and 100 is ignored.
         */
        assert_se(manager_load_unit(m, "sched_rr_bad.service", NULL, NULL, &rr_bad) >= 0);
        assert_se(rr_bad->load_state == UNIT_LOADED);
        ser = SERVICE(rr_bad);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 1);

        /*
         * load rr change.
         * Test that anything between 1 and 99 can be set.
         */
        assert_se(manager_load_unit(m, "sched_rr_change.service", NULL, NULL, &rr_sched) >= 0);
        assert_se(rr_sched->load_state == UNIT_LOADED);
        ser = SERVICE(rr_sched);
        assert_se(ser->exec_context.cpu_sched_policy == SCHED_RR);
        assert_se(ser->exec_context.cpu_sched_priority == 99);

        manager_free(m);

        return EXIT_SUCCESS;
}
