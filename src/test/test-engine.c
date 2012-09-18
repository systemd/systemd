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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "manager.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Unit *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *g = NULL, *h = NULL;
        Job *j;

        assert_se(set_unit_path("test") >= 0);

        assert_se(manager_new(SYSTEMD_SYSTEM, &m) >= 0);

        printf("Load1:\n");
        assert_se(manager_load_unit(m, "a.service", NULL, NULL, &a) >= 0);
        assert_se(manager_load_unit(m, "b.service", NULL, NULL, &b) >= 0);
        assert_se(manager_load_unit(m, "c.service", NULL, NULL, &c) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test1: (Trivial)\n");
        assert_se(manager_add_job(m, JOB_START, c, JOB_REPLACE, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load2:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_unit(m, "d.service", NULL, NULL, &d) >= 0);
        assert_se(manager_load_unit(m, "e.service", NULL, NULL, &e) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test2: (Cyclic Order, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, d, JOB_REPLACE, false, NULL, &j) == -ENOEXEC);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test3: (Cyclic Order, Fixable, Garbage Collector)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_REPLACE, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test4: (Identical transaction)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_FAIL, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load3:\n");
        assert_se(manager_load_unit(m, "g.service", NULL, NULL, &g) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test5: (Colliding transaction, fail)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_FAIL, false, NULL, &j) == -EEXIST);

        printf("Test6: (Colliding transaction, replace)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_REPLACE, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test7: (Unmergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_FAIL, false, NULL, &j) == -EEXIST);

        printf("Test8: (Mergeable job type, fail)\n");
        assert_se(manager_add_job(m, JOB_RESTART, g, JOB_FAIL, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test9: (Unmergeable job type, replace)\n");
        assert_se(manager_add_job(m, JOB_STOP, g, JOB_REPLACE, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Load4:\n");
        assert_se(manager_load_unit(m, "h.service", NULL, NULL, &h) >= 0);
        manager_dump_units(m, stdout, "\t");

        printf("Test10: (Unmergeable job type of auxiliary job, fail)\n");
        assert_se(manager_add_job(m, JOB_START, h, JOB_FAIL, false, NULL, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        manager_free(m);

        return 0;
}
