/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "manager.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Name *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *g = NULL;
        Job *j;

        assert_se(chdir("test2") == 0);

        assert_se(m = manager_new());

        printf("Loaded1:\n");
        assert_se(manager_load_name(m, "a.service", &a) == 0);
        assert_se(manager_load_name(m, "b.service", &b) == 0);
        assert_se(manager_load_name(m, "c.service", &c) == 0);
        manager_dump_names(m, stdout, "\t");

        printf("Test1: (Trivial)\n");
        assert_se(manager_add_job(m, JOB_START, c, JOB_REPLACE, false, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Loaded2:\n");
        manager_clear_jobs(m);
        assert_se(manager_load_name(m, "d.service", &d) == 0);
        assert_se(manager_load_name(m, "e.service", &e) == 0);
        manager_dump_names(m, stdout, "\t");

        printf("Test2: (Cyclic Order, Unfixable)\n");
        assert_se(manager_add_job(m, JOB_START, d, JOB_REPLACE, false, &j) == -ENOEXEC);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test3: (Cyclic Order, Fixable, Garbage Collector)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_REPLACE, false, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Test4: (Identical transaction)\n");
        assert_se(manager_add_job(m, JOB_START, e, JOB_FAIL, false, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        printf("Loaded3:\n");
        assert_se(manager_load_name(m, "g.service", &g) == 0);
        manager_dump_names(m, stdout, "\t");

        printf("Test5: (Colliding transaction, fail)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_FAIL, false, &j) == -EEXIST);

        printf("Test6: (Colliding transaction, replace)\n");
        assert_se(manager_add_job(m, JOB_START, g, JOB_REPLACE, false, &j) == 0);
        manager_dump_jobs(m, stdout, "\t");

        manager_free(m);

        return 0;
}
