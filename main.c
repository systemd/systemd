/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

        if (!(m = manager_new()) < 0) {
                log_error("Failed to allocate manager object: %s", strerror(ENOMEM));
                goto finish;
        }

        if ((r = manager_load_unit(m, "default.target", &target)) < 0) {
                log_error("Failed to load default target: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_add_job(m, JOB_START, target, JOB_REPLACE, false, &job)) < 0) {
                log_error("Failed to start default target: %s", strerror(-r));
                goto finish;
        }

        printf("→ By units:\n");
        manager_dump_units(m, stdout, "\t");

        printf("→ By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");

        /* manager_loop(m); */

        retval = 0;

finish:
        if (m)
                manager_free(m);

        return retval;
}
