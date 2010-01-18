/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "manager.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Name *milestone = NULL;
        Job *job = NULL;
        int r, retval = 1;

        if (!(m = manager_new()) < 0) {
                fprintf(stderr, "Failed to allocate manager object: %s\n", strerror(ENOMEM));
                goto finish;
        }


        if ((r = manager_load_name(m, "default.milestone", &milestone) < 0)) {
                fprintf(stderr, "Failed to load default milestone: %s\n", strerror(-r));
                goto finish;
        }

        manager_dump_names(m, stdout);

        /* if ((r = manager_add_job(m, JOB_START, milestone, JOB_REPLACE, &job)) < 0) { */
        /*         fprintf(stderr, "Failed to start default milestone: %s\n", strerror(-r)); */
        /*         goto finish; */
        /* } */

        retval = 0;

finish:
        if (m)
                manager_free(m);

        return retval;
}
