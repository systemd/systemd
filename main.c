/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "manager.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Name *milestone = NULL, *syslog = NULL;
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

        if ((r = manager_load_name(m, "syslog.socket", &syslog) < 0)) {
                fprintf(stderr, "Failed to load syslog socket: %s\n", strerror(-r));
                goto finish;
        }

        if ((r = manager_add_job(m, JOB_START, milestone, JOB_REPLACE, false, &job)) < 0) {
                fprintf(stderr, "Failed to start default milestone: %s\n", strerror(-r));
                goto finish;
        }

        printf("- By names:\n");
        manager_dump_names(m, stdout, "\t");

        printf("- By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");

        if ((r = manager_add_job(m, JOB_STOP, syslog, JOB_REPLACE, false, &job)) < 0) {
                fprintf(stderr, "Failed to start default milestone: %s\n", strerror(-r));
                goto finish;
        }

        printf("- By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");

        retval = 0;

finish:
        if (m)
                manager_free(m);

        return retval;
}
