/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "manager.h"
#include "log.h"

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        Name *milestone = NULL, *syslog = NULL;
        Job *job = NULL;
        int r, retval = 1;

        assert_se(chdir("test1") == 0);

        if (!(m = manager_new()) < 0) {
                log_error("Failed to allocate manager object: %s", strerror(ENOMEM));
                goto finish;
        }

        if ((r = manager_load_name(m, "default.milestone", &milestone)) < 0) {
                log_error("Failed to load default milestone: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_load_name(m, "syslog.socket", &syslog)) < 0) {
                log_error("Failed to load syslog socket: %s", strerror(-r));
                goto finish;
        }

        if ((r = manager_add_job(m, JOB_START, milestone, JOB_REPLACE, false, &job)) < 0) {
                log_error("Failed to start default milestone: %s", strerror(-r));
                goto finish;
        }

        printf("- By names:\n");
        manager_dump_names(m, stdout, "\t");

        printf("- By jobs:\n");
        manager_dump_jobs(m, stdout, "\t");

        manager_run_jobs(m);

        retval = 0;

finish:
        if (m)
                manager_free(m);

        return retval;
}
