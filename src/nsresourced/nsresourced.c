/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>

#include "sd-event.h"

#include "daemon-util.h"
#include "log.h"
#include "main-func.h"
#include "nsresourced-manager.h"
#include "verbs.h"

COMMAND(
        "systemd-nsresourced\0",
        "Delegate user namespace resources to unprivileged clients.",
        .man_pages = "systemd-nsresourced.service(8)\0",
        .option_namespace = "common",
);

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup();

        umask(0022);

        r = common_parse_argv_full(argc, argv, /* min_args= */ 0, /* max_args= */ 0, /* ret_args= */ NULL);
        if (r <= 0)
                return r;

        if (setenv("SYSTEMD_BYPASS_USERDB", "io.systemd.NamespaceResource", 1) < 0)
                return log_error_errno(errno, "Failed to set $SYSTEMD_BYPASS_USERDB: %m");

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        notify_stop = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
