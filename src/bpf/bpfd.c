/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "daemon-util.h"
#include "bpfd-manager.h"
#include "main-func.h"
#include "log.h"

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        int r;

        log_setup();

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_start(m);
        if (r < 0)
                return log_error_errno(r, "Failed to start up daemon: %m");

        notify_stop = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        log_debug("systemd-bpfd started");

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
