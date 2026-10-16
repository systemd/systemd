/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-event.h"

#include "log.h"
#include "main-func.h"
#include "resolved-dummy-server-test-util.h"

static int run(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dummy_server_freep) DummyServer *server = NULL;
        int r;

        log_setup();

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes one argument in format ip_address:port");

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event: %m");

        r = dummy_server_new(event, argv[1], &server);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        (void) sd_notify(/* unset_environment=false */ false, "READY=1");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
