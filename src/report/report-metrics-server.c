/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "log.h"
#include "main-func.h"
#include "metrics.h"
#include "report-metrics.h"

static int run(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        int r;

        log_setup();

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        r = metrics_setup_varlink_server(
                        &server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        event,
                        SD_EVENT_PRIORITY_NORMAL,
                        vl_method_list_metrics,
                        vl_method_describe_metrics,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set up varlink server: %m");

        r = sd_varlink_server_listen_auto(server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
