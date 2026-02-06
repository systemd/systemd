/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "coredump-config.h"
#include "coredump-container.h"
#include "coredump-context.h"
#include "coredump-socket.h"
#include "coredump-submit.h"
#include "coredump-util.h"
#include "log.h"
#include "namespace-util.h"
#include "time-util.h"
#include "varlink-io.systemd.Coredump.Container.h"
#include "varlink-util.h"

static int vl_method_transfer_coredump(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        CoredumpConfig *config = ASSERT_PTR(userdata);
        struct {
                unsigned coredump_fd_index;
                usec_t timestamp;
        } p = {
                .timestamp = USEC_INFINITY,
        };
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "coredumpFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,    voffsetof(p, coredump_fd_index),  SD_JSON_MANDATORY },
                { "timestamp",              _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,  voffsetof(p, timestamp),          0                 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        context.forwarded = true;

        /* If we are in a non-initial time namespace, ignore the received timestamp. */
        if (!timestamp_is_set(p.timestamp) || namespace_is_init(NAMESPACE_TIME) == 0) {
                r = sd_event_now(sd_varlink_get_event(link), CLOCK_REALTIME, &context.timestamp);
                if (r < 0)
                        return log_error_errno(r, "Failed to get the current time: %m");
        } else
                context.timestamp = p.timestamp;

        r = sd_varlink_take_fd(link, p.coredump_fd_index);
        if (r < 0)
                return log_error_errno(r, "Failed to take file descriptor of the coredump socket: %m");
        context.input_fd = r;

        r = coredump_context_parse_from_peer(&context);
        if (r < 0)
                return r;

        if (!coredump_context_is_journald(&context))
                log_set_target_and_open(LOG_TARGET_JOURNAL_OR_KMSG);

        r = coredump_process_socket(&context);
        if (r < 0)
                goto finalize;

        r = coredump_submit(config, &context);
        if (r < 0)
                goto finalize;

        r = sd_varlink_reply(link, /* parameters= */ NULL);

finalize:
        /* Reopen kmsg for later calls. */
        log_set_target_and_open(LOG_TARGET_KMSG);

        return r;
}

int coredump_container(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_set_target_and_open(LOG_TARGET_KMSG);

        /* Make sure we never enter a loop. */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        /* Ignore all parse errors. */
        CoredumpConfig config = COREDUMP_CONFIG_NULL;
        (void) coredump_parse_config(&config);

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY |
                        SD_VARLINK_SERVER_INHERIT_USERDATA |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
                        &config);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_CoredumpContainer);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Coredump.Container.Transfer", vl_method_transfer_coredump);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
