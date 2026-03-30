/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "set.h"
#include "varlink-io.systemd.VMControl.h"
#include "varlink-util.h"
#include "vmspawn-qmp.h"

struct VmspawnQmpContext {
        /* The dynamic interface must be declared (and thus freed) after the varlink server, because
         * sd_varlink_server_add_interface() stores a bare pointer. Struct fields are freed in the order
         * specified in vmspawn_qmp_context_free(), where we explicitly free the server first. */
        sd_varlink_interface *qemu_interface;
        sd_varlink_server *varlink_server;
        QmpClient *qmp_client;
        Set *subscribed;
        Hashmap *qmp_command_names;
};

static int qmp_execute_simple(sd_varlink *link, VmspawnQmpContext *ctx, const char *qmp_command) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(link);
        assert(ctx);
        assert(qmp_command);

        r = qmp_client_execute(ctx->qmp_client, qmp_command, /* arguments= */ NULL, /* ret_result= */ NULL, &error_class);
        if (ERRNO_IS_NEG_DISCONNECT(r))
                return sd_varlink_error(link, "io.systemd.VMControl.NotConnected", NULL);
        if (r == -EIO)
                return sd_varlink_error(link, "io.systemd.VMControl.NotSupported", NULL);
        if (r < 0)
                return sd_varlink_error_errno(link, r);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple(link, ASSERT_PTR(userdata), "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple(link, ASSERT_PTR(userdata), "cont");
}

static int vl_method_powerdown(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple(link, ASSERT_PTR(userdata), "system_powerdown");
}

static int vl_method_reset(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple(link, ASSERT_PTR(userdata), "system_reset");
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = qmp_client_execute(ctx->qmp_client, "query-status", /* arguments= */ NULL, &result, &error_class);
        if (ERRNO_IS_NEG_DISCONNECT(r))
                return sd_varlink_error(link, "io.systemd.VMControl.NotConnected", NULL);
        if (r == -EIO)
                return sd_varlink_error(link, "io.systemd.VMControl.NotSupported", NULL);
        if (r < 0)
                return sd_varlink_error_errno(link, r);

        sd_json_variant *running = sd_json_variant_by_key(result, "running");
        sd_json_variant *status = sd_json_variant_by_key(result, "status");

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running ? sd_json_variant_boolean(running) : false),
                        SD_JSON_BUILD_PAIR_STRING("status", status ? sd_json_variant_string(status) : "unknown"));
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.VMControl.NotSupported", NULL);
}

int vmspawn_qmp_setup(VmspawnQmpContext **ret, int _qmp_fd, sd_event *event, const char *runtime_dir, char **ret_varlink_address) {
        _cleanup_(vmspawn_qmp_context_freep) VmspawnQmpContext *ctx = NULL;
        _cleanup_close_ int fd = TAKE_FD(_qmp_fd);
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);
        assert_return(runtime_dir, -EINVAL);

        ctx = new(VmspawnQmpContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (VmspawnQmpContext) {};

        /* Phase 1: blocking QMP handshake */
        r = qmp_client_connect_fd(&ctx->qmp_client, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                               ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to create varlink server: %m");

        r = sd_varlink_server_add_interface(ctx->varlink_server, &vl_interface_io_systemd_VMControl);
        if (r < 0)
                return log_error_errno(r, "Failed to add VMControl interface: %m");

        r = sd_varlink_server_bind_method_many(
                        ctx->varlink_server,
                        "io.systemd.VMControl.Pause",           vl_method_pause,
                        "io.systemd.VMControl.Resume",          vl_method_resume,
                        "io.systemd.VMControl.Powerdown",       vl_method_powerdown,
                        "io.systemd.VMControl.Reset",           vl_method_reset,
                        "io.systemd.VMControl.QueryStatus",     vl_method_query_status,
                        "io.systemd.VMControl.SubscribeEvents", vl_method_subscribe_events);
        if (r < 0)
                return log_error_errno(r, "Failed to bind VMControl methods: %m");

        listen_address = path_join(runtime_dir, "io.systemd.VMControl");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        log_debug("QMP varlink server listening on %s", listen_address);

        if (ret_varlink_address)
                *ret_varlink_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx) {
        if (!ctx)
                return NULL;

        /* Free the varlink server before the dynamic interface, since the server stores bare pointers to
         * interfaces added via sd_varlink_server_add_interface(). */
        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->qemu_interface = sd_varlink_interface_free(ctx->qemu_interface);
        ctx->qmp_client = qmp_client_free(ctx->qmp_client);
        set_free(ctx->subscribed);
        hashmap_free(ctx->qmp_command_names);

        return mfree(ctx);
}
