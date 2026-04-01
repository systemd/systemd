/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-polkit.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "set.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-qmp.h"

struct VmspawnQmpContext {
        sd_varlink_server *varlink_server;
        QmpClient *qmp_client;
        Set *subscribed;
        Hashmap *polkit_registry;
        RuntimeScope runtime_scope;
        uid_t owner_uid;
};

static int vmspawn_verify_polkit(sd_varlink *link, VmspawnQmpContext *ctx, const char *verb) {
        assert(link);
        assert(ctx);

        if (ctx->runtime_scope == RUNTIME_SCOPE_USER)
                return 1; /* User scope: always authorized */

        return varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL, /* auto-opens system bus */
                        "org.freedesktop.machine1.manage-machines",
                        (const char**) STRV_MAKE("verb", verb),
                        ctx->owner_uid,
                        /* flags= */ 0,
                        &ctx->polkit_registry);
}

/* Translate a QMP async completion into a varlink error reply */
static void qmp_error_to_varlink(sd_varlink *link, const char *error_class, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error) || error == -ENOTCONN)
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        else if (error == -EIO && streq_ptr(error_class, "CommandNotFound"))
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
        else {
                if (error == -EIO)
                        log_warning("QMP command failed with error class '%s'", strna(error_class));
                (void) sd_varlink_error_errno(link, error);
        }
}

/* Shared async completion for simple QMP commands that return no data */
static void on_qmp_simple_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        if (error == 0)
                (void) sd_varlink_reply(link, NULL);
        else
                qmp_error_to_varlink(link, error_class, error);

        sd_varlink_unref(link);
}

static int qmp_execute_simple_async(sd_varlink *link, VmspawnQmpContext *ctx, const char *qmp_command) {
        int r;

        assert(link);
        assert(ctx);
        assert(qmp_command);

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->qmp_client, qmp_command, /* arguments= */ NULL, on_qmp_simple_complete, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        return 0; /* Reply deferred to callback */
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "terminate");
        if (r <= 0)
                return r;

        return qmp_execute_simple_async(link, ctx, "quit");
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "pause");
        if (r <= 0)
                return r;

        return qmp_execute_simple_async(link, ctx, "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "resume");
        if (r <= 0)
                return r;

        return qmp_execute_simple_async(link, ctx, "cont");
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "power_off");
        if (r <= 0)
                return r;

        return qmp_execute_simple_async(link, ctx, "system_powerdown");
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "reboot");
        if (r <= 0)
                return r;

        return qmp_execute_simple_async(link, ctx, "system_reset");
}

/* Async completion for query-status: extract running/status from QMP result */
static void on_qmp_query_status_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        if (error != 0) {
                qmp_error_to_varlink(link, error_class, error);
                sd_varlink_unref(link);
                return;
        }

        sd_json_variant *running = sd_json_variant_by_key(result, "running");
        sd_json_variant *status = sd_json_variant_by_key(result, "status");

        (void) sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running ? sd_json_variant_boolean(running) : false),
                        SD_JSON_BUILD_PAIR_STRING("status", status ? sd_json_variant_string(status) : "unknown"));

        sd_varlink_unref(link);
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "query_status");
        if (r <= 0)
                return r;

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->qmp_client, "query-status", /* arguments= */ NULL, on_qmp_query_status_complete, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        return 0;
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "subscribe_events");
        if (r <= 0)
                return r;

        /* SD_VARLINK_REQUIRES_MORE in the IDL rejects non-streaming callers before we get here */

        r = set_ensure_put(&ctx->subscribed, &varlink_hash_ops, link);
        if (r < 0)
                return r;

        sd_varlink_ref(link);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("ready", true));
        if (r < 0) {
                sd_varlink_unref(set_remove(ctx->subscribed, link));
                return 0; /* Let the connection hang until the disconnect handler cleans it up */
        }

        return 0;
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = vmspawn_verify_polkit(link, ctx, "acquire_qmp");
        if (r <= 0)
                return r;

        return sd_varlink_error_errno(link, -EOPNOTSUPP);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        sd_varlink *removed;

        assert(server);
        assert(link);

        removed = set_remove(ctx->subscribed, link);
        if (removed)
                sd_varlink_unref(removed);
}

static void on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                uint64_t timestamp_seconds,
                uint64_t timestamp_microseconds,
                void *userdata) {

        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(client);
        assert(event);

        r = varlink_many_notifybo(
                        ctx->subscribed,
                        SD_JSON_BUILD_PAIR_STRING("event", event),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("timestampUSec", timestamp_seconds * USEC_PER_SEC + timestamp_microseconds));
        if (r < 0)
                log_warning_errno(r, "Failed to notify event subscribers, ignoring: %m");
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(client);

        log_debug("QMP connection lost");

        r = varlink_many_error(ctx->subscribed, "io.systemd.MachineInstance.NotConnected", NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to send disconnect error to subscribers, ignoring: %m");

        ctx->subscribed = set_free(ctx->subscribed);
}

int vmspawn_qmp_setup(VmspawnQmpContext **ret, int _qmp_fd, sd_event *event, const char *runtime_dir, RuntimeScope runtime_scope, uid_t owner_uid, char **ret_varlink_address) {
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

        *ctx = (VmspawnQmpContext) {
                .runtime_scope = runtime_scope,
                .owner_uid = owner_uid,
        };

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

        r = sd_varlink_server_add_interface_many(
                        ctx->varlink_server,
                        &vl_interface_io_systemd_MachineInstance,
                        &vl_interface_io_systemd_VirtualMachineInstance,
                        &vl_interface_io_systemd_QemuMachineInstance);
        if (r < 0)
                return log_error_errno(r, "Failed to add varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        ctx->varlink_server,
                        "io.systemd.MachineInstance.Terminate",        vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",        vl_method_power_off,
                        "io.systemd.MachineInstance.Pause",           vl_method_pause,
                        "io.systemd.MachineInstance.Resume",          vl_method_resume,
                        "io.systemd.MachineInstance.Reboot",           vl_method_reboot,
                        "io.systemd.MachineInstance.QueryStatus",     vl_method_query_status,
                        "io.systemd.MachineInstance.SubscribeEvents", vl_method_subscribe_events,
                        "io.systemd.QemuMachineInstance.AcquireQMP",    vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(ctx->varlink_server, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect handler: %m");

        listen_address = path_join(runtime_dir, "io.systemd.MachineInstance");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        qmp_client_set_event_callback(ctx->qmp_client, on_qmp_event, ctx);
        qmp_client_set_disconnect_callback(ctx->qmp_client, on_qmp_disconnect, ctx);

        log_debug("QMP varlink server listening on %s", listen_address);

        if (ret_varlink_address)
                *ret_varlink_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx) {
        if (!ctx)
                return NULL;

        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->qmp_client = qmp_client_free(ctx->qmp_client);
        set_free(ctx->subscribed);
        hashmap_free(ctx->polkit_registry);

        return mfree(ctx);
}
