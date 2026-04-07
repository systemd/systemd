/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-varlink.h"

struct VmspawnQmpBridge {
        QmpClient *qmp;
};

VmspawnQmpBridge *vmspawn_qmp_bridge_free(VmspawnQmpBridge *b) {
        if (!b)
                return NULL;

        qmp_client_free(b->qmp);
        return mfree(b);
}

QmpClient *vmspawn_qmp_bridge_get_qmp(VmspawnQmpBridge *b) {
        assert(b);
        return b->qmp;
}

static void varlink_close_unref(sd_varlink *v) {
        sd_varlink_close(v);
        sd_varlink_unref(v);
}

DEFINE_HASH_OPS_FULL(
                varlink_subscriber_hash_ops,
                void, trivial_hash_func, trivial_compare_func, varlink_close_unref,
                char*, strv_free);

struct VmspawnVarlinkContext {
        sd_varlink_server *varlink_server;
        VmspawnQmpBridge *bridge;
        /* Key: sd_varlink* (ref'd), Value: strv filter (NULL = all events).
         * varlink_subscriber_hash_ops handles cleanup of both on removal. */
        Hashmap *subscribed;
};

/* Translate a QMP async completion into a varlink error reply */
static int qmp_error_to_varlink(sd_varlink *link, const char *error_class, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        if (error == -EIO && streq_ptr(error_class, "CommandNotFound"))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
        if (error == -EIO)
                log_warning("Command failed with error class '%s'", strna(error_class));
        return sd_varlink_error_errno(link, error);
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
                (void) qmp_error_to_varlink(link, error_class, error);

        sd_varlink_unref(link);
}

static int qmp_execute_varlink_async(
                VmspawnVarlinkContext *ctx,
                sd_varlink *link,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback) {

        int r;

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->bridge->qmp, command, arguments, callback, link);
        if (r < 0)
                sd_varlink_unref(link);

        return r;
}

static int qmp_execute_simple_async(sd_varlink *link, VmspawnVarlinkContext *ctx, const char *qmp_command) {
        assert(link);
        assert(ctx);
        assert(qmp_command);

        return qmp_execute_varlink_async(ctx, link, qmp_command, /* arguments= */ NULL, on_qmp_simple_complete);
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "quit");
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "cont");
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "system_powerdown");
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "system_reset");
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
                (void) qmp_error_to_varlink(link, error_class, error);
                sd_varlink_unref(link);
                return;
        }

        sd_json_variant *running = sd_json_variant_by_key(result, "running");
        sd_json_variant *status = sd_json_variant_by_key(result, "status");

        (void) sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running ? sd_json_variant_boolean(running) : false),
                        SD_JSON_BUILD_PAIR_STRING("status", status && sd_json_variant_is_string(status) ? sd_json_variant_string(status) : "unknown"));

        sd_varlink_unref(link);
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        return qmp_execute_varlink_async(ctx, link, "query-status", /* arguments= */ NULL, on_qmp_query_status_complete);
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **filter = NULL;
        int r;

        /* SD_VARLINK_REQUIRES_MORE in the IDL rejects non-streaming callers before we get here */

        r = sd_varlink_dispatch(link, parameters, (const sd_json_dispatch_field[]) {
                { "filter", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv, 0, SD_JSON_NULLABLE },
                {},
        }, &filter);
        if (r != 0)
                return r;

        sd_varlink_ref(link);

        r = hashmap_ensure_put(&ctx->subscribed, &varlink_subscriber_hash_ops, link, filter);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        TAKE_PTR(filter);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("ready", true));
        if (r < 0) {
                hashmap_remove(ctx->subscribed, link);
                return r;
        }

        return 0;
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error_errno(link, -EOPNOTSUPP);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        /* hash_ops handles unref + strv_free on removal */
        hashmap_remove(ctx->subscribed, link);
}

static void on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *notification = NULL;
        sd_varlink *link;
        char **filter;
        int r;

        assert(client);
        assert(event);

        if (hashmap_isempty(ctx->subscribed))
                return;

        r = sd_json_buildo(
                        &notification,
                        SD_JSON_BUILD_PAIR_STRING("event", event),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)));
        if (r < 0) {
                log_warning_errno(r, "Failed to build event notification, ignoring: %m");
                return;
        }

        HASHMAP_FOREACH_KEY(filter, link, ctx->subscribed) {
                if (filter && !strv_contains(filter, event))
                        continue;

                r = sd_varlink_notify(link, notification);
                if (r < 0)
                        log_warning_errno(r, "Failed to notify event subscriber, ignoring: %m");
        }
}

/* Free all subscriber entries — varlink_subscriber_hash_ops handles
 * close + unref for each key and strv_free for each value. */
static void drain_event_subscribers(Hashmap **subscribed) {
        *subscribed = hashmap_free(*subscribed);
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(client);

        log_debug("Backend connection lost");

        /* Propagate connection loss by closing all subscriber connections */
        drain_event_subscribers(&ctx->subscribed);
}

int vmspawn_varlink_init(VmspawnQmpBridge **ret, int qmp_fd_consume, sd_event *event) {
        _cleanup_(vmspawn_qmp_bridge_freep) VmspawnQmpBridge *bridge = NULL;
        _cleanup_close_ int fd = TAKE_FD(qmp_fd_consume);
        int r;

        assert(ret);
        assert(fd >= 0);
        assert(event);

        bridge = new(VmspawnQmpBridge, 1);
        if (!bridge)
                return log_oom();

        *bridge = (VmspawnQmpBridge) {};

        r = qmp_client_connect_fd(&bridge->qmp, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        *ret = TAKE_PTR(bridge);
        return 0;
}

int vmspawn_varlink_start(VmspawnQmpBridge *bridge) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        r = qmp_client_call(bridge->qmp, "cont", /* arguments= */ NULL, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to resume QEMU execution: %s", strna(error_class));

        r = qmp_client_start_async(bridge->qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to switch QMP client to async mode: %m");

        return 0;
}

int vmspawn_varlink_setup(
                VmspawnVarlinkContext **ret,
                VmspawnQmpBridge *bridge,
                const char *runtime_dir,
                char **ret_control_address) {

        _cleanup_(vmspawn_qmp_bridge_freep) VmspawnQmpBridge *bridge_owned = bridge;
        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert(ret);
        assert(bridge_owned);
        assert(runtime_dir);

        sd_event *event = qmp_client_get_event(bridge_owned->qmp);
        assert(event);

        ctx = new(VmspawnVarlinkContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (VmspawnVarlinkContext) {
                .bridge = TAKE_PTR(bridge_owned),
        };

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_INHERIT_USERDATA,
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
                        "io.systemd.MachineInstance.Terminate",         vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",          vl_method_power_off,
                        "io.systemd.MachineInstance.Pause",             vl_method_pause,
                        "io.systemd.MachineInstance.Resume",            vl_method_resume,
                        "io.systemd.MachineInstance.Reboot",            vl_method_reboot,
                        "io.systemd.MachineInstance.QueryStatus",       vl_method_query_status,
                        "io.systemd.MachineInstance.SubscribeEvents",   vl_method_subscribe_events,
                        "io.systemd.QemuMachineInstance.AcquireQMP",    vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(ctx->varlink_server, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect handler: %m");

        listen_address = path_join(runtime_dir, "control");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        qmp_client_set_event_callback(ctx->bridge->qmp, on_qmp_event, ctx);
        qmp_client_set_disconnect_callback(ctx->bridge->qmp, on_qmp_disconnect, ctx);

        log_debug("Varlink control server listening on %s", listen_address);

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        sd_varlink_server_unref(ctx->varlink_server);
        vmspawn_qmp_bridge_free(ctx->bridge);

        drain_event_subscribers(&ctx->subscribed);

        return mfree(ctx);
}
