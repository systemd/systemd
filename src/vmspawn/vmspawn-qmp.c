/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-polkit.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-qmp.h"

struct VmspawnQmpContext {
        sd_varlink_server *varlink_server;
        QmpClient *qmp_client;
        /* Each entry holds one ref on the sd_varlink* key (taken in vl_method_subscribe_events,
         * released in vl_disconnect / on_qmp_disconnect / vmspawn_qmp_context_free).
         * The value is an owned strv filter (NULL means all events). */
        Hashmap *subscribed;
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

        if (ERRNO_IS_DISCONNECT(error))
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

static const sd_json_dispatch_field polkit_dispatch_table[] = {
        VARLINK_DISPATCH_POLKIT_FIELD,
        {},
};

static int qmp_execute_varlink_async(
                VmspawnQmpContext *ctx,
                sd_varlink *link,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback) {

        int r;

        sd_varlink_ref(link);

        r = qmp_client_execute(ctx->qmp_client, command, arguments, callback, link);
        if (r < 0)
                sd_varlink_unref(link);

        return r;
}

static int qmp_execute_simple_async(
                sd_varlink *link,
                sd_json_variant *parameters,
                VmspawnQmpContext *ctx,
                const char *polkit_verb,
                const char *qmp_command) {

        int r;

        assert(link);
        assert(ctx);
        assert(polkit_verb);
        assert(qmp_command);

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, polkit_verb);
        if (r <= 0)
                return r;

        return qmp_execute_varlink_async(ctx, link, qmp_command, NULL, on_qmp_simple_complete);
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "terminate", "quit");
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "pause", "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "resume", "cont");
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "power_off", "system_powerdown");
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, parameters, ASSERT_PTR(userdata), "reboot", "system_reset");
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
                        SD_JSON_BUILD_PAIR_STRING("status", status && sd_json_variant_is_string(status) ? sd_json_variant_string(status) : "unknown"));

        sd_varlink_unref(link);
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, "query_status");
        if (r <= 0)
                return r;

        return qmp_execute_varlink_async(ctx, link, "query-status", NULL, on_qmp_query_status_complete);
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        struct {
                char **filter;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "filter", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv, 0, SD_JSON_NULLABLE },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_strv_free_ char **filter = TAKE_PTR(p.filter);

        r = vmspawn_verify_polkit(link, ctx, "subscribe_events");
        if (r <= 0)
                return r;

        sd_varlink_ref(link);

        r = hashmap_ensure_put(&ctx->subscribed, &trivial_hash_ops, link, filter);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        TAKE_PTR(filter);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("ready", true));
        if (r < 0) {
                strv_free(hashmap_remove(ctx->subscribed, link));
                sd_varlink_unref(link);
                return r;
        }

        return 0;
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, polkit_dispatch_table, NULL);
        if (r != 0)
                return r;

        r = vmspawn_verify_polkit(link, ctx, "acquire_qmp");
        if (r <= 0)
                return r;

        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        void *key = NULL;

        assert(server);
        assert(link);

        /* hashmap_remove2() returns the VALUE and sets *ret to the KEY */
        strv_free(hashmap_remove2(ctx->subscribed, link, &key));
        if (key)
                sd_varlink_unref(link);
}

static void on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
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

/* Drain the subscriber hashmap: steal entries one at a time so each is removed before
 * its value is freed. Use hashmap_isempty() as the loop guard because
 * hashmap_steal_first_key_and_value() returns the value which may be NULL
 * for unfiltered subscriptions. */
static void drain_event_subscribers(Hashmap **subscribed) {
        sd_varlink *link;

        while (!hashmap_isempty(*subscribed)) {
                strv_free(hashmap_steal_first_key_and_value(*subscribed, (void**) &link));
                sd_varlink_unref(link);
        }

        *subscribed = hashmap_free(*subscribed);
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnQmpContext *ctx = ASSERT_PTR(userdata);
        sd_varlink *link;
        void *v;

        assert(client);

        log_debug("QMP connection lost");

        /* Send terminal errors first while all links are still alive */
        HASHMAP_FOREACH_KEY(v, link, ctx->subscribed)
                (void) sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);

        drain_event_subscribers(&ctx->subscribed);
}

/* Detect QEMU features via schema introspection. query-qmp-schema returns all QAPI types;
 * conditionally compiled enum values (like io_uring in BlockdevAioOptions) are only present
 * if QEMU was built with support for them. */
static int qmp_detect_features(QmpClient *qmp, QemuFeatures *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;
        int r;

        assert(qmp);
        assert(ret);

        *ret = (QemuFeatures) {};

        r = qmp_client_call(qmp, "query-qmp-schema", /* arguments= */ NULL, &schema, /* ret_error= */ NULL);
        if (r < 0)
                return r;

        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, schema) {
                sd_json_variant *name = sd_json_variant_by_key(entry, "name");
                if (!streq_ptr(sd_json_variant_string(name), "BlockdevAioOptions"))
                        continue;

                sd_json_variant *meta = sd_json_variant_by_key(entry, "meta-type");
                if (!streq_ptr(sd_json_variant_string(meta), "enum"))
                        break;

                sd_json_variant *members = sd_json_variant_by_key(entry, "members");
                sd_json_variant *member;
                JSON_VARIANT_ARRAY_FOREACH(member, members) {
                        sd_json_variant *mname = sd_json_variant_by_key(member, "name");
                        if (streq_ptr(sd_json_variant_string(mname), "io_uring")) {
                                ret->io_uring = true;
                                break;
                        }
                }
                break;
        }

        log_debug("QEMU feature detection: io_uring=%s", yes_no(ret->io_uring));
        return 0;
}

/* Build blockdev-add JSON arguments for a drive */
static int qmp_build_blockdev_add(const QmpDriveInfo *drive, bool io_uring, sd_json_variant **ret) {
        assert(drive);
        assert(ret);

        /* aio and cache are members of BlockdevOptionsFile (the protocol-level driver), not of
         * BlockdevOptions (the format-level base). They must be inside the "file" sub-object.
         * discard is in the BlockdevOptions base and correctly stays at the top level.
         * cache.direct=false uses the page cache (QEMU default). cache.no-flush=true suppresses
         * host flush on guest fsync, matching the old -blockdev CLI behavior. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", drive->node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->format),
                        SD_JSON_BUILD_PAIR_CONDITION(drive->read_only, "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(drive->discard, "discard", SD_JSON_BUILD_STRING("unmap")),
                        SD_JSON_BUILD_PAIR("file", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("driver", drive->is_block_device ? "host_device" : "file"),
                                        SD_JSON_BUILD_PAIR_STRING("filename", drive->path),
                                        SD_JSON_BUILD_PAIR_CONDITION(io_uring, "aio", SD_JSON_BUILD_STRING("io_uring")),
                                        SD_JSON_BUILD_PAIR("cache", SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_BOOLEAN("direct", false),
                                                        SD_JSON_BUILD_PAIR_BOOLEAN("no-flush", true))))));
}

/* Build device_add JSON arguments for a drive */
static int qmp_build_device_add(const QmpDriveInfo *drive, sd_json_variant **ret) {
        assert(drive);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->disk_driver),
                        SD_JSON_BUILD_PAIR_STRING("drive", drive->node_name),
                        SD_JSON_BUILD_PAIR_STRING("id", drive->node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(drive->boot, "bootindex", SD_JSON_BUILD_STRING("1")),
                        SD_JSON_BUILD_PAIR_CONDITION(!!drive->serial, "serial", SD_JSON_BUILD_STRING(drive->serial)),
                        SD_JSON_BUILD_PAIR_CONDITION(STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"),
                                                    "bus", SD_JSON_BUILD_STRING("vmspawn_scsi.0")));
}

/* Configure a single drive via synchronous QMP commands: blockdev-add to create the block
 * backend, device_add to attach it, and optionally blockdev-snapshot-sync for ephemeral
 * overlays. If blockdev-add with io_uring fails, retries without it. */
static int qmp_setup_one_drive(QmpClient *qmp, const QmpDriveInfo *drive, bool io_uring) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(drive);

        /* blockdev-add: create the block backend */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *blockdev_args = NULL;
        r = qmp_build_blockdev_add(drive, io_uring, &blockdev_args);
        if (r < 0)
                return r;

        r = qmp_client_call(qmp, "blockdev-add", blockdev_args, /* ret_result= */ NULL, &error_class);
        if (r == -EIO && io_uring) {
                log_debug("blockdev-add with aio=io_uring failed for '%s' (%s), retrying without",
                          drive->path, strna(error_class));

                blockdev_args = sd_json_variant_unref(blockdev_args);
                error_class = mfree(error_class);

                r = qmp_build_blockdev_add(drive, /* io_uring= */ false, &blockdev_args);
                if (r < 0)
                        return r;

                r = qmp_client_call(qmp, "blockdev-add", blockdev_args, /* ret_result= */ NULL, &error_class);
                io_uring = false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to add block device '%s': %s", drive->path, strna(error_class));

        /* device_add: attach to virtual hardware */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *device_args = NULL;
        r = qmp_build_device_add(drive, &device_args);
        if (r < 0)
                return r;

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add device for '%s': %s", drive->path, strna(error_class));

        /* blockdev-snapshot-sync: ephemeral overlay */
        if (drive->snapshot_file) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *snap_args = NULL;
                r = sd_json_buildo(
                                &snap_args,
                                SD_JSON_BUILD_PAIR_STRING("node-name", drive->node_name),
                                SD_JSON_BUILD_PAIR_STRING("snapshot-file", drive->snapshot_file),
                                SD_JSON_BUILD_PAIR_STRING("format", "qcow2"));
                if (r < 0)
                        return log_error_errno(r, "Failed to build blockdev-snapshot-sync JSON: %m");

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-snapshot-sync", snap_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to create ephemeral snapshot for '%s': %s",
                                               drive->path, strna(error_class));
        }

        log_debug("Added drive '%s' via QMP (aio=%s%s)", drive->path,
                   io_uring ? "io_uring" : "default",
                   drive->snapshot_file ? ", ephemeral" : "");

        return 0;
}

static int qmp_setup_drives(QmpClient *qmp, const QmpDriveInfo *drives, size_t n_drives, bool io_uring) {
        int r;

        for (size_t i = 0; i < n_drives; i++) {
                r = qmp_setup_one_drive(qmp, &drives[i], io_uring);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_qmp_init(
                QmpClient **ret,
                int qmp_fd,
                sd_event *event,
                const QmpDriveInfo *drives,
                size_t n_drives) {

        _cleanup_(qmp_client_freep) QmpClient *qmp = NULL;
        _cleanup_close_ int fd = TAKE_FD(qmp_fd);
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);

        /* Blocking QMP handshake */
        r = qmp_client_connect_fd(&qmp, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        QemuFeatures features = {};
        r = qmp_detect_features(qmp, &features);
        if (r < 0)
                log_warning_errno(r, "Failed to detect QEMU features, continuing with defaults: %m");

        /* Add drives via pipelined QMP commands, then resume the VM */
        r = qmp_setup_drives(qmp, drives, n_drives, features.io_uring);
        if (r < 0)
                return r;

        _cleanup_free_ char *cont_error = NULL;
        r = qmp_client_call(qmp, "cont", /* arguments= */ NULL, /* ret_result= */ NULL, &cont_error);
        if (r < 0)
                return log_error_errno(r, "Failed to resume QEMU execution: %s", strna(cont_error));

        /* Switch QMP client to async mode for event processing during the event loop */
        r = qmp_client_start_async(qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to switch QMP client to async mode: %m");

        *ret = TAKE_PTR(qmp);
        return 0;
}

int vmspawn_qmp_setup(
                VmspawnQmpContext **ret,
                QmpClient *qmp,
                const char *runtime_dir,
                RuntimeScope runtime_scope,
                uid_t owner_uid,
                char **ret_control_address) {

        _cleanup_(qmp_client_freep) QmpClient *qmp_owned = qmp;
        _cleanup_(vmspawn_qmp_context_freep) VmspawnQmpContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(qmp_owned, -EINVAL);
        assert_return(runtime_dir, -EINVAL);

        sd_event *event = qmp_client_get_event(qmp_owned);
        assert(event);

        ctx = new(VmspawnQmpContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (VmspawnQmpContext) {
                .qmp_client = TAKE_PTR(qmp_owned),
                .runtime_scope = runtime_scope,
                .owner_uid = owner_uid,
        };

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

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx) {
        if (!ctx)
                return NULL;

        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->qmp_client = qmp_client_free(ctx->qmp_client);

        drain_event_subscribers(&ctx->subscribed);

        hashmap_free(ctx->polkit_registry);

        return mfree(ctx);
}
