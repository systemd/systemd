/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "ether-addr-util.h"
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
#include "vmspawn-varlink.h"

struct VmspawnVarlinkBridge {
        QmpClient *qmp;
};

VmspawnVarlinkBridge *vmspawn_varlink_bridge_free(VmspawnVarlinkBridge *b) {
        if (!b)
                return NULL;

        qmp_client_free(b->qmp);
        return mfree(b);
}

struct VmspawnVarlinkContext {
        sd_varlink_server *varlink_server;
        VmspawnVarlinkBridge *bridge;
        /* Each entry holds one ref on the sd_varlink* key (taken in vl_method_subscribe_events,
         * released in vl_disconnect / on_qmp_disconnect / vmspawn_varlink_context_free).
         * The value is an owned strv filter (NULL means all events). */
        Hashmap *subscribed;
};

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

        return qmp_execute_varlink_async(ctx, link, qmp_command, NULL, on_qmp_simple_complete);
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
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        return qmp_execute_varlink_async(ctx, link, "query-status", NULL, on_qmp_query_status_complete);
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
        return sd_varlink_error_errno(link, -EOPNOTSUPP);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
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
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
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
static int qmp_build_blockdev_add(const DriveInfo *drive, bool io_uring, sd_json_variant **ret) {
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
static int qmp_build_device_add(const DriveInfo *drive, sd_json_variant **ret) {
        assert(drive);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->disk_driver),
                        SD_JSON_BUILD_PAIR_STRING("drive", drive->node_name),
                        SD_JSON_BUILD_PAIR_STRING("id", drive->node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(drive->boot, "bootindex", SD_JSON_BUILD_INTEGER(1)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!drive->serial, "serial", SD_JSON_BUILD_STRING(drive->serial)),
                        SD_JSON_BUILD_PAIR_CONDITION(STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"),
                                                    "bus", SD_JSON_BUILD_STRING("vmspawn_scsi.0")));
}

/* Configure a single drive via synchronous QMP commands: blockdev-add to create the block
 * backend, device_add to attach it, and optionally blockdev-snapshot-sync for ephemeral
 * overlays. If blockdev-add with io_uring fails, retries without it. */
static int qmp_setup_one_drive(QmpClient *qmp, const DriveInfo *drive, bool io_uring) {
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

int vmspawn_varlink_setup_network(VmspawnVarlinkBridge *bridge, NetworkInfo *network) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *netdev_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        bool tap_by_fd;
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;
        assert(network);
        assert(network->type);

        tap_by_fd = streq(network->type, "tap") && network->fd >= 0;

        /* For TAP-by-fd: pass the TAP fd to QEMU via getfd + SCM_RIGHTS, then reference it by name
         * in netdev_add. QEMU stores the received fd under the given fdname and closes it on removal. */
        if (tap_by_fd) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL;

                r = sd_json_buildo(
                                &getfd_args,
                                SD_JSON_BUILD_PAIR_STRING("fdname", "vmspawn_tap"));
                if (r < 0)
                        return log_error_errno(r, "Failed to build getfd JSON: %m");

                r = qmp_client_call_send_fd(qmp, "getfd", getfd_args, network->fd,
                                            /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to pass TAP fd to QEMU via getfd: %s", strna(error_class));

                error_class = mfree(error_class);
                network->fd = safe_close(network->fd);
        }

        /* netdev_add: create the network backend */
        r = sd_json_buildo(
                        &netdev_args,
                        SD_JSON_BUILD_PAIR_STRING("type", network->type),
                        SD_JSON_BUILD_PAIR_STRING("id", "net0"),
                        SD_JSON_BUILD_PAIR_CONDITION(tap_by_fd,
                                                     "fd", SD_JSON_BUILD_STRING("vmspawn_tap")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && !!network->ifname,
                                                     "ifname", SD_JSON_BUILD_STRING(network->ifname)),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "script", SD_JSON_BUILD_STRING("no")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "downscript", SD_JSON_BUILD_STRING("no")));
        if (r < 0)
                return log_error_errno(r, "Failed to build netdev_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "netdev_add", netdev_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add network backend via QMP: %s", strna(error_class));

        /* device_add: attach NIC frontend */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-net-pci"),
                        SD_JSON_BUILD_PAIR_STRING("netdev", "net0"),
                        SD_JSON_BUILD_PAIR_STRING("id", "nic0"),
                        SD_JSON_BUILD_PAIR_CONDITION(!!network->mac,
                                                     "mac", SD_JSON_BUILD_STRING(network->mac ? ETHER_ADDR_TO_STR(network->mac) : NULL)));
        if (r < 0)
                return log_error_errno(r, "Failed to build NIC device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add NIC device via QMP: %s", strna(error_class));

        log_debug("Added %s network via QMP%s", network->type, tap_by_fd ? " (fd via getfd)" : "");
        return 0;
}

static int vmspawn_varlink_setup_one_virtiofs(QmpClient *qmp, const VirtiofsInfo *vfs) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *chardev_args = NULL, *device_args = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *addr = NULL, *backend_data = NULL, *backend = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(vfs);
        assert(vfs->id);
        assert(vfs->socket_path);
        assert(vfs->tag);

        /* chardev-add: connect to virtiofsd socket.
         * ChardevBackend and SocketAddressLegacy are QAPI legacy unions with explicit "data"
         * wrapper objects at each level — the nesting is mandatory on the wire. Build bottom-up
         * to keep each level readable. */
        r = sd_json_buildo(
                        &addr,
                        SD_JSON_BUILD_PAIR_STRING("type", "unix"),
                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("path", vfs->socket_path))));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev address JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &backend_data,
                        SD_JSON_BUILD_PAIR_VARIANT("addr", addr),
                        SD_JSON_BUILD_PAIR_BOOLEAN("server", false));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev backend JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &backend,
                        SD_JSON_BUILD_PAIR_STRING("type", "socket"),
                        SD_JSON_BUILD_PAIR_VARIANT("data", backend_data));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev backend wrapper JSON for '%s': %m", vfs->id);

        r = sd_json_buildo(
                        &chardev_args,
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR_VARIANT("backend", backend));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev-add JSON for '%s': %m", vfs->id);

        r = qmp_client_call(qmp, "chardev-add", chardev_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add chardev '%s' via QMP: %s", vfs->id, strna(error_class));

        /* device_add: create vhost-user-fs-pci device */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-user-fs-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("chardev", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("tag", vfs->tag),
                        SD_JSON_BUILD_PAIR_UNSIGNED("queue-size", 1024));
        if (r < 0)
                return log_error_errno(r, "Failed to build virtiofs device_add JSON for '%s': %m", vfs->id);

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add virtiofs device '%s' via QMP: %s", vfs->id, strna(error_class));

        log_debug("Added virtiofs device '%s' (tag=%s) via QMP", vfs->id, vfs->tag);
        return 0;
}

int vmspawn_varlink_setup_virtiofs(VmspawnVarlinkBridge *bridge, const VirtiofsInfos *virtiofs) {
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;
        assert(virtiofs);

        for (size_t i = 0; i < virtiofs->n; i++) {
                r = vmspawn_varlink_setup_one_virtiofs(qmp, &virtiofs->entries[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_varlink_setup_rng(VmspawnVarlinkBridge *bridge) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *object_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;

        /* object-add: create rng-random backend */
        r = sd_json_buildo(
                        &object_args,
                        SD_JSON_BUILD_PAIR_STRING("qom-type", "rng-random"),
                        SD_JSON_BUILD_PAIR_STRING("id", "rng0"),
                        SD_JSON_BUILD_PAIR_STRING("filename", "/dev/urandom"));
        if (r < 0)
                return log_error_errno(r, "Failed to build RNG object-add JSON: %m");

        r = qmp_client_call(qmp, "object-add", object_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add RNG backend via QMP: %s", strna(error_class));

        /* device_add: create virtio-rng-pci frontend */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-rng-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "rng-device0"),
                        SD_JSON_BUILD_PAIR_STRING("rng", "rng0"));
        if (r < 0)
                return log_error_errno(r, "Failed to build RNG device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add RNG device via QMP: %s", strna(error_class));

        log_debug("Added virtio-rng-pci device via QMP");
        return 0;
}

int vmspawn_varlink_setup_vmgenid(VmspawnVarlinkBridge *bridge, sd_id128_t vmgenid) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vmgenid"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmgenid0"),
                        SD_JSON_BUILD_PAIR_STRING("guid", SD_ID128_TO_UUID_STRING(vmgenid)));
        if (r < 0)
                return log_error_errno(r, "Failed to build vmgenid device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add vmgenid device via QMP: %s", strna(error_class));

        log_debug("Added vmgenid device via QMP");
        return 0;
}

int vmspawn_varlink_setup_balloon(VmspawnVarlinkBridge *bridge) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-balloon-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "balloon0"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("free-page-reporting", true));
        if (r < 0)
                return log_error_errno(r, "Failed to build balloon device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add balloon device via QMP: %s", strna(error_class));

        log_debug("Added virtio-balloon device via QMP");
        return 0;
}

int vmspawn_varlink_setup_vsock(VmspawnVarlinkBridge *bridge, VsockInfo *vsock) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;
        assert(vsock);
        assert(vsock->fd >= 0);

        /* getfd: pass the vhost-vsock fd to QEMU via SCM_RIGHTS */
        r = sd_json_buildo(
                        &getfd_args,
                        SD_JSON_BUILD_PAIR_STRING("fdname", "vmspawn_vsock"));
        if (r < 0)
                return log_error_errno(r, "Failed to build getfd JSON for VSOCK: %m");

        r = qmp_client_call_send_fd(qmp, "getfd", getfd_args, vsock->fd,
                                    /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to pass VSOCK fd to QEMU via getfd: %s", strna(error_class));

        vsock->fd = safe_close(vsock->fd);

        /* device_add: create vhost-vsock-pci device referencing the named fd */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-vsock-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vsock0"),
                        SD_JSON_BUILD_PAIR_UNSIGNED("guest-cid", vsock->cid),
                        SD_JSON_BUILD_PAIR_STRING("vhostfd", "vmspawn_vsock"));
        if (r < 0)
                return log_error_errno(r, "Failed to build VSOCK device_add JSON: %m");

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add VSOCK device via QMP: %s", strna(error_class));

        log_debug("Added vhost-vsock-pci device via QMP (cid=%u)", vsock->cid);
        return 0;
}

static bool drives_need_scsi_controller(const DriveInfos *drives) {
        FOREACH_ARRAY(d, drives->drives, drives->n)
                if (STR_IN_SET(d->disk_driver, "scsi-hd", "scsi-cd"))
                        return true;

        return false;
}

static int qmp_setup_scsi_controller(QmpClient *qmp) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-scsi-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmspawn_scsi"));
        if (r < 0)
                return log_error_errno(r, "Failed to build SCSI controller JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add SCSI controller via QMP: %s", strna(error_class));

        log_debug("Added virtio-scsi-pci controller via QMP");
        return 0;
}

int vmspawn_varlink_setup_drives(VmspawnVarlinkBridge *bridge, const DriveInfos *drives) {
        int r;

        assert(bridge);

        QmpClient *qmp = bridge->qmp;
        assert(drives);

        QemuFeatures features = {};
        r = qmp_detect_features(qmp, &features);
        if (r < 0)
                log_warning_errno(r, "Failed to detect QEMU features, continuing with defaults: %m");

        if (drives_need_scsi_controller(drives)) {
                r = qmp_setup_scsi_controller(qmp);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < drives->n; i++) {
                r = qmp_setup_one_drive(qmp, &drives->drives[i], features.io_uring);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_varlink_init(VmspawnVarlinkBridge **ret, int qmp_fd, sd_event *event) {
        _cleanup_(vmspawn_varlink_bridge_freep) VmspawnVarlinkBridge *bridge = NULL;
        _cleanup_close_ int fd = TAKE_FD(qmp_fd);
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);

        bridge = new(VmspawnVarlinkBridge, 1);
        if (!bridge)
                return log_oom();

        *bridge = (VmspawnVarlinkBridge) {};

        r = qmp_client_connect_fd(&bridge->qmp, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        *ret = TAKE_PTR(bridge);
        return 0;
}

int vmspawn_varlink_start(VmspawnVarlinkBridge *bridge) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert_return(bridge, -EINVAL);

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
                VmspawnVarlinkBridge *bridge,
                const char *runtime_dir,
                char **ret_control_address) {

        _cleanup_(vmspawn_varlink_bridge_freep) VmspawnVarlinkBridge *bridge_owned = bridge;
        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(bridge_owned, -EINVAL);
        assert_return(runtime_dir, -EINVAL);

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

        qmp_client_set_event_callback(ctx->bridge->qmp, on_qmp_event, ctx);
        qmp_client_set_disconnect_callback(ctx->bridge->qmp, on_qmp_disconnect, ctx);

        log_debug("QMP varlink server listening on %s", listen_address);

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->bridge = vmspawn_varlink_bridge_free(ctx->bridge);

        drain_event_subscribers(&ctx->subscribed);

        return mfree(ctx);
}
