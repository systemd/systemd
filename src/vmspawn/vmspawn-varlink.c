/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-qmp.h"
#include "vmspawn-util.h"
#include "vmspawn-varlink.h"

DEFINE_PRIVATE_HASH_OPS_FULL(
                varlink_subscriber_hash_ops,
                void, trivial_hash_func, trivial_compare_func, sd_varlink_close_unref,
                char*, strv_free);

static int dispatch_device_deleted(VmspawnVarlinkContext *ctx, sd_json_variant *data);

struct VmspawnVarlinkContext {
        sd_varlink_server *varlink_server;
        VmspawnQmpBridge *bridge;
        /* Key: sd_varlink* (ref'd), Value: strv filter (NULL = all events).
         * varlink_subscriber_hash_ops handles cleanup of both on removal. */
        Hashmap *subscribed;
};

/* Translate a QMP async completion into a varlink error reply */
static int qmp_error_to_varlink(sd_varlink *link, const char *error_desc, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        if (error == -EIO)
                log_warning("QMP command failed: %s", strna(error_desc));
        return sd_varlink_error_errno(link, error);
}

/* Shared async completion for simple QMP commands that return no data.
 * Errors are translated to varlink replies, not propagated through sd_event. */
static int on_qmp_simple_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0)
                (void) qmp_error_to_varlink(link, error_desc, error);
        else
                (void) sd_varlink_reply(link, NULL);

        sd_varlink_unref(link);
        return 0;
}

static int qmp_execute_varlink_async(
                VmspawnVarlinkContext *ctx,
                sd_varlink *link,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback) {

        int r;

        sd_varlink_ref(link);

        r = qmp_client_invoke(ctx->bridge->qmp, command, QMP_CLIENT_ARGS(arguments), callback, link);
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
static int on_qmp_describe_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                (void) qmp_error_to_varlink(link, error_desc, error);
                return 0;
        }

        sd_json_variant *running_v = sd_json_variant_by_key(result, "running");
        sd_json_variant *status_v = sd_json_variant_by_key(result, "status");

        bool running = false;
        if (running_v)
                running = sd_json_variant_boolean(running_v);

        const char *status = "unknown";
        if (status_v && sd_json_variant_is_string(status_v))
                status = sd_json_variant_string(status_v);

        (void) sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running),
                        SD_JSON_BUILD_PAIR_STRING("status", status));

        return 0;
}

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        return qmp_execute_varlink_async(ctx, link, "query-status", /* arguments= */ NULL, on_qmp_describe_complete);
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

        /* Treat [] identically to null: deliver all events. */
        if (strv_isempty(filter))
                filter = strv_free(filter);

        sd_varlink_ref(link);

        r = hashmap_ensure_put(&ctx->subscribed, &varlink_subscriber_hash_ops, link, filter);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        TAKE_PTR(filter);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_STRING("event", "READY"));
        if (r < 0) {
                strv_free(hashmap_remove(ctx->subscribed, link));
                sd_varlink_close_unref(link);
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

        /* Only subscribers hold an extra ref on the link (taken in vl_method_subscribe_events).
         * Non-subscriber connections (one-shot commands like Pause, Describe) must not be unref'd
         * here — their extra ref is consumed by the async completion callback. Only unref, never
         * close — the server handles close after this callback returns (matching resolved's
         * vl_on_notification_disconnect pattern).
         *
         * Use hashmap_remove2() so the returned key (non-NULL iff the entry was present)
         * disambiguates "no filter subscriber" (value=NULL) from "not a subscriber". */
        void *removed_key = NULL;
        strv_free(hashmap_remove2(ctx->subscribed, link, &removed_key));
        if (!removed_key)
                return;

        sd_varlink_unref(link);
}

static int on_job_dismiss_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        if (error < 0)
                log_debug_errno(error, "job-dismiss failed: %s", strna(error_desc));

        return 0;
}

static int dispatch_pending_job(VmspawnQmpBridge *bridge, sd_json_variant *data) {
        const char *job_id, *status;
        int r;

        assert(bridge);

        if (!data)
                return 0;

        job_id = sd_json_variant_string(sd_json_variant_by_key(data, "id"));
        status = sd_json_variant_string(sd_json_variant_by_key(data, "status"));

        if (!job_id || !streq_ptr(status, "concluded"))
                return 0;

        _cleanup_free_ char *key = NULL;
        _cleanup_(pending_job_freep) PendingJob *job = hashmap_remove2(bridge->pending_jobs, job_id, (void**) &key);
        if (!job)
                return 0;

        log_debug("QMP job '%s' concluded, firing continuation", job_id);

        /* Dismiss the concluded job before running the continuation */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dismiss_args = NULL;
        r = sd_json_buildo(&dismiss_args, SD_JSON_BUILD_PAIR_STRING("id", job_id));
        if (r < 0)
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);

        r = qmp_client_invoke(bridge->qmp, "job-dismiss", QMP_CLIENT_ARGS(dismiss_args),
                              on_job_dismiss_complete, /* userdata= */ NULL);
        if (r < 0)
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);

        if (!job->on_concluded)
                return 1;

        r = job->on_concluded(bridge->qmp, TAKE_PTR(job->userdata));
        if (r < 0) {
                log_error_errno(r, "Job continuation failed: %m");
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);
        }

        return 1;
}

static int notify_event_subscribers(VmspawnVarlinkContext *ctx, const char *event_name, sd_json_variant *data) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *notification = NULL;
        sd_varlink *link;
        char **filter;
        int r;

        assert(ctx);
        assert(event_name);

        if (hashmap_isempty(ctx->subscribed))
                return 0;

        r = sd_json_buildo(
                        &notification,
                        SD_JSON_BUILD_PAIR_STRING("event", event_name),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)));
        if (r < 0) {
                log_warning_errno(r, "Failed to build event notification, ignoring: %m");
                return 0;
        }

        HASHMAP_FOREACH_KEY(filter, link, ctx->subscribed) {
                if (filter && !strv_contains(filter, event_name))
                        continue;

                r = sd_varlink_notify(link, notification);
                if (r < 0)
                        log_warning_errno(r, "Failed to notify event subscriber, ignoring: %m");
        }

        return 0;
}

static int on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(client);
        assert(event);

        /* Dispatch job status changes to pending continuations (e.g. blockdev-create) */
        if (streq(event, "JOB_STATUS_CHANGE"))
                return dispatch_pending_job(ctx->bridge, data);

        /* Only our own hotplug ids route to the block-device handler; other frontends fall through. */
        if (streq(event, "DEVICE_DELETED") && data) {
                const char *id = sd_json_variant_string(sd_json_variant_by_key(data, "device"));
                if (id && startswith(id, QMP_BLOCK_QDEV_PREFIX))
                        return dispatch_device_deleted(ctx, data);
        }

        return notify_event_subscribers(ctx, event, data);
}

/* Free all subscriber entries — varlink_subscriber_hash_ops handles
 * close + unref for each key and strv_free for each value. */
static void drain_event_subscribers(Hashmap **subscribed) {
        assert(subscribed);
        *subscribed = hashmap_free(*subscribed);
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(client);

        log_debug("Backend connection lost");

        /* Propagate connection loss by closing all subscriber connections */
        drain_event_subscribers(&ctx->subscribed);
}

/* 28-char limit: QEMU's 31-byte BDS node-name limit minus the "bd-" prefix. */
static bool block_device_id_valid(const char *id) {
        if (isempty(id))
                return false;
        if (strlen(id) > 28)
                return false;
        for (const char *p = id; *p; p++)
                if (!ascii_isalpha(*p) && !ascii_isdigit(*p) && *p != '_' && *p != '-')
                        return false;
        return true;
}

static int vl_method_add_block_device(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        VmspawnQmpBridge *bridge = ASSERT_PTR(ctx->bridge);
        struct {
                unsigned file_descriptor;
                const char *format;
                const char *driver;
                int read_only;
                int discard;
                const char *serial;
                const char *id;
        } p = {
                .read_only = -1,
                .discard = -1,
        };
        int r;

        r = sd_varlink_dispatch(link, parameters, (const sd_json_dispatch_field[]) {
                { "fileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,     offsetof(typeof(p), file_descriptor), SD_JSON_MANDATORY },
                { "format",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(typeof(p), format),          SD_JSON_MANDATORY },
                { "driver",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(typeof(p), driver),          SD_JSON_MANDATORY },
                { "readOnly",       SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(typeof(p), read_only),       0                 },
                { "discard",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, offsetof(typeof(p), discard),         0                 },
                { "serial",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(typeof(p), serial),          0                 },
                { "id",             SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(typeof(p), id),              0                 },
                {},
        }, &p);
        if (r != 0)
                return r;

        if (!STR_IN_SET(p.format, "raw", "qcow2"))
                return sd_varlink_error_invalid_parameter_name(link, "format");

        const char *disk_driver;
        if (streq(p.driver, "virtio_blk"))
                disk_driver = "virtio-blk-pci";
        else if (streq(p.driver, "nvme"))
                disk_driver = "nvme";
        else if (streq(p.driver, "scsi_hd"))
                disk_driver = "scsi-hd";
        else if (streq(p.driver, "scsi_cd"))
                disk_driver = "scsi-cd";
        else
                return sd_varlink_error_invalid_parameter_name(link, "driver");

        bool is_scsi = STR_IN_SET(disk_driver, "scsi-hd", "scsi-cd");

        if (p.id && !block_device_id_valid(p.id))
                return sd_varlink_error(link, "io.systemd.VirtualMachineInstance.InvalidBlockDeviceId", NULL);

        _cleanup_close_ int image_fd = sd_varlink_peek_dup_fd(link, p.file_descriptor);
        if (image_fd == -ENXIO)
                return sd_varlink_error_invalid_parameter_name(link, "fileDescriptor");
        if (image_fd < 0)
                return log_debug_errno(image_fd, "Failed to peek fd %u: %m", p.file_descriptor);

        struct stat st;
        if (fstat(image_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat image fd: %m");

        r = stat_verify_regular_or_block(&st);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "fileDescriptor");

        _cleanup_(drive_info_unrefp) DriveInfo *drive = drive_info_new();
        if (!drive)
                return log_oom();

        drive->link = sd_varlink_ref(link);

        if (p.id) {
                drive->id = strdup(p.id);
                if (!drive->id)
                        return log_oom();
        } else {
                if (asprintf(&drive->id, "bd%" PRIu64, bridge->next_id) < 0)
                        return log_oom();
                bridge->next_id++;
        }

        drive->format = strdup(p.format);
        drive->disk_driver = strdup(disk_driver);
        if (!drive->format || !drive->disk_driver)
                return log_oom();

        /* NVMe requires a serial; default to the varlink id if caller didn't set one. */
        const char *serial_src = p.serial;
        if (!serial_src && streq(disk_driver, "nvme"))
                serial_src = drive->id;
        if (serial_src) {
                drive->serial = strdup(serial_src);
                if (!drive->serial)
                        return log_oom();
        }

        /* SCSI disks attach to the virtio-scsi-pci controller's bus, not a PCIe
         * root port. The controller itself may consume a port if we have to
         * create it on-demand — handled inside vmspawn_qmp_add_block_device. */
        if (ARCHITECTURE_NEEDS_PCIE_ROOT_PORTS && !is_scsi) {
                r = vmspawn_qmp_bridge_allocate_pcie_port(bridge, drive->id,
                                                          &drive->pcie_port, &drive->pcie_port_idx);
                if (r == -EBUSY)
                        return sd_varlink_error(link, "io.systemd.VirtualMachineInstance.BlockBackendBusy", NULL);
                if (r < 0)
                        return log_oom();
        }

        if (S_ISBLK(st.st_mode))
                drive->flags |= QMP_DRIVE_BLOCK_DEVICE;
        if (p.discard > 0)
                drive->flags |= QMP_DRIVE_DISCARD;

        /* QEMU's fdset match is strict on O_ACCMODE: the pushed fd's access
         * mode has to match the blockdev's read-only flag. Derive the flag
         * from the fd; if the caller also set readOnly=true but pushed an
         * O_RDWR fd, that's inconsistent — reject it. */
        int fd_flags = fcntl(image_fd, F_GETFL);
        if (fd_flags < 0)
                return log_error_errno(errno, "Failed to read fd flags: %m");
        if ((fd_flags & O_ACCMODE) == O_RDONLY)
                drive->flags |= QMP_DRIVE_READ_ONLY;
        else if (p.read_only > 0)
                return sd_varlink_error_invalid_parameter_name(link, "readOnly");

        drive->fd = TAKE_FD(image_fd);

        return vmspawn_qmp_add_block_device(bridge, TAKE_PTR(drive));
}

static int dispatch_device_deleted(VmspawnVarlinkContext *ctx, sd_json_variant *data) {
        assert(ctx);
        assert(data);

        const char *device = ASSERT_PTR(sd_json_variant_string(sd_json_variant_by_key(data, "device")));
        assert(startswith(device, QMP_BLOCK_QDEV_PREFIX));

        const char *varlink_id = device + strlen(QMP_BLOCK_QDEV_PREFIX);

        (void) vmspawn_qmp_bridge_release_pcie_port_by_id(ctx->bridge, varlink_id);

        vmspawn_qmp_block_device_teardown(ctx->bridge->qmp, varlink_id,
                                          BLOCK_DEVICE_ADD_STAGE_BLOCKDEV_ADD);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *event_data = NULL;
        (void) sd_json_buildo(&event_data, SD_JSON_BUILD_PAIR_STRING("id", varlink_id));
        (void) notify_event_subscribers(ctx, "BlockDeviceRemoved", event_data);

        log_info("Block device '%s' removed", varlink_id);
        return 0;
}

static int vl_method_remove_block_device(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        VmspawnQmpBridge *bridge = ASSERT_PTR(ctx->bridge);
        const char *id = NULL;
        int r;

        r = sd_varlink_dispatch(link, parameters, (const sd_json_dispatch_field[]) {
                { "id", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, 0, SD_JSON_MANDATORY },
                {},
        }, &id);
        if (r != 0)
                return r;

        if (!block_device_id_valid(id))
                return sd_varlink_error(link, "io.systemd.VirtualMachineInstance.InvalidBlockDeviceId", NULL);

        return vmspawn_qmp_remove_block_device(bridge, link, id);
}

/* Filter by inserted.node-name (the blockdev-add name, e.g. "bd-bd0") — the
 * top-level "device" field is the legacy -drive name (empty for us), and
 * "qdev" for virtio-blk-pci is the nested virtio-backend QOM path. */
static void notify_block_device_entry(sd_varlink *link, sd_json_variant *entry) {
        assert(link);
        assert(entry);

        sd_json_variant *inserted = sd_json_variant_by_key(entry, "inserted");
        if (!inserted)
                return;

        const char *node_name = sd_json_variant_string(sd_json_variant_by_key(inserted, "node-name"));
        if (!node_name || !startswith(node_name, QMP_BLOCK_QDEV_PREFIX))
                return;

        const char *varlink_id = node_name + strlen(QMP_BLOCK_QDEV_PREFIX);

        const char *drv = sd_json_variant_string(sd_json_variant_by_key(inserted, "drv"));
        const char *format;
        if (streq_ptr(drv, "raw"))
                format = "raw";
        else if (streq_ptr(drv, "qcow2"))
                format = "qcow2";
        else
                return;

        bool ro = false;
        sd_json_variant *ro_v = sd_json_variant_by_key(inserted, "ro");
        if (ro_v)
                ro = sd_json_variant_boolean(ro_v);

        (void) sd_varlink_notifybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("id", varlink_id),
                        SD_JSON_BUILD_PAIR_STRING("format", format),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", ro));
}

static int on_list_block_devices_reply(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                if (ERRNO_IS_DISCONNECT(error))
                        return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
                if (error_desc)
                        log_warning("query-block failed: %s", error_desc);
                return sd_varlink_error_errno(link, error);
        }

        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, result)
                notify_block_device_entry(link, entry);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_list_block_devices(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        sd_varlink_ref(link);
        r = qmp_client_invoke(ctx->bridge->qmp, "query-block", QMP_CLIENT_ARGS(NULL),
                              on_list_block_devices_reply, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }
        return 0;
}

int vmspawn_varlink_setup(
                VmspawnVarlinkContext **ret,
                VmspawnQmpBridge *bridge,
                const char *runtime_dir,
                char **ret_control_address) {

        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert(ret);
        assert(bridge);
        assert(runtime_dir);

        sd_event *event = qmp_client_get_event(bridge->qmp);
        assert(event);

        ctx = new0(VmspawnVarlinkContext, 1);
        if (!ctx)
                return log_oom();

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
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
                        "io.systemd.MachineInstance.Terminate",                   vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",                    vl_method_power_off,
                        "io.systemd.MachineInstance.Pause",                       vl_method_pause,
                        "io.systemd.MachineInstance.Resume",                      vl_method_resume,
                        "io.systemd.MachineInstance.Reboot",                      vl_method_reboot,
                        "io.systemd.MachineInstance.Describe",                    vl_method_describe,
                        "io.systemd.MachineInstance.SubscribeEvents",             vl_method_subscribe_events,
                        "io.systemd.VirtualMachineInstance.AddBlockDevice",       vl_method_add_block_device,
                        "io.systemd.VirtualMachineInstance.RemoveBlockDevice",    vl_method_remove_block_device,
                        "io.systemd.VirtualMachineInstance.ListBlockDevices",     vl_method_list_block_devices,
                        "io.systemd.QemuMachineInstance.AcquireQMP",              vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(ctx->varlink_server, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect handler: %m");

        listen_address = path_join(runtime_dir, "control");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0600);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        ctx->bridge = bridge;
        qmp_client_bind_event(ctx->bridge->qmp, on_qmp_event, ctx);
        qmp_client_bind_disconnect(ctx->bridge->qmp, on_qmp_disconnect, ctx);
        qmp_client_set_userdata(ctx->bridge->qmp, ctx->bridge);

        log_debug("Varlink control server listening on %s", listen_address);

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnVarlinkContext* vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        sd_varlink_server_unref(ctx->varlink_server);
        vmspawn_qmp_bridge_free(ctx->bridge);

        drain_event_subscribers(&ctx->subscribed);

        return mfree(ctx);
}
