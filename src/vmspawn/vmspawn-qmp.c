/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "errno-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "qmp-client.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "vmspawn-qmp.h"
#include "vmspawn-util.h"

DEFINE_PRIVATE_HASH_OPS_FULL(
                pending_job_hash_ops,
                char, string_hash_func, string_compare_func, free,
                PendingJob, pending_job_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                block_devices_hash_ops,
                char, string_hash_func, string_compare_func,
                DriveInfo, drive_info_unref);

DriveInfo* drive_info_new(void) {
        DriveInfo *d = new(DriveInfo, 1);
        if (!d)
                return NULL;

        *d = (DriveInfo) {
                .n_ref = 1,
                .fd = -EBADF,
                .overlay_fd = -EBADF,
                .pcie_port_idx = -1,
        };
        return d;
}

static int vmspawn_qmp_bridge_allocate_pcie_port(
                VmspawnQmpBridge *bridge,
                const char *owner_id,
                char **ret_name,
                int *ret_idx) {

        assert(bridge);
        assert(owner_id);
        assert(ret_name);
        assert(ret_idx);

        for (int i = 0; i < VMSPAWN_PCIE_HOTPLUG_SPARES; i++) {
                if (bridge->hotplug_port_owner[i])
                        continue;

                _cleanup_free_ char *owner = strdup(owner_id), *name = NULL;
                if (!owner || asprintf(&name, "vmspawn-hotplug-pci-root-port-%d", i) < 0)
                        return -ENOMEM;

                bridge->hotplug_port_owner[i] = TAKE_PTR(owner);
                *ret_name = TAKE_PTR(name);
                *ret_idx = i;
                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY),
                               "No free PCIe hotplug port available for owner '%s'.",
                               owner_id);
}

static void vmspawn_qmp_bridge_release_pcie_port_by_idx(VmspawnQmpBridge *bridge, int idx) {
        assert(bridge);

        if (idx < 0)
                return;

        assert(idx < VMSPAWN_PCIE_HOTPLUG_SPARES);

        bridge->hotplug_port_owner[idx] = mfree(bridge->hotplug_port_owner[idx]);
}

static DriveInfo* drive_info_free(DriveInfo *d) {
        assert(d);

        if (d->bridge)
                vmspawn_qmp_bridge_release_pcie_port_by_idx(d->bridge, d->pcie_port_idx);

        free(d->path);
        free(d->format);
        free(d->disk_driver);
        free(d->serial);
        free(d->pcie_port);
        free(d->id);
        free(d->qmp_node_name);
        free(d->qmp_device_id);
        free(d->qmp_file_node_name);
        free(d->fdset_path);
        sd_varlink_unref(d->link);
        safe_close(d->fd);
        safe_close(d->overlay_fd);
        return mfree(d);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DriveInfo, drive_info, drive_info_free);

void drive_infos_done(DriveInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(d, infos->drives, infos->n_drives)
                drive_info_unref(*d);
        infos->drives = mfree(infos->drives);
        infos->n_drives = 0;
}

void network_info_done(NetworkInfo *info) {
        assert(info);
        info->ifname = mfree(info->ifname);
        info->pcie_port = mfree(info->pcie_port);
        info->fd = safe_close(info->fd);
}

void virtiofs_info_done(VirtiofsInfo *info) {
        assert(info);
        info->id = mfree(info->id);
        info->socket_path = mfree(info->socket_path);
        info->tag = mfree(info->tag);
        info->pcie_port = mfree(info->pcie_port);
}

void virtiofs_infos_done(VirtiofsInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(e, infos->entries, infos->n_entries)
                virtiofs_info_done(e);
        infos->entries = mfree(infos->entries);
        infos->n_entries = 0;
}

void vsock_info_done(VsockInfo *info) {
        assert(info);
        info->pcie_port = mfree(info->pcie_port);
        info->fd = safe_close(info->fd);
}

void machine_config_done(MachineConfig *c) {
        if (!c)
                return;

        drive_infos_done(&c->drives);
        network_info_done(&c->network);
        virtiofs_infos_done(&c->virtiofs);
        vsock_info_done(&c->vsock);
}

/* Generic completion callback; userdata is a string literal label. Exits the event loop on boot-time failures. */
static int on_qmp_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        assert(client);

        VmspawnQmpBridge *bridge = ASSERT_PTR(qmp_client_get_userdata(client));
        const char *label = ASSERT_PTR(userdata);

        if (error < 0) {
                log_error_errno(error, "%s failed: %s", label, strna(error_desc));

                if (bridge->setup_done)
                        return 0;

                return sd_event_exit(qmp_client_get_event(client), error);
        }

        return 0;
}

/* Send add-fd via SCM_RIGHTS; return /dev/fdset/N and the numeric fdset id. */
static int qmp_fdset_add(
                QmpClient *qmp,
                int fd_consume,
                qmp_command_callback_t callback,
                void *userdata,
                char **ret_path,
                uint64_t *ret_fdset_id) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd = fd_consume;
        _cleanup_free_ char *path = NULL;
        uint64_t id;
        int r;

        assert(qmp);
        assert(fd_consume >= 0);
        assert(callback);
        assert(ret_path);

        id = qmp_client_next_fdset_id(qmp);

        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", id));
        if (r < 0)
                return r;

        if (asprintf(&path, "/dev/fdset/%" PRIu64, id) < 0)
                return -ENOMEM;

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "add-fd", QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd)),
                              callback, userdata);
        if (r < 0)
                return r;

        *ret_path = TAKE_PTR(path);
        if (ret_fdset_id)
                *ret_fdset_id = id;
        return 0;
}

/* Issue remove-fd for an fdset whose dup is now held by a blockdev. The fdset
 * persists until the dup is closed (in raw_close at blockdev-del time) — see
 * QEMU's monitor/fds.c:177-181 on the fds/dup_fds split. */
static int qmp_fdset_remove(
                QmpClient *qmp,
                uint64_t fdset_id,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(qmp);
        assert(callback);

        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", fdset_id));
        if (r < 0)
                return r;

        return qmp_client_invoke(qmp, /* ret_slot= */ NULL, "remove-fd", QMP_CLIENT_ARGS(args),
                                 callback, userdata);
}

typedef struct QmpFileNodeParams {
        const char *node_name;
        const char *filename;
        const char *driver;     /* "file" or "host_device" */
        QmpDriveFlags flags;
} QmpFileNodeParams;

/* Build blockdev-add JSON for the protocol-level (file) node */
static int qmp_build_blockdev_add_file(const QmpFileNodeParams *p, sd_json_variant **ret) {
        assert(p);
        assert(p->node_name);
        assert(p->filename);
        assert(p->driver);
        assert(ret);

        /* cache.direct=false uses the page cache (QEMU default). cache.no-flush suppresses host
         * flush on guest fsync — only safe for ephemeral/extra drives where data loss is acceptable. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", p->node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", p->driver),
                        SD_JSON_BUILD_PAIR_STRING("filename", p->filename),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(p->flags, QMP_DRIVE_READ_ONLY), "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(p->flags, QMP_DRIVE_IO_URING), "aio", JSON_BUILD_CONST_STRING("io_uring")),
                        SD_JSON_BUILD_PAIR("cache", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_BOOLEAN("direct", false),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("no-flush", FLAGS_SET(p->flags, QMP_DRIVE_NO_FLUSH)))));
}

typedef struct QmpFormatNodeParams {
        const char *node_name;
        const char *format;          /* "raw", "qcow2", etc. */
        const char *file_node_name;  /* reference to the underlying file node */
        const char *backing;         /* reference to a backing format node (NULL if none) */
        QmpDriveFlags flags;
} QmpFormatNodeParams;

/* Build blockdev-add JSON for the format-level node */
static int qmp_build_blockdev_add_format(const QmpFormatNodeParams *p, sd_json_variant **ret) {
        assert(p);
        assert(p->node_name);
        assert(p->format);
        assert(p->file_node_name);
        assert(ret);

        /* When "file" is a string (not an object), QEMU interprets it as a reference to an
         * existing node-name. The "backing" field likewise references a format-level node. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", p->node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", p->format),
                        SD_JSON_BUILD_PAIR_STRING("file", p->file_node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(p->flags, QMP_DRIVE_READ_ONLY), "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(p->flags, QMP_DRIVE_DISCARD), "discard", JSON_BUILD_CONST_STRING("unmap")),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(p->flags, QMP_DRIVE_DISCARD_NO_UNREF), "discard-no-unref", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!p->backing, "backing", SD_JSON_BUILD_STRING(p->backing)));
}

static int qmp_build_device_add(const DriveInfo *drive, sd_json_variant **ret) {
        assert(drive);
        assert(drive->qmp_node_name);
        assert(drive->qmp_device_id);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->disk_driver),
                        SD_JSON_BUILD_PAIR_STRING("drive", drive->qmp_node_name),
                        SD_JSON_BUILD_PAIR_STRING("id", drive->qmp_device_id),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(drive->flags, QMP_DRIVE_BOOT), "bootindex", SD_JSON_BUILD_INTEGER(1)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!drive->serial, "serial", SD_JSON_BUILD_STRING(drive->serial)),
                        SD_JSON_BUILD_PAIR_CONDITION(STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"),
                                                    "bus", JSON_BUILD_CONST_STRING("vmspawn_scsi.0")),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd") && !!drive->pcie_port,
                                        "bus", SD_JSON_BUILD_STRING(drive->pcie_port)));
}

/* Issue blockdev-add for a file node. */
static int qmp_add_file_node(QmpClient *qmp, const QmpFileNodeParams *p) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        r = qmp_build_blockdev_add_file(p, &args);
        if (r < 0)
                return r;

        return qmp_client_invoke(qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(args), on_qmp_complete, (void*) "blockdev-add");
}

/* Get the virtual size of an image from the fd directly. For raw images the virtual size
 * equals the file/device size. For qcow2 the virtual size is a big-endian uint64 at header
 * offset 24 (the "size" field in the qcow2 header). */
static int get_image_virtual_size(int fd, const char *format, bool is_block_device, uint64_t *ret) {
        int r;

        assert(fd >= 0);
        assert(format);
        assert(ret);

        if (streq(format, "raw")) {
                if (is_block_device)
                        return blockdev_get_device_size(fd, ret);

                struct stat st;
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat image: %m");

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Raw device is neither a regular file nor a block device");

                *ret = st.st_size;
                return 0;
        }

        if (streq(format, "qcow2")) {
                uint32_t magic = 0;
                ssize_t n = pread(fd, &magic, sizeof(magic), 0);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read qcow2 magic: %m");
                if (n != sizeof(magic) || be32toh(magic) != UINT32_C(0x514649fb))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Not a valid qcow2 image (bad magic)");

                uint64_t size_be = 0;
                n = pread(fd, &size_be, sizeof(size_be), 24);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read qcow2 header: %m");
                if (n != sizeof(size_be))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read on qcow2 header");

                *ret = be64toh(size_be);
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported image format '%s'", format);
}

/* Forward declarations — on_ephemeral_create_concluded routes failures through
 * the shared block-device add callbacks defined further below. */
static int drive_info_add_fail(DriveInfo *d, int error, const char *error_desc);
static int on_add_format_node_stage(QmpClient *client, sd_json_variant *result,
                                    const char *error_desc, int error, void *userdata);
static int on_add_device_add_complete(QmpClient *client, sd_json_variant *result,
                                      const char *error_desc, int error, void *userdata);

/* Continuation state for on_ephemeral_create_concluded: overlay format + device_add. */
typedef struct EphemeralDriveCtx {
        DriveInfo *drive;          /* ref */
        char *overlay_file_node;
        char *base_fmt_node;
} EphemeralDriveCtx;

static EphemeralDriveCtx* ephemeral_drive_ctx_free(EphemeralDriveCtx *ctx) {
        if (!ctx)
                return NULL;
        drive_info_unref(ctx->drive);
        free(ctx->overlay_file_node);
        free(ctx->base_fmt_node);
        return mfree(ctx);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EphemeralDriveCtx *, ephemeral_drive_ctx_free);

static void ephemeral_drive_ctx_free_void(void *p) {
        ephemeral_drive_ctx_free(p);
}

static int on_ephemeral_create_concluded(QmpClient *qmp, void *userdata) {
        _cleanup_(ephemeral_drive_ctx_freep) EphemeralDriveCtx *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fmt_args = NULL, *device_args = NULL;
        _cleanup_(drive_info_unrefp) DriveInfo *slot_ref = NULL;
        DriveInfo *drive = ctx->drive;
        int r;

        assert(qmp);

        /* Open formatted overlay as qcow2 with backing reference */
        QmpFormatNodeParams overlay_fmt_params = {
                .node_name      = drive->qmp_node_name,
                .format         = "qcow2",
                .file_node_name = ctx->overlay_file_node,
                .backing        = ctx->base_fmt_node,
                .flags          = drive->flags & (QMP_DRIVE_DISCARD|QMP_DRIVE_DISCARD_NO_UNREF),
        };
        r = qmp_build_blockdev_add_format(&overlay_fmt_params, &fmt_args);
        if (r < 0)
                return drive_info_add_fail(drive, r, NULL);

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(fmt_args),
                              on_add_format_node_stage, slot_ref);
        if (r < 0)
                return drive_info_add_fail(drive, r, NULL);
        TAKE_PTR(slot_ref);

        r = qmp_build_device_add(drive, &device_args);
        if (r < 0)
                return drive_info_add_fail(drive, r, NULL);

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(device_args),
                              on_add_device_add_complete, slot_ref);
        if (r < 0)
                return drive_info_add_fail(drive, r, NULL);
        TAKE_PTR(slot_ref);

        log_debug("Queued ephemeral drive completion for '%s'", drive->qmp_device_id);
        return 0;
}

/* Base image (read-only) + anonymous qcow2 overlay (read-write). Overlay format
 * and device_add run from the blockdev-create continuation. */
static int qmp_setup_ephemeral_drive(VmspawnQmpBridge *bridge, QmpClient *qmp, DriveInfo *drive) {
        int r;

        assert(bridge);
        assert(qmp);
        assert(drive);
        assert(drive->fd >= 0);
        assert(drive->overlay_fd >= 0);

        drive->bridge = bridge;
        drive->counter = bridge->next_block_counter++;

        _cleanup_free_ char *base_file_node = NULL, *base_fmt_node = NULL, *overlay_file_node = NULL;
        if (asprintf(&drive->qmp_node_name, "vmspawn-%" PRIu64 "-storage", drive->counter) < 0 ||
            asprintf(&drive->qmp_device_id, "vmspawn-%" PRIu64 "-disk", drive->counter) < 0 ||
            asprintf(&base_file_node, "vmspawn-%" PRIu64 "-base-file", drive->counter) < 0 ||
            asprintf(&base_fmt_node, "vmspawn-%" PRIu64 "-base-fmt", drive->counter) < 0 ||
            asprintf(&overlay_file_node, "vmspawn-%" PRIu64 "-overlay-file", drive->counter) < 0)
                return log_oom();

        /* Auto-assigned user id reuses qmp_device_id (matching vmspawn_qmp_add_block_device). */
        if (!drive->id) {
                drive->id = strdup(drive->qmp_device_id);
                if (!drive->id)
                        return log_oom();
        }

        /* Read virtual size before passing the fd to QEMU (TAKE_FD consumes it) */
        uint64_t virtual_size;
        r = get_image_virtual_size(drive->fd, drive->format, FLAGS_SET(drive->flags, QMP_DRIVE_BLOCK_DEVICE), &virtual_size);
        if (r < 0)
                return r;

        /* Step 1-2: Pass both fds to QEMU */
        _cleanup_free_ char *base_path = NULL;
        uint64_t base_fdset_id;
        r = qmp_fdset_add(qmp, TAKE_FD(drive->fd),
                          on_qmp_complete, (void*) "add-fd", &base_path, &base_fdset_id);
        if (r < 0)
                return log_error_errno(r, "Failed to send add-fd for base image '%s': %m", drive->path);

        _cleanup_free_ char *overlay_path = NULL;
        uint64_t overlay_fdset_id;
        r = qmp_fdset_add(qmp, TAKE_FD(drive->overlay_fd),
                          on_qmp_complete, (void*) "add-fd", &overlay_path, &overlay_fdset_id);
        if (r < 0)
                return log_error_errno(r, "Failed to send add-fd for overlay of '%s': %m", drive->path);

        /* Step 3: Base image file node (read-only) */
        QmpFileNodeParams base_file_params = {
                .node_name = base_file_node,
                .filename  = base_path,
                .driver    = FLAGS_SET(drive->flags, QMP_DRIVE_BLOCK_DEVICE) ? "host_device" : "file",
                .flags     = QMP_DRIVE_READ_ONLY | (drive->flags & QMP_DRIVE_NO_FLUSH),
        };
        if (FLAGS_SET(bridge->features, VMSPAWN_QMP_FEATURE_IO_URING))
                base_file_params.flags |= QMP_DRIVE_IO_URING;
        r = qmp_add_file_node(qmp, &base_file_params);
        if (r < 0)
                return log_error_errno(r, "Failed to send blockdev-add for base file '%s': %m", drive->path);

        /* The base file node now holds a dup of the fd; release the monitor's
         * original so the fdset auto-frees when raw_close runs at teardown. */
        r = qmp_fdset_remove(qmp, base_fdset_id, on_qmp_complete, (void*) "remove-fd");
        if (r < 0)
                return log_error_errno(r, "Failed to send remove-fd for base image '%s': %m", drive->path);

        /* Step 4: Base image format node (read-only) */
        QmpFormatNodeParams base_fmt_params = {
                .node_name      = base_fmt_node,
                .format         = drive->format,
                .file_node_name = base_file_node,
                .flags          = QMP_DRIVE_READ_ONLY,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *base_fmt_args = NULL;
        r = qmp_build_blockdev_add_format(&base_fmt_params, &base_fmt_args);
        if (r < 0)
                return r;

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(base_fmt_args), on_qmp_complete, (void*) "blockdev-add");
        if (r < 0)
                return log_error_errno(r, "Failed to send blockdev-add for base format '%s': %m", drive->path);

        /* Step 5: Overlay file node (read-write, no io_uring for anon overlay) */
        QmpFileNodeParams overlay_file_params = {
                .node_name = overlay_file_node,
                .filename  = overlay_path,
                .driver    = "file",
                .flags     = QMP_DRIVE_NO_FLUSH,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *overlay_file_args = NULL;
        r = qmp_build_blockdev_add_file(&overlay_file_params, &overlay_file_args);
        if (r < 0)
                return r;

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(overlay_file_args), on_qmp_complete, (void*) "blockdev-add");
        if (r < 0)
                return log_error_errno(r, "Failed to send blockdev-add for overlay file '%s': %m", drive->path);

        /* Same as for base: the overlay file node has the dup. */
        r = qmp_fdset_remove(qmp, overlay_fdset_id, on_qmp_complete, (void*) "remove-fd");
        if (r < 0)
                return log_error_errno(r, "Failed to send remove-fd for overlay of '%s': %m", drive->path);

        /* Step 6: Fire blockdev-create to format the overlay */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *create_options = NULL;
        r = sd_json_buildo(&create_options,
                        SD_JSON_BUILD_PAIR_STRING("driver", "qcow2"),
                        SD_JSON_BUILD_PAIR_STRING("file", overlay_file_node),
                        SD_JSON_BUILD_PAIR_UNSIGNED("size", virtual_size),
                        SD_JSON_BUILD_PAIR_STRING("backing-file", base_fmt_node),
                        SD_JSON_BUILD_PAIR_STRING("backing-fmt", drive->format));
        if (r < 0)
                return log_error_errno(r, "Failed to build blockdev-create options: %m");

        _cleanup_free_ char *job_id = NULL;
        if (asprintf(&job_id, "vmspawn-%" PRIu64 "-overlay-create", drive->counter) < 0)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd_args = NULL;
        r = sd_json_buildo(&cmd_args,
                        SD_JSON_BUILD_PAIR_STRING("job-id", job_id),
                        SD_JSON_BUILD_PAIR_VARIANT("options", create_options));
        if (r < 0)
                return log_error_errno(r, "Failed to build blockdev-create JSON: %m");

        /* Fold DISCARD_NO_UNREF into drive->flags so the continuation's overlay format blockdev-add
         * picks it up via drive->flags. */
        if (FLAGS_SET(drive->flags, QMP_DRIVE_DISCARD) &&
            FLAGS_SET(bridge->features, VMSPAWN_QMP_FEATURE_DISCARD_NO_UNREF))
                drive->flags |= QMP_DRIVE_DISCARD_NO_UNREF;

        /* Register continuation: when the job concludes, fire overlay format + device_add */
        _cleanup_(ephemeral_drive_ctx_freep) EphemeralDriveCtx *ectx = new(EphemeralDriveCtx, 1);
        if (!ectx)
                return log_oom();

        *ectx = (EphemeralDriveCtx) {
                .drive              = drive_info_ref(drive),
                .overlay_file_node  = strdup(overlay_file_node),
                .base_fmt_node      = strdup(base_fmt_node),
        };
        if (!ectx->overlay_file_node || !ectx->base_fmt_node)
                return log_oom();

        r = vmspawn_qmp_bridge_register_job(bridge, job_id,
                                            on_ephemeral_create_concluded, ectx,
                                            ephemeral_drive_ctx_free_void);
        if (r < 0)
                return log_error_errno(r, "Failed to register job continuation: %m");

        TAKE_PTR(ectx);

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "blockdev-create", QMP_CLIENT_ARGS(cmd_args), on_qmp_complete, (void*) "blockdev-create");
        if (r < 0) {
                _unused_ _cleanup_(pending_job_freep) PendingJob *dead = hashmap_remove(bridge->pending_jobs, job_id);
                return log_error_errno(r, "Failed to send blockdev-create for '%s': %m", drive->path);
        }

        log_debug("Queued ephemeral drive setup for '%s' (job %s)", drive->path, job_id);
        return 0;
}

static int reply_qmp_error(sd_varlink *link, const char *error_desc, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        if (error_desc)
                log_warning("QMP error: %s", error_desc);
        return sd_varlink_error_errno(link, error < 0 ? error : -EIO);
}

/* After the pipelined remove-fd at add time, QEMU auto-frees the fdset when
 * raw_close (during blockdev-del) releases the last dup. Teardown deletes the
 * format node first, then the file node — order matters because the format
 * node holds a strong reference to its `file` child, which would block a
 * file-first del with "Node X is busy: node is used as 'file' of Y". */
static void vmspawn_qmp_block_device_teardown(QmpClient *client,
                                              const char *qmp_node_name,
                                              const char *qmp_file_node_name,
                                              BlockDeviceStateFlags stages) {
        assert(client);

        if (FLAGS_SET(stages, BLOCK_DEVICE_STATE_BLOCKDEV_ADDED) && qmp_node_name) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
                if (sd_json_buildo(&args, SD_JSON_BUILD_PAIR_STRING("node-name", qmp_node_name)) >= 0)
                        (void) qmp_client_invoke(client, /* ret_slot= */ NULL, "blockdev-del", QMP_CLIENT_ARGS(args),
                                                 on_qmp_complete, (void*) "teardown blockdev-del format");
        }

        if (FLAGS_SET(stages, BLOCK_DEVICE_STATE_FILE_NODE_ADDED) && qmp_file_node_name) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
                if (sd_json_buildo(&args, SD_JSON_BUILD_PAIR_STRING("node-name", qmp_file_node_name)) >= 0)
                        (void) qmp_client_invoke(client, /* ret_slot= */ NULL, "blockdev-del", QMP_CLIENT_ARGS(args),
                                                 on_qmp_complete, (void*) "teardown blockdev-del file");
        }
}

/* Insert into the owning primary map and the non-owning qmp_device_id view. On
 * secondary-put failure, roll back the primary so neither map carries a stale entry. */
static int bridge_register_drive(VmspawnQmpBridge *b, DriveInfo *d) {
        int r;

        assert(b);
        assert(d);
        assert(d->id);
        assert(d->qmp_device_id);

        r = hashmap_ensure_put(&b->block_devices, &block_devices_hash_ops,
                               d->id, drive_info_ref(d));
        if (r < 0) {
                drive_info_unref(d);
                return r;
        }

        r = hashmap_ensure_put(&b->block_devices_by_qmp_id, &string_hash_ops,
                               d->qmp_device_id, d);
        if (r < 0) {
                drive_info_unref(hashmap_remove(b->block_devices, d->id));
                return r;
        }

        return 0;
}

/* Drop the drive from both maps; returns the pointer removed from the primary
 * (NULL if it wasn't there) so the caller can decide whether to unref. */
static DriveInfo* bridge_unregister_drive(VmspawnQmpBridge *b, DriveInfo *d) {
        assert(b);
        assert(d);

        hashmap_remove_value(b->block_devices_by_qmp_id, d->qmp_device_id, d);
        return hashmap_remove_value(b->block_devices, d->id, d);
}

/* First-error entry point: marks FAILED so cascading callbacks no-op, drops
 * the registry slot, then replies on the link or exits the loop. */
static int drive_info_add_fail(DriveInfo *d, int error, const char *error_desc) {
        assert(d);

        if (FLAGS_SET(d->state, BLOCK_DEVICE_STATE_ADD_FAILED))
                return 0;

        /* Pin the object alive across bridge_unregister_drive() + drive_info_unref() below. */
        _cleanup_(drive_info_unrefp) DriveInfo *ref = drive_info_ref(d);

        vmspawn_qmp_block_device_teardown(ref->bridge->qmp, ref->qmp_node_name,
                                          ref->qmp_file_node_name, ref->state);
        ref->state = BLOCK_DEVICE_STATE_ADD_FAILED;

        if (bridge_unregister_drive(ref->bridge, ref))
                drive_info_unref(ref);

        if (ref->link) {
                (void) reply_qmp_error(ref->link, error_desc, error);
                ref->link = sd_varlink_unref(ref->link);
                return 0;
        }

        log_error_errno(error, "Block device '%s' setup failed: %s",
                        strna(ref->id), strna(error_desc));

        /* Boot-time (link == NULL) is always fatal — even for late-arriving ephemeral replies. */
        return sd_event_exit(qmp_client_get_event(ref->bridge->qmp), error);
}

/* Rolls back the up-front registry insert on a sync error path. */
static void drive_info_unregister_on_failurep(DriveInfo **dp) {
        assert(dp);

        DriveInfo *d = *dp;
        if (!d)
                return;
        d->state |= BLOCK_DEVICE_STATE_ADD_FAILED;
        if (bridge_unregister_drive(d->bridge, d))
                drive_info_unref(d);
}

/* Shared by the intermediate stages that don't need to record a rollback bit
 * (add-fd, remove-fd). Just forwards errors to drive_info_add_fail so cascades
 * from earlier stage failures get suppressed via the FAILED sentinel. */
static int on_add_observe_stage(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *d = ASSERT_PTR(userdata);
        assert(client);

        if (error < 0)
                return drive_info_add_fail(d, error, error_desc);
        return 0;
}

static int on_add_file_node_stage(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *d = ASSERT_PTR(userdata);
        assert(client);

        if (error < 0)
                return drive_info_add_fail(d, error, error_desc);

        /* A sync error after blockdev-add(file) was queued may have marked the
         * chain FAILED. The file node we just created is orphaned — tear it
         * down retroactively. */
        if (FLAGS_SET(d->state, BLOCK_DEVICE_STATE_ADD_FAILED)) {
                vmspawn_qmp_block_device_teardown(d->bridge->qmp,
                                                  /* qmp_node_name= */ NULL,
                                                  d->qmp_file_node_name,
                                                  BLOCK_DEVICE_STATE_FILE_NODE_ADDED);
                return 0;
        }

        d->state |= BLOCK_DEVICE_STATE_FILE_NODE_ADDED;
        return 0;
}

static int on_add_format_node_stage(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *d = ASSERT_PTR(userdata);
        assert(client);

        if (error < 0)
                return drive_info_add_fail(d, error, error_desc);

        /* A sync error after blockdev-add(format) was queued may have marked
         * the chain FAILED. The format node we just created is orphaned —
         * tear it down retroactively. The file node was already torn down by
         * drive_info_add_fail at original failure time. */
        if (FLAGS_SET(d->state, BLOCK_DEVICE_STATE_ADD_FAILED)) {
                vmspawn_qmp_block_device_teardown(d->bridge->qmp, d->qmp_node_name,
                                                  /* qmp_file_node_name= */ NULL,
                                                  BLOCK_DEVICE_STATE_BLOCKDEV_ADDED);
                return 0;
        }

        d->state |= BLOCK_DEVICE_STATE_BLOCKDEV_ADDED;
        return 0;
}

static int on_add_device_add_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *d = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0)
                return drive_info_add_fail(d, error, error_desc);

        if (FLAGS_SET(d->state, BLOCK_DEVICE_STATE_ADD_FAILED))
                return 0;

        if (d->link) {
                (void) sd_varlink_reply(d->link, NULL);
                d->link = sd_varlink_unref(d->link);
        }

        log_info("Block device '%s' attached", d->id);
        return 0;
}

static int on_scsi_controller_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        assert(client);

        VmspawnQmpBridge *bridge = ASSERT_PTR(qmp_client_get_userdata(client));

        if (error < 0) {
                /* QEMU's device_add is transactional — on error it calls object_unparent()
                 * before replying, so the "vmspawn_scsi" id is free for the next retry. */
                vmspawn_qmp_bridge_release_pcie_port_by_idx(bridge, bridge->scsi_controller_port_idx);
                bridge->scsi_controller_port_idx = -1;
                bridge->scsi_controller_created = false;
                log_warning("virtio-scsi-pci controller setup failed: %s", strna(error_desc));
                if (!bridge->setup_done)
                        return sd_event_exit(qmp_client_get_event(client), error);
        }

        return 0;
}

static int qmp_setup_scsi_controller(VmspawnQmpBridge *bridge, const char *pcie_port) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(bridge);

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-scsi-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmspawn_scsi"),
                        SD_JSON_BUILD_PAIR_CONDITION(!!pcie_port, "bus", SD_JSON_BUILD_STRING(pcie_port)));
        if (r < 0)
                return log_error_errno(r, "Failed to build SCSI controller JSON: %m");

        r = qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(args),
                              on_scsi_controller_complete, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send SCSI controller device_add: %m");

        log_debug("Queued virtio-scsi-pci controller setup");
        return 0;
}

int vmspawn_qmp_add_block_device(VmspawnQmpBridge *bridge, DriveInfo *drive) {
        int r;

        assert(bridge);
        assert(drive);
        assert(drive->format);
        assert(drive->disk_driver);
        assert(drive->fd >= 0);

        _unused_ _cleanup_(drive_info_unrefp) DriveInfo *owned = drive;
        _cleanup_(drive_info_unrefp) DriveInfo *slot_ref = NULL;
        _cleanup_(drive_info_unregister_on_failurep) DriveInfo *registered = NULL;

        drive->bridge = bridge;
        drive->counter = bridge->next_block_counter++;
        if (asprintf(&drive->qmp_node_name, "vmspawn-%" PRIu64 "-storage", drive->counter) < 0)
                return log_oom();
        if (asprintf(&drive->qmp_device_id, "vmspawn-%" PRIu64 "-disk", drive->counter) < 0)
                return log_oom();
        drive->file_generation = 0;
        if (asprintf(&drive->qmp_file_node_name, "vmspawn-%" PRIu64 "-file-%" PRIu64,
                     drive->counter, drive->file_generation) < 0)
                return log_oom();
        /* Auto-assigned user ids reuse qmp_device_id. */
        if (!drive->id) {
                drive->id = strdup(drive->qmp_device_id);
                if (!drive->id)
                        return log_oom();
        }

        /* Reserve the registry slot up-front so the device_add callback's commit can't fail. */
        r = bridge_register_drive(bridge, drive);
        if (r < 0)
                return r;
        registered = drive;

        /* First SCSI hotplug needs a virtio-scsi-pci controller to attach to. */
        if (STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd") && !bridge->scsi_controller_created) {
                _cleanup_free_ char *controller_port = NULL;
                int controller_port_idx = -1;
                if (ARCHITECTURE_NEEDS_PCIE_ROOT_PORTS) {
                        r = vmspawn_qmp_bridge_allocate_pcie_port(bridge, "vmspawn_scsi",
                                                                  &controller_port, &controller_port_idx);
                        if (r == -EBUSY)
                                return log_error_errno(r, "No PCIe hotplug ports left for SCSI controller");
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate PCIe hotplug port for SCSI controller: %m");
                }

                r = qmp_setup_scsi_controller(bridge, controller_port);
                if (r < 0) {
                        vmspawn_qmp_bridge_release_pcie_port_by_idx(bridge, controller_port_idx);
                        return r;
                }

                /* Set before the reply so a second SCSI hotplug queued in the meantime
                 * doesn't re-create the controller; reset in on_scsi_controller_complete on error. */
                bridge->scsi_controller_port_idx = controller_port_idx;
                bridge->scsi_controller_created = true;
        }

        slot_ref = drive_info_ref(drive);
        r = qmp_fdset_add(bridge->qmp, TAKE_FD(drive->fd),
                          on_add_observe_stage, slot_ref, &drive->fdset_path, &drive->fdset_id);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        /* Build flags for the file-level node: RO and NO_FLUSH from the drive
         * plus IO_URING from the bridge feature probe. */
        QmpDriveFlags file_flags = drive->flags & (QMP_DRIVE_READ_ONLY|QMP_DRIVE_NO_FLUSH);
        if (FLAGS_SET(bridge->features, VMSPAWN_QMP_FEATURE_IO_URING))
                file_flags |= QMP_DRIVE_IO_URING;

        QmpFileNodeParams file_params = {
                .node_name = drive->qmp_file_node_name,
                .filename  = drive->fdset_path,
                .driver    = FLAGS_SET(drive->flags, QMP_DRIVE_BLOCK_DEVICE) ? "host_device" : "file",
                .flags     = file_flags,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *file_args = NULL;
        r = qmp_build_blockdev_add_file(&file_params, &file_args);
        if (r < 0)
                return r;

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(file_args),
                              on_add_file_node_stage, slot_ref);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        QmpFormatNodeParams format_params = {
                .node_name      = drive->qmp_node_name,
                .format         = drive->format,
                .file_node_name = drive->qmp_file_node_name,
                .flags          = drive->flags,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *format_args = NULL;
        r = qmp_build_blockdev_add_format(&format_params, &format_args);
        if (r < 0)
                return r;

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(format_args),
                              on_add_format_node_stage, slot_ref);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        /* Release the monitor's original fd; blockdev-add(file) above took a dup. */
        slot_ref = drive_info_ref(drive);
        r = qmp_fdset_remove(bridge->qmp, drive->fdset_id, on_add_observe_stage, slot_ref);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *device_args = NULL;
        r = qmp_build_device_add(drive, &device_args);
        if (r < 0)
                return r;

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(device_args),
                              on_add_device_add_complete, slot_ref);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        TAKE_PTR(registered);
        return 0;
}

static int qmp_setup_regular_drive(VmspawnQmpBridge *bridge, DriveInfo *drive) {
        assert(bridge);
        assert(drive);
        assert(drive->fd >= 0);

        return vmspawn_qmp_add_block_device(bridge, drive);
}

/* device_del completion is just QEMU acking the request; teardown happens
 * in vmspawn_qmp_dispatch_device_deleted() once the guest acks the eject. */
static int on_remove_device_del_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *drive = ASSERT_PTR(userdata);
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = TAKE_PTR(drive->link);

        assert(client);
        assert(link);

        if (error < 0) {
                /* device_del rejected: clear the pending bit so the caller can retry. */
                drive->state &= ~BLOCK_DEVICE_STATE_REMOVE_PENDING;

                return reply_qmp_error(link, error_desc, error);
        }

        return sd_varlink_reply(link, NULL);
}

int vmspawn_qmp_remove_block_device(VmspawnQmpBridge *bridge, sd_varlink *link, const char *id) {
        int r;

        assert(bridge);
        assert(link);
        assert(id);

        DriveInfo *drive = hashmap_get(bridge->block_devices, id);
        if (!drive)
                return sd_varlink_error(link, "io.systemd.MachineInstance.NoSuchStorage", NULL);
        if (!FLAGS_SET(drive->flags, QMP_DRIVE_REMOVABLE))
                return sd_varlink_error(link, "io.systemd.MachineInstance.StorageImmutable", NULL);
        if (!FLAGS_SET(drive->state, BLOCK_DEVICE_STATE_BLOCKDEV_ADDED))
                return reply_qmp_error(link, "Block device add pending", -EBUSY);
        if (FLAGS_SET(drive->state, BLOCK_DEVICE_STATE_REMOVE_PENDING))
                return reply_qmp_error(link, "Block device removal pending", -EBUSY);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_STRING("id", drive->qmp_device_id));
        if (r < 0)
                return sd_varlink_error_errno(link, r);

        assert(!drive->link);
        drive->link = sd_varlink_ref(link);
        drive->state |= BLOCK_DEVICE_STATE_REMOVE_PENDING;

        r = qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "device_del", QMP_CLIENT_ARGS(args),
                              on_remove_device_del_complete, drive_info_ref(drive));
        if (r < 0) {
                drive->link = sd_varlink_unref(drive->link);
                drive->state &= ~BLOCK_DEVICE_STATE_REMOVE_PENDING;
                drive_info_unref(drive);
                return sd_varlink_error_errno(link, r);
        }
        return 0;
}

/* DEVICE_DELETED arrives once the guest has acked the eject; only then is it
 * safe to drop the blockdev node and release the registry slot (and PCIe port). */
int vmspawn_qmp_dispatch_device_deleted(VmspawnQmpBridge *bridge, sd_json_variant *data) {
        assert(bridge);

        if (!data)
                return 0;

        const char *qmp_device_id = sd_json_variant_string(sd_json_variant_by_key(data, "device"));
        if (!qmp_device_id)
                return 0;

        DriveInfo *drive = hashmap_get(bridge->block_devices_by_qmp_id, qmp_device_id);
        if (!drive)
                return 0;

        vmspawn_qmp_block_device_teardown(bridge->qmp, drive->qmp_node_name,
                                          drive->qmp_file_node_name, drive->state);

        assert_se(bridge_unregister_drive(bridge, drive) == drive);
        drive_info_unref(drive);
        return 0;
}

int vmspawn_qmp_setup_network(VmspawnQmpBridge *bridge, NetworkInfo *network) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *netdev_args = NULL, *device_args = NULL;
        bool tap_by_fd;
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
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

                r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "getfd", QMP_CLIENT_ARGS_FD(getfd_args, TAKE_FD(network->fd)),
                                      on_qmp_complete, (void*) "getfd");
                if (r < 0)
                        return log_error_errno(r, "Failed to send getfd for TAP fd: %m");
        }

        /* netdev_add: create the network backend */
        r = sd_json_buildo(
                        &netdev_args,
                        SD_JSON_BUILD_PAIR_STRING("type", network->type),
                        SD_JSON_BUILD_PAIR_STRING("id", "net0"),
                        SD_JSON_BUILD_PAIR_CONDITION(tap_by_fd,
                                                     "fd", JSON_BUILD_CONST_STRING("vmspawn_tap")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && !!network->ifname,
                                                     "ifname", SD_JSON_BUILD_STRING(network->ifname)),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "script", JSON_BUILD_CONST_STRING("no")),
                        SD_JSON_BUILD_PAIR_CONDITION(!tap_by_fd && streq(network->type, "tap"),
                                                     "downscript", JSON_BUILD_CONST_STRING("no")));
        if (r < 0)
                return log_error_errno(r, "Failed to build netdev_add JSON: %m");

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "netdev_add", QMP_CLIENT_ARGS(netdev_args), on_qmp_complete, (void*) "netdev_add");
        if (r < 0)
                return log_error_errno(r, "Failed to send netdev_add: %m");

        /* device_add: attach NIC frontend */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-net-pci"),
                        SD_JSON_BUILD_PAIR_STRING("netdev", "net0"),
                        SD_JSON_BUILD_PAIR_STRING("id", "nic0"),
                        SD_JSON_BUILD_PAIR_CONDITION(network->mac_set,
                                                     "mac", SD_JSON_BUILD_STRING(network->mac_set ? ETHER_ADDR_TO_STR(&network->mac) : NULL)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!network->pcie_port,
                                                     "bus", SD_JSON_BUILD_STRING(network->pcie_port)));
        if (r < 0)
                return log_error_errno(r, "Failed to build NIC device_add JSON: %m");

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
        if (r < 0)
                return log_error_errno(r, "Failed to send NIC device_add: %m");

        log_debug("Queued %s network setup%s", network->type, tap_by_fd ? " (fd via getfd)" : "");
        return 0;
}

static int vmspawn_qmp_setup_one_virtiofs(QmpClient *qmp, const VirtiofsInfo *vfs) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *chardev_args = NULL, *device_args = NULL;
        int r;

        assert(qmp);
        assert(vfs);
        assert(vfs->id);
        assert(vfs->socket_path);
        assert(vfs->tag);

        /* chardev-add: connect to virtiofsd socket.
         * ChardevBackend and SocketAddressLegacy are QAPI legacy unions with explicit "data"
         * wrapper objects at each level — the nesting is mandatory on the wire. */
        r = sd_json_buildo(
                        &chardev_args,
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR("backend", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("type", "socket"),
                                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR("addr", SD_JSON_BUILD_OBJECT(
                                                                        SD_JSON_BUILD_PAIR_STRING("type", "unix"),
                                                                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_OBJECT(
                                                                                        SD_JSON_BUILD_PAIR_STRING("path", vfs->socket_path))))),
                                                        SD_JSON_BUILD_PAIR_BOOLEAN("server", false))))));
        if (r < 0)
                return log_error_errno(r, "Failed to build chardev-add JSON for '%s': %m", vfs->id);

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "chardev-add", QMP_CLIENT_ARGS(chardev_args), on_qmp_complete, (void*) "chardev-add");
        if (r < 0)
                return log_error_errno(r, "Failed to send chardev-add '%s': %m", vfs->id);

        /* device_add: create vhost-user-fs-pci device */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-user-fs-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("chardev", vfs->id),
                        SD_JSON_BUILD_PAIR_STRING("tag", vfs->tag),
                        SD_JSON_BUILD_PAIR_UNSIGNED("queue-size", 1024),
                        SD_JSON_BUILD_PAIR_CONDITION(!!vfs->pcie_port,
                                                     "bus", SD_JSON_BUILD_STRING(vfs->pcie_port)));
        if (r < 0)
                return log_error_errno(r, "Failed to build virtiofs device_add JSON for '%s': %m", vfs->id);

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
        if (r < 0)
                return log_error_errno(r, "Failed to send virtiofs device_add '%s': %m", vfs->id);

        log_debug("Queued virtiofs device '%s' (tag=%s)", vfs->id, vfs->tag);
        return 0;
}

int vmspawn_qmp_setup_virtiofs(VmspawnQmpBridge *bridge, const VirtiofsInfos *virtiofs) {
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
        assert(virtiofs);

        FOREACH_ARRAY(e, virtiofs->entries, virtiofs->n_entries) {
                r = vmspawn_qmp_setup_one_virtiofs(qmp, e);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_qmp_setup_vsock(VmspawnQmpBridge *bridge, VsockInfo *vsock) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL, *device_args = NULL;
        int r;

        assert(bridge);
        assert(vsock);

        if (vsock->fd < 0)
                return 0;

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

        /* getfd: pass the vhost-vsock fd to QEMU via SCM_RIGHTS */
        r = sd_json_buildo(
                        &getfd_args,
                        SD_JSON_BUILD_PAIR_STRING("fdname", "vmspawn_vsock"));
        if (r < 0)
                return log_error_errno(r, "Failed to build getfd JSON for VSOCK: %m");

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "getfd", QMP_CLIENT_ARGS_FD(getfd_args, TAKE_FD(vsock->fd)),
                              on_qmp_complete, (void*) "getfd");
        if (r < 0)
                return log_error_errno(r, "Failed to send getfd for VSOCK fd: %m");

        /* device_add: create vhost-vsock-pci device referencing the named fd */
        r = sd_json_buildo(
                        &device_args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vhost-vsock-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vsock0"),
                        SD_JSON_BUILD_PAIR_UNSIGNED("guest-cid", vsock->cid),
                        SD_JSON_BUILD_PAIR_STRING("vhostfd", "vmspawn_vsock"),
                        SD_JSON_BUILD_PAIR_CONDITION(!!vsock->pcie_port,
                                                     "bus", SD_JSON_BUILD_STRING(vsock->pcie_port)));
        if (r < 0)
                return log_error_errno(r, "Failed to build VSOCK device_add JSON: %m");

        r = qmp_client_invoke(qmp, /* ret_slot= */ NULL, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
        if (r < 0)
                return log_error_errno(r, "Failed to send VSOCK device_add: %m");

        log_debug("Queued vhost-vsock-pci device setup (cid=%u)", vsock->cid);
        return 0;
}

int vmspawn_qmp_setup_drives(VmspawnQmpBridge *bridge, DriveInfos *drives) {
        int r;

        assert(bridge);
        assert(drives);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

        /* io_uring support was probed during vmspawn_qmp_init(). The cached result in
         * bridge->features is passed to each file node setup call. SCSI controller
         * creation is handled on-demand by vmspawn_qmp_add_block_device() for the first
         * SCSI drive, using the hotplug-spares pool. */

        FOREACH_ARRAY(d, drives->drives, drives->n_drives) {
                if ((*d)->overlay_fd >= 0)
                        r = qmp_setup_ephemeral_drive(bridge, qmp, *d);
                else
                        r = qmp_setup_regular_drive(bridge, TAKE_PTR(*d));
                if (r < 0)
                        return r;
        }

        return 0;
}

PendingJob* pending_job_free(PendingJob *j) {
        if (!j)
                return NULL;
        if (j->free_userdata)
                j->free_userdata(j->userdata);
        return mfree(j);
}

VmspawnQmpBridge* vmspawn_qmp_bridge_free(VmspawnQmpBridge *b) {
        if (!b)
                return NULL;

        /* Unref first: pending QMP callbacks may release hotplug ports through the bridge. */
        qmp_client_unref(b->qmp);

        hashmap_free(b->block_devices_by_qmp_id);
        hashmap_free(b->block_devices);
        hashmap_free(b->pending_jobs);

        FOREACH_ELEMENT(owner, b->hotplug_port_owner)
                free(*owner);

        return mfree(b);
}

int vmspawn_qmp_bridge_register_job(
                VmspawnQmpBridge *b,
                const char *job_id,
                pending_job_callback_t on_concluded,
                void *userdata,
                pending_job_free_t free_userdata) {

        _cleanup_free_ PendingJob *job = NULL;
        _cleanup_free_ char *id = NULL;
        int r;

        assert(b);
        assert(job_id);

        id = strdup(job_id);
        if (!id)
                return -ENOMEM;

        job = new(PendingJob, 1);
        if (!job)
                return -ENOMEM;

        *job = (PendingJob) {
                .on_concluded  = on_concluded,
                .free_userdata = free_userdata,
                .userdata      = userdata,
        };

        r = hashmap_ensure_put(&b->pending_jobs, &pending_job_hash_ops, id, job);
        if (r < 0)
                return r;

        TAKE_PTR(id);
        TAKE_PTR(job);
        return 0;
}

QmpClient* vmspawn_qmp_bridge_get_qmp(VmspawnQmpBridge *b) {
        assert(b);
        return b->qmp;
}

/* Probe-reply convention: ignore -EIO (QMP rejection = "feature absent", log at debug
 * and leave the feature flag clear) and transport errors (caught by the post-loop
 * qmp_client_is_disconnected() check in vmspawn_qmp_probe_features()). Cleanup calls
 * are best-effort — failing to delete a private probe node leaves a harmless /dev/null
 * blockdev in QEMU until it exits. */

static int on_io_uring_probe_del_reply(
                QmpClient *c,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        assert(c);

        if (error_desc)
                log_debug("Failed to remove io_uring probe node: %s", error_desc);
        return 0;
}

static int on_io_uring_probe_add_reply(
                QmpClient *c,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnQmpBridge *bridge = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *del_args = NULL;
        int r;

        assert(c);

        if (error < 0 && !error_desc)
                return log_debug_errno(error, "io_uring probe did not execute: %m");
        if (error_desc) {
                log_debug("QEMU does not support aio=io_uring: %s", error_desc);
                return 0;
        }

        bridge->features |= VMSPAWN_QMP_FEATURE_IO_URING;
        log_debug("QEMU supports aio=io_uring");

        /* Best-effort cleanup; the chained reply keeps the pump busy via the slots set. */
        r = sd_json_buildo(&del_args,
                        SD_JSON_BUILD_PAIR_STRING("node-name", "__io_uring_probe"));
        if (r < 0)
                return r;

        return qmp_client_invoke(c, /* ret_slot= */ NULL, "blockdev-del", QMP_CLIENT_ARGS(del_args),
                        on_io_uring_probe_del_reply, bridge);
}

static int probe_io_uring(QmpClient *c, VmspawnQmpBridge *bridge) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        assert(c);
        assert(bridge);

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("node-name", "__io_uring_probe"),
                        SD_JSON_BUILD_PAIR_STRING("driver", "file"),
                        SD_JSON_BUILD_PAIR_STRING("filename", "/dev/null"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("read-only", true),
                        SD_JSON_BUILD_PAIR_STRING("aio", "io_uring"));
        if (r < 0)
                return r;

        return qmp_client_invoke(c, /* ret_slot= */ NULL, "blockdev-add", QMP_CLIENT_ARGS(args),
                        on_io_uring_probe_add_reply, bridge);
}

static int on_probe_schema_reply(
                QmpClient *c,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        VmspawnQmpBridge *bridge = ASSERT_PTR(userdata);

        assert(c);

        if (error < 0 && !error_desc)
                return log_debug_errno(error, "query-qmp-schema probe did not execute: %m");
        if (error_desc) {
                log_debug("query-qmp-schema rejected: %s", error_desc);
                return 0;
        }

        if (qmp_schema_has_member(result, "discard-no-unref")) {
                bridge->features |= VMSPAWN_QMP_FEATURE_DISCARD_NO_UNREF;
                log_debug("QEMU supports qcow2 discard-no-unref");
        } else
                log_debug("QEMU does not support qcow2 discard-no-unref");

        return 0;
}

static int probe_schema(QmpClient *c, VmspawnQmpBridge *bridge) {
        assert(c);
        assert(bridge);

        return qmp_client_invoke(c, /* ret_slot= */ NULL, "query-qmp-schema", QMP_CLIENT_ARGS(NULL),
                        on_probe_schema_reply, bridge);
}

int vmspawn_qmp_init(VmspawnQmpBridge **ret, int fd, sd_event *event) {
        _cleanup_(vmspawn_qmp_bridge_freep) VmspawnQmpBridge *bridge = NULL;
        int r;

        assert(ret);
        assert(fd >= 0);
        assert(event);

        bridge = new0(VmspawnQmpBridge, 1);
        if (!bridge)
                return log_oom();

        bridge->scsi_controller_port_idx = -1;

        r = qmp_client_connect_fd(&bridge->qmp, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to create QMP client: %m");

        r = qmp_client_set_description(bridge->qmp, "vmspawn-qmp-client");
        if (r < 0)
                return log_error_errno(r, "Failed to set QMP client description: %m");

        r = qmp_client_attach_event(bridge->qmp, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach QMP client to event loop: %m");

        *ret = TAKE_PTR(bridge);
        return 0;
}

int vmspawn_qmp_probe_features(VmspawnQmpBridge *bridge) {
        int r;

        assert(bridge);

        /* probe_io_uring() and probe_schema() both call qmp_client_invoke(), which internally
         * drives the handshake to RUNNING via qmp_client_ensure_running() on its first call. */
        r = probe_io_uring(bridge->qmp, bridge);
        if (r < 0)
                return log_error_errno(r, "Failed to issue io_uring probe: %m");

        r = probe_schema(bridge->qmp, bridge);
        if (r < 0)
                return log_error_errno(r, "Failed to issue schema probe: %m");

        /* Canonical sync-on-async pump, matching varlink_call_internal(). The QMP client tracks
         * outstanding replies in its own slots set; drain until it's idle. */
        while (!qmp_client_is_idle(bridge->qmp)) {
                r = qmp_client_process(bridge->qmp);
                if (r < 0)
                        return log_error_errno(r, "QMP probe pump failed: %m");
                if (r > 0)
                        continue;

                r = qmp_client_wait(bridge->qmp, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "QMP probe wait failed: %m");
        }

        /* If fail_pending() drained the slots (transport dropped mid-probe), features can't be
         * trusted and we have no QMP channel for device setup anyway. */
        if (qmp_client_is_disconnected(bridge->qmp))
                return log_error_errno(SYNTHETIC_ERRNO(ECONNRESET),
                                       "QMP connection dropped during feature probing");

        return 0;
}

static int on_cont_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        assert(client);

        VmspawnQmpBridge *bridge = ASSERT_PTR(userdata);

        if (error < 0) {
                log_error_errno(error, "Failed to resume QEMU execution: %s", strna(error_desc));
                return sd_event_exit(qmp_client_get_event(client), error);
        }

        /* VM is running — all boot-time device setup has completed. */
        bridge->setup_done = true;
        return 0;
}

int vmspawn_qmp_start(VmspawnQmpBridge *bridge) {
        assert(bridge);

        return qmp_client_invoke(bridge->qmp, /* ret_slot= */ NULL, "cont", /* args= */ NULL, on_cont_complete, bridge);
}
