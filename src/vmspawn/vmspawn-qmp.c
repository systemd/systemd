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

int vmspawn_qmp_bridge_allocate_pcie_port(VmspawnQmpBridge *bridge, const char *owner_id, char **ret_name, int *ret_idx) {
        assert(bridge);
        assert(owner_id);
        assert(ret_name);
        assert(ret_idx);

        for (unsigned i = 0; i < VMSPAWN_PCIE_HOTPLUG_SPARES; i++) {
                if (bridge->hotplug_port_owner[i])
                        continue;

                _cleanup_free_ char *owner = strdup(owner_id);
                _cleanup_free_ char *name = NULL;
                if (!owner || asprintf(&name, "vmspawn-hotplug-pci-root-port-%u", i) < 0)
                        return -ENOMEM;

                bridge->hotplug_port_owner[i] = TAKE_PTR(owner);
                *ret_name = TAKE_PTR(name);
                *ret_idx = (int) i;
                return 0;
        }

        return -EBUSY;
}

void vmspawn_qmp_bridge_release_pcie_port_by_idx(VmspawnQmpBridge *bridge, int idx) {
        assert(bridge);

        if (idx < 0)
                return;

        assert((unsigned) idx < VMSPAWN_PCIE_HOTPLUG_SPARES);
        bridge->hotplug_port_owner[idx] = mfree(bridge->hotplug_port_owner[idx]);
}

int vmspawn_qmp_bridge_release_pcie_port_by_id(VmspawnQmpBridge *bridge, const char *owner_id) {
        assert(bridge);
        assert(owner_id);

        for (unsigned i = 0; i < VMSPAWN_PCIE_HOTPLUG_SPARES; i++)
                if (streq_ptr(bridge->hotplug_port_owner[i], owner_id)) {
                        bridge->hotplug_port_owner[i] = mfree(bridge->hotplug_port_owner[i]);
                        return 1;
                }

        return 0;
}

DriveInfo* drive_info_ref(DriveInfo *d) {
        if (!d)
                return NULL;

        assert(d->n_ref > 0);
        d->n_ref++;
        return d;
}

DriveInfo* drive_info_unref(DriveInfo *d) {
        if (!d)
                return NULL;

        assert(d->n_ref > 0);
        if (--d->n_ref > 0)
                return NULL;

        if (d->bridge)
                vmspawn_qmp_bridge_release_pcie_port_by_idx(d->bridge, d->pcie_port_idx);

        free(d->path);
        free(d->format);
        free(d->disk_driver);
        free(d->serial);
        free(d->pcie_port);
        free(d->id);
        free(d->fdset_path);
        sd_varlink_unref(d->link);
        safe_close(d->fd);
        safe_close(d->overlay_fd);
        return mfree(d);
}

void drive_infos_done(DriveInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(d, infos->drives, infos->n_drives)
                drive_info_unref(*d);
        infos->drives = mfree(infos->drives);
        infos->n_drives = 0;
        infos->scsi_pcie_port = mfree(infos->scsi_pcie_port);
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

        r = qmp_client_invoke(qmp, "add-fd", QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd)),
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

        return qmp_client_invoke(qmp, "remove-fd", QMP_CLIENT_ARGS(args),
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

/* qmp_name is the fully-qualified QMP name ("bd-<id>"); used as both the
 * qdev id and the drive-backend reference. */
static int qmp_build_device_add(const DriveInfo *drive, const char *qmp_name, sd_json_variant **ret) {
        assert(drive);
        assert(qmp_name);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("driver", drive->disk_driver),
                        SD_JSON_BUILD_PAIR_STRING("drive", qmp_name),
                        SD_JSON_BUILD_PAIR_STRING("id", qmp_name),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(drive->flags, QMP_DRIVE_BOOT), "bootindex", SD_JSON_BUILD_INTEGER(1)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!drive->serial, "serial", SD_JSON_BUILD_STRING(drive->serial)),
                        SD_JSON_BUILD_PAIR_CONDITION(STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"),
                                                    "bus", JSON_BUILD_CONST_STRING("vmspawn_scsi.0")),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd") && !!drive->pcie_port,
                                        "bus", SD_JSON_BUILD_STRING(drive->pcie_port)));
}

/* Inline form: one blockdev-add creates format+file; one blockdev-del tears
 * down the whole tree. Used for regular boot drives and hotplug. */
static int qmp_build_blockdev_add_inline(
                const char *node_name,
                const char *format,
                const char *filename,
                const char *file_driver,
                QmpDriveFlags flags,
                VmspawnQmpFeatureFlags features,
                sd_json_variant **ret) {

        bool use_io_uring = FLAGS_SET(features, VMSPAWN_QMP_FEATURE_IO_URING);
        bool use_discard_no_unref = FLAGS_SET(flags, QMP_DRIVE_DISCARD_NO_UNREF);

        assert(node_name);
        assert(format);
        assert(filename);
        assert(file_driver);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", format),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(flags, QMP_DRIVE_READ_ONLY), "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(flags, QMP_DRIVE_DISCARD), "discard", JSON_BUILD_CONST_STRING("unmap")),
                        SD_JSON_BUILD_PAIR_CONDITION(use_discard_no_unref, "discard-no-unref", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR("file", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("driver", file_driver),
                                        SD_JSON_BUILD_PAIR_STRING("filename", filename),
                                        SD_JSON_BUILD_PAIR_CONDITION(FLAGS_SET(flags, QMP_DRIVE_READ_ONLY), "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                                        SD_JSON_BUILD_PAIR_CONDITION(use_io_uring, "aio", JSON_BUILD_CONST_STRING("io_uring")),
                                        SD_JSON_BUILD_PAIR("cache", SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_BOOLEAN("direct", false),
                                                        SD_JSON_BUILD_PAIR_BOOLEAN("no-flush", FLAGS_SET(flags, QMP_DRIVE_NO_FLUSH)))))));
}

/* Issue blockdev-add for a file node. */
static int qmp_add_file_node(QmpClient *qmp, const QmpFileNodeParams *p) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        int r;

        r = qmp_build_blockdev_add_file(p, &args);
        if (r < 0)
                return r;

        return qmp_client_invoke(qmp, "blockdev-add", QMP_CLIENT_ARGS(args), on_qmp_complete, (void*) "blockdev-add");
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

/* Ephemeral drive continuation — fired when the blockdev-create job concludes.
 * Completes the drive setup by adding the overlay format node and the device. */
typedef struct EphemeralDriveCtx {
        char *node_name;           /* overlay format node name (= drive node name) */
        char *overlay_file_node;
        char *base_fmt_node;
        /* Fields for device_add */
        char *disk_driver;
        char *serial;              /* NULL if unset */
        char *pcie_port;           /* pcie-root-port bus for device_add (NULL on non-PCIe) */
        QmpDriveFlags flags;       /* subset: QMP_DRIVE_DISCARD, QMP_DRIVE_DISCARD_NO_UNREF, QMP_DRIVE_BOOT */
} EphemeralDriveCtx;

static EphemeralDriveCtx* ephemeral_drive_ctx_free(EphemeralDriveCtx *ctx) {
        if (!ctx)
                return NULL;
        free(ctx->node_name);
        free(ctx->overlay_file_node);
        free(ctx->base_fmt_node);
        free(ctx->disk_driver);
        free(ctx->serial);
        free(ctx->pcie_port);
        return mfree(ctx);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EphemeralDriveCtx *, ephemeral_drive_ctx_free);

static void ephemeral_drive_ctx_free_void(void *p) {
        ephemeral_drive_ctx_free(p);
}

static int on_ephemeral_create_concluded(QmpClient *qmp, void *userdata) {
        _cleanup_(ephemeral_drive_ctx_freep) EphemeralDriveCtx *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fmt_args = NULL, *device_args = NULL;
        int r;

        /* Open formatted overlay as qcow2 with backing reference */
        QmpFormatNodeParams overlay_fmt_params = {
                .node_name      = ctx->node_name,
                .format         = "qcow2",
                .file_node_name = ctx->overlay_file_node,
                .backing        = ctx->base_fmt_node,
                .flags          = ctx->flags & (QMP_DRIVE_DISCARD|QMP_DRIVE_DISCARD_NO_UNREF),
        };
        r = qmp_build_blockdev_add_format(&overlay_fmt_params, &fmt_args);
        if (r < 0)
                return log_error_errno(r, "Failed to build overlay format JSON for '%s': %m", ctx->node_name);

        r = qmp_client_invoke(qmp, "blockdev-add", QMP_CLIENT_ARGS(fmt_args), on_qmp_complete, (void*) "blockdev-add");
        if (r < 0)
                return r;

        /* device_add: attach to virtual hardware. Build a temporary DriveInfo as a
         * read-only view into the continuation context to reuse qmp_build_device_add().
         * ctx->node_name is already the bd-prefixed QMP name. */
        const DriveInfo tmp = {
                .disk_driver = ctx->disk_driver,
                .serial      = ctx->serial,
                .pcie_port   = ctx->pcie_port,
                .flags       = ctx->flags & QMP_DRIVE_BOOT,
                .fd          = -EBADF,
                .overlay_fd  = -EBADF,
        };
        r = qmp_build_device_add(&tmp, ctx->node_name, &device_args);
        if (r < 0)
                return log_error_errno(r, "Failed to build device_add JSON for '%s': %m", ctx->node_name);

        r = qmp_client_invoke(qmp, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
        if (r < 0)
                return r;

        log_debug("Queued ephemeral drive completion for '%s'", ctx->node_name);
        return 0;
}

/* Set up an ephemeral drive: base image (read-only) + anonymous qcow2 overlay (read-write).
 * The final steps (overlay format + device_add) are deferred to a job continuation that
 * fires when the blockdev-create job concludes. */
static int qmp_setup_ephemeral_drive(VmspawnQmpBridge *bridge, QmpClient *qmp, DriveInfo *drive) {
        int r;

        assert(bridge);
        assert(qmp);
        assert(drive);
        assert(drive->fd >= 0);
        assert(drive->overlay_fd >= 0);

        _cleanup_free_ char *drive_id = NULL;
        if (asprintf(&drive_id, "bd%" PRIu64, bridge->next_id++) < 0)
                return log_oom();

        /* QMP names all carry the bd- prefix so DEVICE_DELETED filtering works
         * uniformly across ephemeral, boot-time, and hotplug drives. */
        _cleanup_free_ char *qmp_name = strjoin(QMP_BLOCK_QDEV_PREFIX, drive_id);
        if (!qmp_name)
                return log_oom();

        _cleanup_free_ char *base_file_node = strjoin(qmp_name, "-base-file");
        _cleanup_free_ char *base_fmt_node = strjoin(qmp_name, "-base-fmt");
        _cleanup_free_ char *overlay_file_node = strjoin(qmp_name, "-overlay-file");
        if (!base_file_node || !base_fmt_node || !overlay_file_node)
                return log_oom();

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

        r = qmp_client_invoke(qmp, "blockdev-add", QMP_CLIENT_ARGS(base_fmt_args), on_qmp_complete, (void*) "blockdev-add");
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

        r = qmp_client_invoke(qmp, "blockdev-add", QMP_CLIENT_ARGS(overlay_file_args), on_qmp_complete, (void*) "blockdev-add");
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

        _cleanup_free_ char *job_id = strjoin("create-", qmp_name);
        if (!job_id)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd_args = NULL;
        r = sd_json_buildo(&cmd_args,
                        SD_JSON_BUILD_PAIR_STRING("job-id", job_id),
                        SD_JSON_BUILD_PAIR_VARIANT("options", create_options));
        if (r < 0)
                return log_error_errno(r, "Failed to build blockdev-create JSON: %m");

        /* Register continuation: when the job concludes, fire overlay format + device_add */
        _cleanup_(ephemeral_drive_ctx_freep) EphemeralDriveCtx *ectx = new(EphemeralDriveCtx, 1);
        if (!ectx)
                return log_oom();

        QmpDriveFlags ectx_flags = drive->flags & (QMP_DRIVE_DISCARD|QMP_DRIVE_BOOT);
        if (FLAGS_SET(drive->flags, QMP_DRIVE_DISCARD) &&
            FLAGS_SET(bridge->features, VMSPAWN_QMP_FEATURE_DISCARD_NO_UNREF))
                ectx_flags |= QMP_DRIVE_DISCARD_NO_UNREF;

        *ectx = (EphemeralDriveCtx) {
                .node_name          = strdup(qmp_name),
                .overlay_file_node  = strdup(overlay_file_node),
                .base_fmt_node      = strdup(base_fmt_node),
                .disk_driver        = strdup(drive->disk_driver),
                .serial             = drive->serial ? strdup(drive->serial) : NULL,
                .pcie_port          = drive->pcie_port ? strdup(drive->pcie_port) : NULL,
                .flags              = ectx_flags,
        };
        if (!ectx->node_name || !ectx->overlay_file_node || !ectx->base_fmt_node ||
            !ectx->disk_driver || (drive->serial && !ectx->serial) ||
            (drive->pcie_port && !ectx->pcie_port))
                return log_oom();

        r = vmspawn_qmp_bridge_register_job(bridge, job_id,
                                            on_ephemeral_create_concluded, ectx,
                                            ephemeral_drive_ctx_free_void);
        if (r < 0)
                return log_error_errno(r, "Failed to register job continuation: %m");

        TAKE_PTR(ectx);

        r = qmp_client_invoke(qmp, "blockdev-create", QMP_CLIENT_ARGS(cmd_args), on_qmp_complete, (void*) "blockdev-create");
        if (r < 0) {
                _cleanup_(pending_job_freep) PendingJob *dead = hashmap_remove(bridge->pending_jobs, job_id);
                return log_error_errno(r, "Failed to send blockdev-create for '%s': %m", drive->path);
        }

        log_debug("Queued ephemeral drive setup for '%s' (job %s)", drive->path, job_id);
        return 0;
}

static int qmp_setup_regular_drive(VmspawnQmpBridge *bridge, DriveInfo *drive) {
        _cleanup_(drive_info_unrefp) DriveInfo *owned = drive;

        assert(bridge);
        assert(drive);
        assert(drive->fd >= 0);
        assert(!drive->id);

        if (asprintf(&owned->id, "bd%" PRIu64, bridge->next_id) < 0)
                return log_oom();
        bridge->next_id++;

        return vmspawn_qmp_add_block_device(bridge, TAKE_PTR(owned));
}

static int reply_qmp_error(sd_varlink *link, const char *error_desc, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        if (error_desc)
                log_warning("QMP error: %s", error_desc);
        return sd_varlink_error_errno(link, error < 0 ? error : -EIO);
}

static int reply_qmp_add_error(sd_varlink *link, const char *error_desc, int error) {
        assert(link);

        /* Exact prefixes asserted verbatim in QEMU's iotests (tests/qemu-iotests/087.out);
         * stable since QEMU 6.0 (blockdev-add) / 6.2 (device_add). */
        if (error_desc &&
            (startswith(error_desc, "Duplicate nodes with node-name=") ||
             startswith(error_desc, "Duplicate device ID ")))
                return sd_varlink_error(link, "io.systemd.VirtualMachineInstance.BlockDeviceIdInUse", NULL);
        return reply_qmp_error(link, error_desc, error);
}

/* After the pipelined remove-fd at add time, QEMU auto-frees the fdset when
 * raw_close (during blockdev-del) releases the last dup. So teardown only
 * needs to fire blockdev-del. */
void vmspawn_qmp_block_device_teardown(QmpClient *client, const char *id, unsigned stages) {
        assert(client);
        assert(id);

        if (!FLAGS_SET(stages, BLOCK_DEVICE_ADD_STAGE_BLOCKDEV_ADD))
                return;

        _cleanup_free_ char *qmp_name = strjoin(QMP_BLOCK_QDEV_PREFIX, id);
        if (!qmp_name) {
                (void) log_oom();
                return;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        if (sd_json_buildo(&args, SD_JSON_BUILD_PAIR_STRING("node-name", qmp_name)) >= 0)
                (void) qmp_client_invoke(client, "blockdev-del", QMP_CLIENT_ARGS(args),
                                         on_qmp_complete, (void*) "teardown blockdev-del");
}

/* FAILED bit marks the rollback_mask after the first error fires, so cascading
 * stage callbacks become no-ops. Hotplug replies to the link; boot-time tears
 * down the event loop. */
static int drive_info_add_fail(DriveInfo *d, int error, const char *error_desc) {
        assert(d);

        if (FLAGS_SET(d->rollback_mask, BLOCK_DEVICE_ADD_STAGE_FAILED))
                return 0;

        vmspawn_qmp_block_device_teardown(d->bridge->qmp, d->id, d->rollback_mask);
        d->rollback_mask = BLOCK_DEVICE_ADD_STAGE_FAILED;

        if (d->link) {
                (void) reply_qmp_add_error(d->link, error_desc, error);
                d->link = sd_varlink_unref(d->link);
                return 0;
        }

        log_error_errno(error, "Block device '%s' setup failed: %s",
                        strna(d->id), strna(error_desc));
        return sd_event_exit(qmp_client_get_event(d->bridge->qmp), error);
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

static int on_add_blockdev_stage(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(drive_info_unrefp) DriveInfo *d = ASSERT_PTR(userdata);
        assert(client);

        if (error < 0)
                return drive_info_add_fail(d, error, error_desc);

        d->rollback_mask |= BLOCK_DEVICE_ADD_STAGE_BLOCKDEV_ADD;

        /* A sync error after blockdev-add was queued may have marked the chain FAILED.
         * The blockdev node we just created is orphaned — tear it down retroactively. */
        if (FLAGS_SET(d->rollback_mask, BLOCK_DEVICE_ADD_STAGE_FAILED))
                vmspawn_qmp_block_device_teardown(d->bridge->qmp, d->id,
                                                  BLOCK_DEVICE_ADD_STAGE_BLOCKDEV_ADD);
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

        if (FLAGS_SET(d->rollback_mask, BLOCK_DEVICE_ADD_STAGE_FAILED))
                return 0;

        /* Commit: port stays reserved under owner id until DEVICE_DELETED. */
        d->pcie_port_idx = -1;

        if (d->link)
                (void) sd_varlink_replybo(d->link, SD_JSON_BUILD_PAIR_STRING("id", d->id));

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
                vmspawn_qmp_bridge_release_pcie_port_by_idx(bridge, bridge->scsi_controller_port_idx);
                bridge->scsi_controller_port_idx = -1;
                bridge->scsi_controller_created = false;
                log_warning("virtio-scsi-pci controller setup failed: %s", strna(error_desc));
                if (!bridge->setup_done)
                        return sd_event_exit(qmp_client_get_event(client), error);
                return 0;
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

        r = qmp_client_invoke(bridge->qmp, "device_add", QMP_CLIENT_ARGS(args),
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
        assert(drive->id);
        assert(drive->format);
        assert(drive->disk_driver);
        assert(drive->fd >= 0);

        _cleanup_(drive_info_unrefp) DriveInfo *owned = drive, *slot_ref = NULL;
        drive->bridge = bridge;

        _cleanup_free_ char *qmp_name = strjoin(QMP_BLOCK_QDEV_PREFIX, drive->id);
        if (!qmp_name)
                return log_oom();

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
                                return log_oom();
                }

                r = qmp_setup_scsi_controller(bridge, controller_port);
                if (r < 0) {
                        vmspawn_qmp_bridge_release_pcie_port_by_idx(bridge, controller_port_idx);
                        return r;
                }

                /* Flip the flag before returning to the event loop so a second SCSI
                 * hotplug queued before the device_add reply doesn't re-create the
                 * controller. Reset in the error path of on_scsi_controller_complete. */
                bridge->scsi_controller_port_idx = controller_port_idx;
                bridge->scsi_controller_created = true;
        }

        uint64_t fdset_id;
        slot_ref = drive_info_ref(drive);
        r = qmp_fdset_add(bridge->qmp, TAKE_FD(drive->fd),
                          on_add_observe_stage, slot_ref, &drive->fdset_path, &fdset_id);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *blockdev_args = NULL;
        r = qmp_build_blockdev_add_inline(
                        qmp_name, drive->format, drive->fdset_path,
                        FLAGS_SET(drive->flags, QMP_DRIVE_BLOCK_DEVICE) ? "host_device" : "file",
                        drive->flags, bridge->features, &blockdev_args);
        if (r < 0)
                return r;

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(bridge->qmp, "blockdev-add", QMP_CLIENT_ARGS(blockdev_args),
                              on_add_blockdev_stage, slot_ref);
        if (r < 0)
                return r;
        TAKE_PTR(slot_ref);

        /* Release the monitor's original fd; the blockdev-add above took a dup.
         * From this point on, blockdev-add is live in QEMU's command queue, so a sync
         * error here must mark FAILED — the blockdev-add callback will see it and
         * issue retroactive teardown. */
        slot_ref = drive_info_ref(drive);
        r = qmp_fdset_remove(bridge->qmp, fdset_id, on_add_observe_stage, slot_ref);
        if (r < 0) {
                drive->rollback_mask |= BLOCK_DEVICE_ADD_STAGE_FAILED;
                return r;
        }
        TAKE_PTR(slot_ref);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *device_args = NULL;
        r = qmp_build_device_add(drive, qmp_name, &device_args);
        if (r < 0) {
                drive->rollback_mask |= BLOCK_DEVICE_ADD_STAGE_FAILED;
                return r;
        }

        slot_ref = drive_info_ref(drive);
        r = qmp_client_invoke(bridge->qmp, "device_add", QMP_CLIENT_ARGS(device_args),
                              on_add_device_add_complete, slot_ref);
        if (r < 0) {
                drive->rollback_mask |= BLOCK_DEVICE_ADD_STAGE_FAILED;
                return r;
        }
        TAKE_PTR(slot_ref);

        TAKE_PTR(owned);
        return 0;
}

static int on_remove_device_del_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error < 0) {
                if (error_desc && strstr(error_desc, "not found"))
                        return sd_varlink_error(link, "io.systemd.VirtualMachineInstance.NoSuchBlockDevice", NULL);
                return reply_qmp_error(link, error_desc, error);
        }

        return sd_varlink_reply(link, NULL);
}

int vmspawn_qmp_remove_block_device(VmspawnQmpBridge *bridge, sd_varlink *link, const char *id) {
        int r;

        assert(bridge);
        assert(link);
        assert(id);

        _cleanup_free_ char *qmp_name = strjoin(QMP_BLOCK_QDEV_PREFIX, id);
        if (!qmp_name)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_STRING("id", qmp_name));
        if (r < 0)
                return r;

        sd_varlink_ref(link);
        r = qmp_client_invoke(bridge->qmp, "device_del", QMP_CLIENT_ARGS(args),
                              on_remove_device_del_complete, link);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }
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

                r = qmp_client_invoke(qmp, "getfd", QMP_CLIENT_ARGS_FD(getfd_args, TAKE_FD(network->fd)),
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

        r = qmp_client_invoke(qmp, "netdev_add", QMP_CLIENT_ARGS(netdev_args), on_qmp_complete, (void*) "netdev_add");
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

        r = qmp_client_invoke(qmp, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
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

        r = qmp_client_invoke(qmp, "chardev-add", QMP_CLIENT_ARGS(chardev_args), on_qmp_complete, (void*) "chardev-add");
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

        r = qmp_client_invoke(qmp, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
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

        r = qmp_client_invoke(qmp, "getfd", QMP_CLIENT_ARGS_FD(getfd_args, TAKE_FD(vsock->fd)),
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

        r = qmp_client_invoke(qmp, "device_add", QMP_CLIENT_ARGS(device_args), on_qmp_complete, (void*) "device_add");
        if (r < 0)
                return log_error_errno(r, "Failed to send VSOCK device_add: %m");

        log_debug("Queued vhost-vsock-pci device setup (cid=%u)", vsock->cid);
        return 0;
}

static bool drives_need_scsi_controller(DriveInfos *drives) {
        assert(drives);

        FOREACH_ARRAY(d, drives->drives, drives->n_drives) {
                DriveInfo *drive = *d;
                if (STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"))
                        return true;
        }

        return false;
}

int vmspawn_qmp_setup_drives(VmspawnQmpBridge *bridge, DriveInfos *drives) {
        int r;

        assert(bridge);
        assert(drives);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

        /* io_uring support was probed during vmspawn_qmp_init(). The cached result in
         * bridge->features is passed to each file node setup call. */

        if (drives_need_scsi_controller(drives)) {
                r = qmp_setup_scsi_controller(bridge, drives->scsi_pcie_port);
                if (r < 0)
                        return r;
        }

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

        hashmap_free(b->pending_jobs);

        FOREACH_ELEMENT(owner, b->hotplug_port_owner)
                free(*owner);

        qmp_client_unref(b->qmp);
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

        return qmp_client_invoke(c, "blockdev-del", QMP_CLIENT_ARGS(del_args),
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

        return qmp_client_invoke(c, "blockdev-add", QMP_CLIENT_ARGS(args),
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

        return qmp_client_invoke(c, "query-qmp-schema", QMP_CLIENT_ARGS(NULL),
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

        VmspawnQmpBridge *bridge = ASSERT_PTR(qmp_client_get_userdata(client));

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

        return qmp_client_invoke(bridge->qmp, "cont", /* args= */ NULL, on_cont_complete, /* userdata= */ NULL);
}
