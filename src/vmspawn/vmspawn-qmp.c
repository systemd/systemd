/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "vmspawn-qmp.h"

/* Detect QEMU features via schema introspection. query-qmp-schema returns all QAPI types;
 * conditionally compiled enum values (like io_uring in BlockdevAioOptions) are only present
 * if QEMU was built with support for them. */
static int qmp_detect_features(QmpClient *qmp, QemuFeatures *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;
        int r;

        assert(qmp);
        assert(ret);

        *ret = (QemuFeatures) { .io_uring = -1 };

        r = qmp_client_call(qmp, "query-qmp-schema", /* arguments= */ NULL, &schema, /* reterr_error= */ NULL);
        if (r < 0)
                return r;

        ret->io_uring = 0; /* Schema probed successfully, assume unavailable until found */

        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, schema) {
                struct {
                        const char *name;
                        const char *meta_type;
                        sd_json_variant *members;
                } p = {};

                (void) sd_json_dispatch(entry,
                                (const sd_json_dispatch_field[]) {
                                        { "name",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(typeof(p), name)      },
                                        { "meta-type", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(typeof(p), meta_type) },
                                        { "members",   SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_variant,      offsetof(typeof(p), members)   },
                                        {},
                                },
                                /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                &p);

                if (!streq_ptr(p.name, "BlockdevAioOptions"))
                        continue;
                if (!streq_ptr(p.meta_type, "enum"))
                        break;

                sd_json_variant *member;
                JSON_VARIANT_ARRAY_FOREACH(member, p.members) {
                        const char *mname = NULL;
                        (void) sd_json_dispatch(member,
                                        (const sd_json_dispatch_field[]) {
                                                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0 },
                                                {},
                                        },
                                        /* flags= */ SD_JSON_ALLOW_EXTENSIONS,
                                        &mname);
                        if (streq_ptr(mname, "io_uring")) {
                                ret->io_uring = 1;
                                break;
                        }
                }
                break;
        }

        log_debug("QEMU feature detection: io_uring=%s", ret->io_uring > 0 ? "yes" : ret->io_uring < 0 ? "unprobed" : "no");
        return 0;
}

/* Build blockdev-add JSON for the protocol-level (file) node */
static int qmp_build_blockdev_add_file(
                const char *node_name,
                const char *filename,
                const char *driver,
                bool io_uring,
                bool read_only,
                bool no_flush,
                sd_json_variant **ret) {

        assert(node_name);
        assert(filename);
        assert(driver);
        assert(ret);

        /* cache.direct=false uses the page cache (QEMU default). cache.no-flush suppresses host
         * flush on guest fsync — only safe for ephemeral/extra drives where data loss is acceptable. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", driver),
                        SD_JSON_BUILD_PAIR_STRING("filename", filename),
                        SD_JSON_BUILD_PAIR_CONDITION(read_only, "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(io_uring, "aio", SD_JSON_BUILD_STRING("io_uring")),
                        SD_JSON_BUILD_PAIR("cache", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_BOOLEAN("direct", false),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("no-flush", no_flush))));
}

/* Build blockdev-add JSON for the format-level node */
static int qmp_build_blockdev_add_format(
                const char *node_name,
                const char *format,
                const char *file_node_name,
                bool read_only,
                bool discard,
                const char *backing,
                sd_json_variant **ret) {

        assert(node_name);
        assert(format);
        assert(file_node_name);
        assert(ret);

        /* When "file" is a string (not an object), QEMU interprets it as a reference to an
         * existing node-name. The "backing" field likewise references a format-level node. */
        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("node-name", node_name),
                        SD_JSON_BUILD_PAIR_STRING("driver", format),
                        SD_JSON_BUILD_PAIR_STRING("file", file_node_name),
                        SD_JSON_BUILD_PAIR_CONDITION(read_only, "read-only", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(discard, "discard", SD_JSON_BUILD_STRING("unmap")),
                        SD_JSON_BUILD_PAIR_CONDITION(!!backing, "backing", SD_JSON_BUILD_STRING(backing)));
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

/* Issue blockdev-add for a drive's file node, with io_uring fallback. */
static int qmp_add_file_node(QmpClient *qmp, const DriveInfo *drive,
                             const char *node_name, const QmpFdset *fdset,
                             bool read_only, QemuFeatures *features) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        const char *driver = drive->is_block_device ? "host_device" : "file";
        int r;

        r = qmp_build_blockdev_add_file(node_name, fdset->path, driver, features->io_uring > 0,
                                        read_only, drive->no_flush, &args);
        if (r < 0)
                return r;

        r = qmp_client_call(qmp, "blockdev-add", args, /* ret_result= */ NULL, &error_class);
        if (r == -EIO && features->io_uring > 0) {
                log_debug("blockdev-add with aio=io_uring failed for '%s' (%s), retrying without",
                          fdset->path, strna(error_class));

                args = sd_json_variant_unref(args);
                error_class = mfree(error_class);

                r = qmp_build_blockdev_add_file(node_name, fdset->path, driver, /* io_uring= */ false,
                                                read_only, drive->no_flush, &args);
                if (r < 0)
                        return r;

                r = qmp_client_call(qmp, "blockdev-add", args, /* ret_result= */ NULL, &error_class);
                features->io_uring = 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to add file node '%s': %s", fdset->path, strna(error_class));

        return 0;
}

/* Get the virtual size of an image from the fd directly. For raw images the virtual size
 * equals the file/device size. For qcow2 the virtual size is a big-endian uint64 at header
 * offset 24 (the "size" field in the qcow2 header). */
static int get_image_virtual_size(int fd, const char *format, bool is_block_device, uint64_t *ret) {
        assert(fd >= 0);
        assert(format);
        assert(ret);

        if (streq(format, "raw")) {
                if (is_block_device)
                        return blockdev_get_device_size(fd, ret);

                struct stat st;
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat image: %m");

                *ret = st.st_size;
                return 0;
        }

        if (streq(format, "qcow2")) {
                uint32_t magic;
                ssize_t n = pread(fd, &magic, sizeof(magic), 0);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read qcow2 magic: %m");
                if (n != sizeof(magic) || be32toh(magic) != UINT32_C(0x514649fb))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Not a valid qcow2 image (bad magic)");

                uint64_t size_be;
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

/* Run blockdev-create synchronously: issue the command and wait for the job to conclude
 * via JOB_STATUS_CHANGE events. */
static int qmp_blockdev_create_and_wait(QmpClient *qmp, sd_json_variant *options, const char *job_id) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(options);
        assert(job_id);

        r = sd_json_buildo(&cmd_args,
                        SD_JSON_BUILD_PAIR_STRING("job-id", job_id),
                        SD_JSON_BUILD_PAIR_VARIANT("options", options));
        if (r < 0)
                return log_error_errno(r, "Failed to build blockdev-create JSON: %m");

        r = qmp_client_call(qmp, "blockdev-create", cmd_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to start blockdev-create job '%s': %s", job_id, strna(error_class));

        error_class = mfree(error_class);
        r = qmp_client_job_wait(qmp, job_id, &error_class);
        if (r < 0)
                return log_error_errno(r, "blockdev-create job '%s' failed: %s", job_id, strna(error_class));

        return 0;
}

/* Configure a single drive. Uses add-fd to pass pre-opened fds, split
 * file/format blockdev-add nodes, and blockdev-create for ephemeral overlays. */
static int qmp_setup_one_drive(QmpClient *qmp, const DriveInfo *drive, QemuFeatures *features) {
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(qmp);
        assert(drive);
        assert(drive->fd >= 0);

        bool ephemeral = drive->overlay_fd >= 0;

        if (ephemeral) {
                /* Ephemeral mode: base image (read-only) + anonymous qcow2 overlay (read-write).
                 * Node names: <name>-base-file, <name>-base-fmt, <name>-overlay-file, <name> */
                const char *base_file_node = strjoina(drive->node_name, "-base-file");
                const char *base_fmt_node = strjoina(drive->node_name, "-base-fmt");
                const char *overlay_file_node = strjoina(drive->node_name, "-overlay-file");

                /* Step 1-2: Pass both fds to QEMU */
                _cleanup_(qmp_fdset_done) QmpFdset base_fdset = {};
                r = qmp_client_fdset_new(qmp, drive->fd, &base_fdset);
                if (r < 0)
                        return r;

                _cleanup_(qmp_fdset_done) QmpFdset overlay_fdset = {};
                r = qmp_client_fdset_new(qmp, drive->overlay_fd, &overlay_fdset);
                if (r < 0)
                        return r;

                /* Step 3: Base image file node (read-only) */
                r = qmp_add_file_node(qmp, drive, base_file_node, &base_fdset,
                                      /* read_only= */ true, features);
                if (r < 0)
                        return r;

                /* Step 4: Base image format node (read-only) */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *base_fmt_args = NULL;
                r = qmp_build_blockdev_add_format(base_fmt_node, drive->format, base_file_node,
                                                  /* read_only= */ true, /* discard= */ false, /* backing= */ NULL, &base_fmt_args);
                if (r < 0)
                        return r;

                r = qmp_client_call(qmp, "blockdev-add", base_fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add base format node for '%s': %s",
                                               drive->path, strna(error_class));

                /* Step 5: Overlay file node (read-write) */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *overlay_file_args = NULL;
                r = qmp_build_blockdev_add_file(overlay_file_node, overlay_fdset.path, "file",
                                                /* io_uring= */ false, /* read_only= */ false,
                                                /* no_flush= */ true, &overlay_file_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", overlay_file_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add overlay file node for '%s': %s",
                                               drive->path, strna(error_class));

                /* Step 6: Get base image virtual size directly from the fd */
                uint64_t virtual_size;
                r = get_image_virtual_size(drive->fd, drive->format, drive->is_block_device, &virtual_size);
                if (r < 0)
                        return r;

                /* Step 7: Format overlay as qcow2 via blockdev-create */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *create_options = NULL;
                r = sd_json_buildo(&create_options,
                                SD_JSON_BUILD_PAIR_STRING("driver", "qcow2"),
                                SD_JSON_BUILD_PAIR_STRING("file", overlay_file_node),
                                SD_JSON_BUILD_PAIR_UNSIGNED("size", virtual_size),
                                SD_JSON_BUILD_PAIR_STRING("backing-file", base_fmt_node),
                                SD_JSON_BUILD_PAIR_STRING("backing-fmt", drive->format));
                if (r < 0)
                        return log_error_errno(r, "Failed to build blockdev-create options: %m");

                const char *job_id = strjoina("create-", drive->node_name);

                r = qmp_blockdev_create_and_wait(qmp, create_options, job_id);
                if (r < 0)
                        return r;

                /* Step 8: Open formatted overlay as qcow2 with backing reference */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *overlay_fmt_args = NULL;
                r = qmp_build_blockdev_add_format(drive->node_name, "qcow2", overlay_file_node,
                                                  /* read_only= */ false, drive->discard, base_fmt_node, &overlay_fmt_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", overlay_fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add overlay format node for '%s': %s",
                                               drive->path, strna(error_class));
        } else {
                /* Non-ephemeral: single file node + format node.
                 * Node names: <name>-file, <name> */
                const char *file_node_name = strjoina(drive->node_name, "-file");

                _cleanup_(qmp_fdset_done) QmpFdset fdset = {};
                r = qmp_client_fdset_new(qmp, drive->fd, &fdset);
                if (r < 0)
                        return r;

                r = qmp_add_file_node(qmp, drive, file_node_name, &fdset,
                                      drive->read_only, features);
                if (r < 0)
                        return r;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fmt_args = NULL;
                r = qmp_build_blockdev_add_format(drive->node_name, drive->format, file_node_name,
                                                  drive->read_only, drive->discard, /* backing= */ NULL, &fmt_args);
                if (r < 0)
                        return r;

                error_class = mfree(error_class);
                r = qmp_client_call(qmp, "blockdev-add", fmt_args, /* ret_result= */ NULL, &error_class);
                if (r < 0)
                        return log_error_errno(r, "Failed to add format node for '%s': %s",
                                               drive->path, strna(error_class));
        }

        /* device_add: attach to virtual hardware */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *device_args = NULL;
        r = qmp_build_device_add(drive, &device_args);
        if (r < 0)
                return r;

        error_class = mfree(error_class);
        r = qmp_client_call(qmp, "device_add", device_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add device for '%s': %s", drive->path, strna(error_class));

        log_debug("Added drive '%s' (aio=%s%s)", drive->path,
                   features->io_uring > 0 ? "io_uring" : "default",
                   ephemeral ? ", ephemeral" : "");

        return 0;
}

int vmspawn_qmp_setup_network(VmspawnQmpBridge *bridge, NetworkInfo *network) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *netdev_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
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
                return log_error_errno(r, "Failed to add network backend: %s", strna(error_class));

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
                return log_error_errno(r, "Failed to add NIC device: %s", strna(error_class));

        log_debug("Added %s network%s", network->type, tap_by_fd ? " (fd via getfd)" : "");
        return 0;
}

static int vmspawn_qmp_setup_one_virtiofs(QmpClient *qmp, const VirtiofsInfo *vfs) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *chardev_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
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

        r = qmp_client_call(qmp, "chardev-add", chardev_args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add chardev '%s': %s", vfs->id, strna(error_class));

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
                return log_error_errno(r, "Failed to add virtiofs device '%s': %s", vfs->id, strna(error_class));

        log_debug("Added virtiofs device '%s' (tag=%s)", vfs->id, vfs->tag);
        return 0;
}

int vmspawn_qmp_setup_virtiofs(VmspawnQmpBridge *bridge, const VirtiofsInfos *virtiofs) {
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
        assert(virtiofs);

        for (size_t i = 0; i < virtiofs->n_entries; i++) {
                r = vmspawn_qmp_setup_one_virtiofs(qmp, &virtiofs->entries[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

int vmspawn_qmp_setup_rng(VmspawnQmpBridge *bridge) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *object_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

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
                return log_error_errno(r, "Failed to add RNG backend: %s", strna(error_class));

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
                return log_error_errno(r, "Failed to add RNG device: %s", strna(error_class));

        log_debug("Added virtio-rng-pci device");
        return 0;
}

int vmspawn_qmp_setup_vmgenid(VmspawnQmpBridge *bridge, sd_id128_t vmgenid) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "vmgenid"),
                        SD_JSON_BUILD_PAIR_STRING("id", "vmgenid0"),
                        SD_JSON_BUILD_PAIR_STRING("guid", SD_ID128_TO_UUID_STRING(vmgenid)));
        if (r < 0)
                return log_error_errno(r, "Failed to build vmgenid device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add vmgenid device: %s", strna(error_class));

        log_debug("Added vmgenid device");
        return 0;
}

int vmspawn_qmp_setup_balloon(VmspawnQmpBridge *bridge) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("driver", "virtio-balloon-pci"),
                        SD_JSON_BUILD_PAIR_STRING("id", "balloon0"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("free-page-reporting", true));
        if (r < 0)
                return log_error_errno(r, "Failed to build balloon device_add JSON: %m");

        r = qmp_client_call(qmp, "device_add", args, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to add balloon device: %s", strna(error_class));

        log_debug("Added virtio-balloon device");
        return 0;
}

int vmspawn_qmp_setup_vsock(VmspawnQmpBridge *bridge, VsockInfo *vsock) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *getfd_args = NULL, *device_args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
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
                return log_error_errno(r, "Failed to add VSOCK device: %s", strna(error_class));

        log_debug("Added vhost-vsock-pci device (cid=%u)", vsock->cid);
        return 0;
}

static bool drives_need_scsi_controller(const DriveInfos *drives) {
        FOREACH_ARRAY(d, drives->drives, drives->n_drives)
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
                return log_error_errno(r, "Failed to add SCSI controller: %s", strna(error_class));

        log_debug("Added virtio-scsi-pci controller");
        return 0;
}

int vmspawn_qmp_setup_drives(VmspawnQmpBridge *bridge, const DriveInfos *drives) {
        int r;

        assert(bridge);

        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
        assert(drives);

        QemuFeatures features = { .io_uring = -1 };
        r = qmp_detect_features(qmp, &features);
        if (r < 0)
                log_warning_errno(r, "Failed to detect QEMU features, continuing with defaults: %m");

        if (drives_need_scsi_controller(drives)) {
                r = qmp_setup_scsi_controller(qmp);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < drives->n_drives; i++) {
                r = qmp_setup_one_drive(qmp, &drives->drives[i], &features);
                if (r < 0)
                        return r;
        }

        return 0;
}
