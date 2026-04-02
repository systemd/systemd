/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "cleanup-util.h"
#include "macro.h"
#include "qmp-client.h"
#include "runtime-scope.h"

typedef struct VmspawnQmpContext VmspawnQmpContext;

/* QEMU feature flags detected via QMP schema introspection */
typedef struct QemuFeatures {
        bool io_uring;     /* aio=io_uring for block devices */
} QemuFeatures;

/* Drive info for QMP-based drive setup */
typedef struct QmpDriveInfo {
        const char *path;
        const char *format;        /* "raw" or "qcow2" */
        const char *disk_driver;   /* "virtio-blk-pci", "scsi-hd", "scsi-cd", "nvme" */
        char *serial;              /* owned */
        char *node_name;           /* owned */
        const char *snapshot_file; /* if non-NULL, overlay with this temp file (ephemeral mode) */
        bool is_block_device;
        bool read_only;
        bool discard;
        bool boot;
} QmpDriveInfo;

static inline void qmp_drive_info_done(QmpDriveInfo *info) {
        assert(info);
        info->serial = mfree(info->serial);
        info->node_name = mfree(info->node_name);
}

typedef struct QmpDriveInfos {
        QmpDriveInfo *drives;
        size_t n;
} QmpDriveInfos;

static inline void qmp_drive_infos_done(QmpDriveInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(d, infos->drives, infos->n)
                qmp_drive_info_done(d);
        infos->drives = mfree(infos->drives);
        infos->n = 0;
}

/* QMP handshake, feature detection, drive setup, and VM start */
int vmspawn_qmp_init(QmpClient **ret, int qmp_fd, sd_event *event,
                      const QmpDriveInfo *drives, size_t n_drives);

/* Varlink server for VM control on top of an established QMP client */
int vmspawn_qmp_setup(VmspawnQmpContext **ret, QmpClient *qmp,
                      const char *runtime_dir, RuntimeScope runtime_scope,
                      uid_t owner_uid, char **ret_control_address);

VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnQmpContext *, vmspawn_qmp_context_free);
