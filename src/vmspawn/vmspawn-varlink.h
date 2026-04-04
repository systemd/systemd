/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/ethernet.h>

#include "sd-event.h"

#include "cleanup-util.h"
#include "macro.h"
#include "qmp-client.h"

typedef struct VmspawnVarlinkContext VmspawnVarlinkContext;

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

/* Network info for QMP-based network setup. Covers privileged TAP (by name),
 * nsresourced TAP (by FD via getfd), and user-mode networking. The no-network
 * case (-nic none) stays on the QEMU command line. */
typedef struct QmpNetworkInfo {
        const char *type;                  /* "tap" or "user" */
        const char *ifname;                /* TAP interface name (tap by name only) */
        const struct ether_addr *mac;      /* VM-side MAC address (tap only, NULL if unset) */
        int fd;                            /* TAP fd to pass via getfd (tap by fd only, -EBADF if unused) */
} QmpNetworkInfo;

static inline void qmp_network_info_done(QmpNetworkInfo *info) {
        assert(info);
        info->fd = safe_close(info->fd);
}

/* Virtiofs device info for QMP-based chardev + device setup */
typedef struct QmpVirtiofsInfo {
        char *id;              /* owned: chardev and device id (e.g. "rootdir", "mnt0") */
        char *socket_path;     /* owned: virtiofsd listen socket path */
        char *tag;             /* owned: virtiofs mount tag visible to guest */
} QmpVirtiofsInfo;

static inline void qmp_virtiofs_info_done(QmpVirtiofsInfo *info) {
        assert(info);
        info->id = mfree(info->id);
        info->socket_path = mfree(info->socket_path);
        info->tag = mfree(info->tag);
}

typedef struct QmpVirtiofsInfos {
        QmpVirtiofsInfo *entries;
        size_t n;
} QmpVirtiofsInfos;

static inline void qmp_virtiofs_infos_done(QmpVirtiofsInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(e, infos->entries, infos->n)
                qmp_virtiofs_info_done(e);
        infos->entries = mfree(infos->entries);
        infos->n = 0;
}

/* VSOCK device info for QMP-based setup via getfd + device_add */
typedef struct QmpVsockInfo {
        int fd;                 /* vhost-vsock fd to pass via getfd (-EBADF if unused) */
        unsigned cid;           /* guest CID */
} QmpVsockInfo;

static inline void qmp_vsock_info_done(QmpVsockInfo *info) {
        assert(info);
        info->fd = safe_close(info->fd);
}

/* Phase 1: QMP handshake. Returns a connected QmpClient ready for device
 * setup commands. */
int vmspawn_varlink_init(QmpClient **ret, int qmp_fd, sd_event *event);

/* Phase 2: Device setup — call any subset in any order before vmspawn_varlink_start(). */
int vmspawn_varlink_setup_drives(QmpClient *qmp, const QmpDriveInfos *drives);
int vmspawn_varlink_setup_network(QmpClient *qmp, QmpNetworkInfo *network);
int vmspawn_varlink_setup_virtiofs(QmpClient *qmp, const QmpVirtiofsInfos *virtiofs);
int vmspawn_varlink_setup_rng(QmpClient *qmp);
int vmspawn_varlink_setup_balloon(QmpClient *qmp);
int vmspawn_varlink_setup_vmgenid(QmpClient *qmp, sd_id128_t vmgenid);
int vmspawn_varlink_setup_vsock(QmpClient *qmp, QmpVsockInfo *vsock);

/* Phase 3: Resume vCPUs and switch QMP client to async event processing. */
int vmspawn_varlink_start(QmpClient *qmp);

/* Varlink server for VM control on top of an established QMP client */
int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, QmpClient *qmp,
                      const char *runtime_dir, char **ret_control_address);

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
