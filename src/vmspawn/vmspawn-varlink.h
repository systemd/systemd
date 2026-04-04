/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/ethernet.h>

#include "sd-event.h"

#include "cleanup-util.h"
#include "macro.h"

typedef struct VmspawnVarlinkBridge VmspawnVarlinkBridge;
typedef struct VmspawnVarlinkContext VmspawnVarlinkContext;

VmspawnVarlinkBridge *vmspawn_varlink_bridge_free(VmspawnVarlinkBridge *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkBridge *, vmspawn_varlink_bridge_free);

/* QEMU feature flags detected via QMP schema introspection */
typedef struct QemuFeatures {
        bool io_uring;     /* aio=io_uring for block devices */
} QemuFeatures;

/* Drive info for QMP-based drive setup */
typedef struct DriveInfo {
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
} DriveInfo;

static inline void drive_info_done(DriveInfo *info) {
        assert(info);
        info->serial = mfree(info->serial);
        info->node_name = mfree(info->node_name);
}

typedef struct DriveInfos {
        DriveInfo *drives;
        size_t n;
} DriveInfos;

static inline void drive_infos_done(DriveInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(d, infos->drives, infos->n)
                drive_info_done(d);
        infos->drives = mfree(infos->drives);
        infos->n = 0;
}

/* Network info for QMP-based network setup. Covers privileged TAP (by name),
 * nsresourced TAP (by FD via getfd), and user-mode networking. The no-network
 * case (-nic none) stays on the QEMU command line. */
typedef struct NetworkInfo {
        const char *type;                  /* "tap" or "user" */
        const char *ifname;                /* TAP interface name (tap by name only) */
        const struct ether_addr *mac;      /* VM-side MAC address (tap only, NULL if unset) */
        int fd;                            /* TAP fd to pass via getfd (tap by fd only, -EBADF if unused) */
} NetworkInfo;

static inline void network_info_done(NetworkInfo *info) {
        assert(info);
        info->fd = safe_close(info->fd);
}

/* Virtiofs device info for QMP-based chardev + device setup */
typedef struct VirtiofsInfo {
        char *id;              /* owned: chardev and device id (e.g. "rootdir", "mnt0") */
        char *socket_path;     /* owned: virtiofsd listen socket path */
        char *tag;             /* owned: virtiofs mount tag visible to guest */
} VirtiofsInfo;

static inline void virtiofs_info_done(VirtiofsInfo *info) {
        assert(info);
        info->id = mfree(info->id);
        info->socket_path = mfree(info->socket_path);
        info->tag = mfree(info->tag);
}

typedef struct VirtiofsInfos {
        VirtiofsInfo *entries;
        size_t n;
} VirtiofsInfos;

static inline void virtiofs_infos_done(VirtiofsInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(e, infos->entries, infos->n)
                virtiofs_info_done(e);
        infos->entries = mfree(infos->entries);
        infos->n = 0;
}

/* VSOCK device info for QMP-based setup via getfd + device_add */
typedef struct VsockInfo {
        int fd;                 /* vhost-vsock fd to pass via getfd (-EBADF if unused) */
        unsigned cid;           /* guest CID */
} VsockInfo;

static inline void vsock_info_done(VsockInfo *info) {
        assert(info);
        info->fd = safe_close(info->fd);
}

/* Phase 1: Connect to VMM backend. Connect to VMM backend. Returns an opaque bridge ready for device setup. */
int vmspawn_varlink_init(VmspawnVarlinkBridge **ret, int qmp_fd, sd_event *event);

/* Phase 2: Device setup — call any subset in any order before vmspawn_varlink_start(). */
int vmspawn_varlink_setup_drives(VmspawnVarlinkBridge *bridge, const DriveInfos *drives);
int vmspawn_varlink_setup_network(VmspawnVarlinkBridge *bridge, NetworkInfo *network);
int vmspawn_varlink_setup_virtiofs(VmspawnVarlinkBridge *bridge, const VirtiofsInfos *virtiofs);
int vmspawn_varlink_setup_rng(VmspawnVarlinkBridge *bridge);
int vmspawn_varlink_setup_balloon(VmspawnVarlinkBridge *bridge);
int vmspawn_varlink_setup_vmgenid(VmspawnVarlinkBridge *bridge, sd_id128_t vmgenid);
int vmspawn_varlink_setup_vsock(VmspawnVarlinkBridge *bridge, VsockInfo *vsock);

/* Phase 3: Resume vCPUs and switch async event processing. */
int vmspawn_varlink_start(VmspawnVarlinkBridge *bridge);

/* Varlink server for VM control on top of an established bridge connection */
int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, VmspawnVarlinkBridge *bridge,
                      const char *runtime_dir, char **ret_control_address);

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
