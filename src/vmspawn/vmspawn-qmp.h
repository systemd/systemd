/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/ethernet.h>

#include "fd-util.h"
#include "macro.h"
#include "vmspawn-varlink.h"

/* QEMU feature flags detected via QMP schema introspection */
typedef struct QemuFeatures {
        int io_uring;          /* aio=io_uring: -1 unprobed, 0 unavailable, 1 available */
} QemuFeatures;

/* Drive info for QMP-based drive setup */
typedef struct DriveInfo {
        const char *path;          /* kept for logging only — not passed to QEMU */
        const char *format;        /* "raw" or "qcow2" */
        const char *disk_driver;   /* "virtio-blk-pci", "scsi-hd", "scsi-cd", "nvme" */
        char *serial;              /* owned */
        char *node_name;           /* owned */
        int fd;                    /* pre-opened image fd (owned, -EBADF if unused) */
        int overlay_fd;            /* pre-opened anonymous overlay fd for ephemeral (owned, -EBADF if unused) */
        bool is_block_device;
        bool read_only;
        bool discard;
        bool no_flush;
        bool boot;
} DriveInfo;

static inline void drive_info_done(DriveInfo *info) {
        assert(info);
        info->serial = mfree(info->serial);
        info->node_name = mfree(info->node_name);
        info->fd = safe_close(info->fd);
        info->overlay_fd = safe_close(info->overlay_fd);
}

typedef struct DriveInfos {
        DriveInfo *drives;
        size_t n_drives;
} DriveInfos;

static inline void drive_infos_done(DriveInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(d, infos->drives, infos->n_drives)
                drive_info_done(d);
        infos->drives = mfree(infos->drives);
        infos->n_drives = 0;
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
        size_t n_entries;
} VirtiofsInfos;

static inline void virtiofs_infos_done(VirtiofsInfos *infos) {
        assert(infos);
        FOREACH_ARRAY(e, infos->entries, infos->n_entries)
                virtiofs_info_done(e);
        infos->entries = mfree(infos->entries);
        infos->n_entries = 0;
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

/* Phase 2: Device setup — call any subset in any order before vmspawn_varlink_start(). */
int vmspawn_qmp_setup_drives(VmspawnQmpBridge *bridge, const DriveInfos *drives);
int vmspawn_qmp_setup_network(VmspawnQmpBridge *bridge, NetworkInfo *network);
int vmspawn_qmp_setup_virtiofs(VmspawnQmpBridge *bridge, const VirtiofsInfos *virtiofs);
int vmspawn_qmp_setup_rng(VmspawnQmpBridge *bridge);
int vmspawn_qmp_setup_balloon(VmspawnQmpBridge *bridge);
int vmspawn_qmp_setup_vmgenid(VmspawnQmpBridge *bridge, sd_id128_t vmgenid);
int vmspawn_qmp_setup_vsock(VmspawnQmpBridge *bridge, VsockInfo *vsock);
