/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/ethernet.h>

#include "sd-event.h"
#include "sd-id128.h"

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

/* Network info for QMP-based network setup. Only used for cases where QEMU can
 * be configured via QMP (privileged TAP and user-mode). The nsresourced TAP case
 * (FD inheritance) and no-network case stay on the QEMU command line. */
typedef struct NetworkInfo {
        const char *type;                  /* "tap" or "user" */
        const char *ifname;                /* TAP interface name (tap only) */
        const struct ether_addr *mac;      /* VM-side MAC address (tap only, NULL if unset) */
} NetworkInfo;

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

/* QMP handshake, feature detection, device setup, and VM start.
 * vmgenid is optional: pass SD_ID128_NULL to skip vmgenid device creation. */
int vmspawn_varlink_init(VmspawnVarlinkBridge **ret, int qmp_fd, sd_event *event,
                      const DriveInfo *drives, size_t n_drives,
                      const NetworkInfo *network,
                      const VirtiofsInfo *virtiofs, size_t n_virtiofs,
                      sd_id128_t vmgenid);

/* Varlink server for VM control on top of an established bridge connection */
int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, VmspawnVarlinkBridge *bridge,
                      const char *runtime_dir, char **ret_control_address);

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
