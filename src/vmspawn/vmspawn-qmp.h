/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/ethernet.h>

#include "shared-forward.h"

/* Pending job continuation — called when a QMP background job reaches "concluded" state.
 * Used by blockdev-create to chain remaining drive setup after the job completes. */
typedef int (*pending_job_callback_t)(QmpClient *qmp, void *userdata);
typedef void (*pending_job_free_t)(void *userdata);

typedef struct PendingJob {
        pending_job_callback_t on_concluded;
        pending_job_free_t free_userdata;
        void *userdata;
} PendingJob;

PendingJob* pending_job_free(PendingJob *j);
DEFINE_TRIVIAL_CLEANUP_FUNC(PendingJob *, pending_job_free);

typedef enum VmspawnQmpFeatureFlags {
        VMSPAWN_QMP_FEATURE_IO_URING         = 1u << 0,
        VMSPAWN_QMP_FEATURE_DISCARD_NO_UNREF = 1u << 1,
} VmspawnQmpFeatureFlags;

typedef struct VmspawnQmpBridge {
        QmpClient *qmp;
        Hashmap *pending_jobs;  /* job_id (string, owned) -> PendingJob* */
        VmspawnQmpFeatureFlags features;
} VmspawnQmpBridge;

VmspawnQmpBridge* vmspawn_qmp_bridge_free(VmspawnQmpBridge *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnQmpBridge *, vmspawn_qmp_bridge_free);

QmpClient* vmspawn_qmp_bridge_get_qmp(VmspawnQmpBridge *b);

/* Phase 1: Connect to VMM backend. Returns an opaque bridge ready for device setup. */
int vmspawn_qmp_init(VmspawnQmpBridge **ret, int fd, sd_event *event);

/* Phase 1b: Feature probing. Fires one-shot QMP commands and drives the client
 * synchronously until every reply has been delivered. Populates bridge->features.
 * Must run before the device-setup phase; both io_uring and discard-no-unref flags
 * are consumed by vmspawn_qmp_setup_drives(). */
int vmspawn_qmp_probe_features(VmspawnQmpBridge *bridge);

/* Phase 3: Resume vCPUs. All commands are async — responses arrive during sd_event_loop(). */
int vmspawn_qmp_start(VmspawnQmpBridge *bridge);

int vmspawn_qmp_bridge_register_job(
                VmspawnQmpBridge *b,
                const char *job_id,
                pending_job_callback_t on_concluded,
                void *userdata,
                pending_job_free_t free_userdata);

typedef enum QmpDriveFlags {
        QMP_DRIVE_BLOCK_DEVICE     = 1u << 0,
        QMP_DRIVE_READ_ONLY        = 1u << 1,
        QMP_DRIVE_DISCARD          = 1u << 2,
        QMP_DRIVE_NO_FLUSH         = 1u << 3,
        QMP_DRIVE_BOOT             = 1u << 4,
        QMP_DRIVE_IO_URING         = 1u << 5,
        QMP_DRIVE_DISCARD_NO_UNREF = 1u << 6,  /* qcow2 only */
} QmpDriveFlags;

/* Drive info for QMP-based drive setup */
typedef struct DriveInfo {
        const char *path;          /* kept for logging only — not passed to QEMU */
        const char *format;        /* "raw" or "qcow2" */
        const char *disk_driver;   /* "virtio-blk-pci", "scsi-hd", "scsi-cd", "nvme" */
        char *serial;              /* owned */
        char *node_name;           /* owned */
        char *pcie_port;           /* owned: pcie-root-port id for device_add bus (NULL on non-PCIe) */
        int fd;                    /* pre-opened image fd (owned, -EBADF if unused) */
        int overlay_fd;            /* pre-opened anonymous overlay fd for ephemeral (owned, -EBADF if unused) */
        QmpDriveFlags flags;
} DriveInfo;

void drive_info_done(DriveInfo *info);

typedef struct DriveInfos {
        DriveInfo *drives;
        size_t n_drives;
        char *scsi_pcie_port;  /* owned: pcie-root-port id for SCSI controller (NULL if no SCSI or non-PCIe) */
} DriveInfos;

void drive_infos_done(DriveInfos *infos);

/* Network info for QMP-based network setup. Covers privileged TAP (by name),
 * nsresourced TAP (by FD via getfd), and user-mode networking. The no-network
 * case (-nic none) stays on the QEMU command line. */
typedef struct NetworkInfo {
        const char *type;                  /* "tap" or "user" — points to a string literal */
        char *ifname;                      /* owned: TAP interface name (tap by name only, NULL if unset) */
        struct ether_addr mac;             /* VM-side MAC address (tap only, valid iff mac_set) */
        bool mac_set;
        char *pcie_port;                   /* owned: pcie-root-port id for device_add bus (NULL on non-PCIe) */
        int fd;                            /* TAP fd to pass via getfd (tap by fd only, -EBADF if unused) */
} NetworkInfo;

void network_info_done(NetworkInfo *info);

/* Virtiofs device info for QMP-based chardev + device setup */
typedef struct VirtiofsInfo {
        char *id;              /* owned: chardev and device id (e.g. "rootdir", "mnt0") */
        char *socket_path;     /* owned: virtiofsd listen socket path */
        char *tag;             /* owned: virtiofs mount tag visible to guest */
        char *pcie_port;       /* owned: pcie-root-port id for device_add bus (NULL on non-PCIe) */
} VirtiofsInfo;

void virtiofs_info_done(VirtiofsInfo *info);

typedef struct VirtiofsInfos {
        VirtiofsInfo *entries;
        size_t n_entries;
} VirtiofsInfos;

void virtiofs_infos_done(VirtiofsInfos *infos);

/* VSOCK device info for QMP-based setup via getfd + device_add */
typedef struct VsockInfo {
        int fd;                 /* vhost-vsock fd to pass via getfd (-EBADF if unused) */
        unsigned cid;           /* guest CID */
        char *pcie_port;        /* owned: pcie-root-port id for device_add bus (NULL on non-PCIe) */
} VsockInfo;

void vsock_info_done(VsockInfo *info);

/* Aggregate of the per-device info structures populated before the bridge-based
 * device setup phase. Keeps lifetime and cleanup of all device state in one place. */
typedef struct MachineConfig {
        DriveInfos drives;
        NetworkInfo network;
        VirtiofsInfos virtiofs;
        VsockInfo vsock;
} MachineConfig;

void machine_config_done(MachineConfig *c);

/* Phase 2: Device setup — call any subset in any order before vmspawn_qmp_start(). */
int vmspawn_qmp_setup_drives(VmspawnQmpBridge *bridge, DriveInfos *drives);
int vmspawn_qmp_setup_network(VmspawnQmpBridge *bridge, NetworkInfo *network);
int vmspawn_qmp_setup_virtiofs(VmspawnQmpBridge *bridge, const VirtiofsInfos *virtiofs);
int vmspawn_qmp_setup_vsock(VmspawnQmpBridge *bridge, VsockInfo *vsock);
