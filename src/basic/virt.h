/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "errno-list.h"
#include "macro.h"

typedef enum Virtualization {
        VIRTUALIZATION_NONE = 0,

        VIRTUALIZATION_VM_FIRST,
        VIRTUALIZATION_KVM = VIRTUALIZATION_VM_FIRST,
        VIRTUALIZATION_AMAZON,
        VIRTUALIZATION_QEMU,
        VIRTUALIZATION_BOCHS,
        VIRTUALIZATION_XEN,
        VIRTUALIZATION_UML,
        VIRTUALIZATION_VMWARE,
        VIRTUALIZATION_ORACLE,
        VIRTUALIZATION_MICROSOFT,
        VIRTUALIZATION_ZVM,
        VIRTUALIZATION_PARALLELS,
        VIRTUALIZATION_BHYVE,
        VIRTUALIZATION_QNX,
        VIRTUALIZATION_ACRN,
        VIRTUALIZATION_POWERVM,
        VIRTUALIZATION_APPLE,
        VIRTUALIZATION_SRE,
        VIRTUALIZATION_VM_OTHER,
        VIRTUALIZATION_VM_LAST = VIRTUALIZATION_VM_OTHER,

        VIRTUALIZATION_CONTAINER_FIRST,
        VIRTUALIZATION_SYSTEMD_NSPAWN = VIRTUALIZATION_CONTAINER_FIRST,
        VIRTUALIZATION_LXC_LIBVIRT,
        VIRTUALIZATION_LXC,
        VIRTUALIZATION_OPENVZ,
        VIRTUALIZATION_DOCKER,
        VIRTUALIZATION_PODMAN,
        VIRTUALIZATION_RKT,
        VIRTUALIZATION_WSL,
        VIRTUALIZATION_PROOT,
        VIRTUALIZATION_POUCH,
        VIRTUALIZATION_CONTAINER_OTHER,
        VIRTUALIZATION_CONTAINER_LAST = VIRTUALIZATION_CONTAINER_OTHER,

        _VIRTUALIZATION_MAX,
        _VIRTUALIZATION_INVALID = -EINVAL,
        _VIRTUALIZATION_ERRNO_MAX = -ERRNO_MAX, /* ensure full range of errno fits into this enum */
} Virtualization;

static inline bool VIRTUALIZATION_IS_VM(Virtualization x) {
        return x >= VIRTUALIZATION_VM_FIRST && x <= VIRTUALIZATION_VM_LAST;
}

static inline bool VIRTUALIZATION_IS_CONTAINER(Virtualization x) {
        return x >= VIRTUALIZATION_CONTAINER_FIRST && x <= VIRTUALIZATION_CONTAINER_LAST;
}

Virtualization detect_vm(void);
Virtualization detect_container(void);
Virtualization detect_virtualization(void);

int running_in_userns(void);
int running_in_chroot(void);

const char *virtualization_to_string(Virtualization v) _const_;
Virtualization virtualization_from_string(const char *s) _pure_;
bool has_cpu_with_flag(const char *flag);
