/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devicetree.h"
#include "efi.h"

/* Patches type 1 hypervisor VM nodes directly into the devicetree already
 * installed in *dt_state*, describing the Linux kernel image, initrd, DTB,
 * bootargs, and attributes that the type 1 hypervisor should use to launch
 * each VM. The first VM is marked as the primary/HLOS kernel VM. */
typedef struct FdtVmPayload {
        char id;
        uint64_t kernel_addr;
        uint64_t kernel_size;
        uint64_t initrd_addr;
        uint64_t initrd_size;
        uint64_t dtb_addr;
        uint64_t dtb_size;
        const char *bootargs;
        const void *attributes;
        size_t attributes_size;
} FdtVmPayload;

EFI_STATUS fdt_patch_type_1_hypervisor_vms(
                struct devicetree_state *dt_state,
                const FdtVmPayload payloads[],
                size_t n_payloads);
