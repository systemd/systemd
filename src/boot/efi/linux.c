/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 */

#include <efi.h>
#include <efilib.h>

#include "util.h"
#include "linux.h"

#define SETUP_MAGIC             0x53726448      /* "HdrS" */
struct SetupHeader {
        UINT8 boot_sector[0x01f1];
        UINT8 setup_secs;
        UINT16 root_flags;
        UINT32 sys_size;
        UINT16 ram_size;
        UINT16 video_mode;
        UINT16 root_dev;
        UINT16 signature;
        UINT16 jump;
        UINT32 header;
        UINT16 version;
        UINT16 su_switch;
        UINT16 setup_seg;
        UINT16 start_sys;
        UINT16 kernel_ver;
        UINT8 loader_id;
        UINT8 load_flags;
        UINT16 movesize;
        UINT32 code32_start;
        UINT32 ramdisk_start;
        UINT32 ramdisk_len;
        UINT32 bootsect_kludge;
        UINT16 heap_end;
        UINT8 ext_loader_ver;
        UINT8 ext_loader_type;
        UINT32 cmd_line_ptr;
        UINT32 ramdisk_max;
        UINT32 kernel_alignment;
        UINT8 relocatable_kernel;
        UINT8 min_alignment;
        UINT16 xloadflags;
        UINT32 cmdline_size;
        UINT32 hardware_subarch;
        UINT64 hardware_subarch_data;
        UINT32 payload_offset;
        UINT32 payload_length;
        UINT64 setup_data;
        UINT64 pref_address;
        UINT32 init_size;
        UINT32 handover_offset;
} __attribute__((packed));

#ifdef __x86_64__
typedef VOID(*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct SetupHeader *setup);
static inline VOID linux_efi_handover(EFI_HANDLE image, struct SetupHeader *setup) {
        handover_f handover;

        asm volatile ("cli");
        handover = (handover_f)((UINTN)setup->code32_start + 512 + setup->handover_offset);
        handover(image, ST, setup);
}
#else
typedef VOID(*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct SetupHeader *setup) __attribute__((regparm(0)));
static inline VOID linux_efi_handover(EFI_HANDLE image, struct SetupHeader *setup) {
        handover_f handover;

        handover = (handover_f)((UINTN)setup->code32_start + setup->handover_offset);
        handover(image, ST, setup);
}
#endif

EFI_STATUS linux_exec(EFI_HANDLE *image,
                      CHAR8 *cmdline, UINTN cmdline_len,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size) {
        struct SetupHeader *image_setup;
        struct SetupHeader *boot_setup;
        EFI_PHYSICAL_ADDRESS addr;
        EFI_STATUS err;

        image_setup = (struct SetupHeader *)(linux_addr);
        if (image_setup->signature != 0xAA55 || image_setup->header != SETUP_MAGIC)
                return EFI_LOAD_ERROR;

        if (image_setup->version < 0x20b || !image_setup->relocatable_kernel)
                return EFI_LOAD_ERROR;

        addr = 0x3fffffff;
        err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
                                EFI_SIZE_TO_PAGES(0x4000), &addr);
        if (EFI_ERROR(err))
                return err;
        boot_setup = (struct SetupHeader *)(UINTN)addr;
        ZeroMem(boot_setup, 0x4000);
        CopyMem(boot_setup, image_setup, sizeof(struct SetupHeader));
        boot_setup->loader_id = 0xff;

        boot_setup->code32_start = (UINT32)linux_addr + (image_setup->setup_secs+1) * 512;

        if (cmdline) {
                addr = 0xA0000;
                err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
                                        EFI_SIZE_TO_PAGES(cmdline_len + 1), &addr);
                if (EFI_ERROR(err))
                        return err;
                CopyMem((VOID *)(UINTN)addr, cmdline, cmdline_len);
                ((CHAR8 *)addr)[cmdline_len] = 0;
                boot_setup->cmd_line_ptr = (UINT32)addr;
        }

        boot_setup->ramdisk_start = (UINT32)initrd_addr;
        boot_setup->ramdisk_len = (UINT32)initrd_size;

        linux_efi_handover(image, boot_setup);
        return EFI_LOAD_ERROR;
}
