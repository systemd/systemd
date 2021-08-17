/* SPDX-License-Identifier: LGPL-2.1+ */

#include <efi.h>
#include <efilib.h>
#include <libfdt.h>

#include "linux.h"
#include "linux-aarch64.h"

/* DTB table GUID, as defined by UEFI specification 2.9 */
/* gnu-efi after 3.0.13 should already define this */
#ifndef EFI_DTB_TABLE_GUID
#define EFI_DTB_TABLE_GUID \
    { 0xb1b621d5, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0} }
static EFI_GUID EfiDtbTableGuid = EFI_DTB_TABLE_GUID;
#endif

/* Create new fdt, either empty or with the content of old_fdt if not null */
static void *create_new_fdt(void *old_fdt, int fdt_sz) {
        EFI_STATUS err;
        void *fdt = (void *) 0xFFFFFFFFUL;
        int ret;

        err = uefi_call_wrapper(BS->AllocatePages, 4,
                                AllocateMaxAddress,
                                EfiACPIReclaimMemory,
                                EFI_SIZE_TO_PAGES(fdt_sz),
                                (EFI_PHYSICAL_ADDRESS*)&fdt);
        if (EFI_ERROR(err)) {
                Print(L"Cannot allocate when creating fdt\n");
                return 0;
        }

        if (old_fdt) {
                ret = fdt_open_into(old_fdt, fdt, fdt_sz);
                if (ret != 0) {
                        Print(L"Error %d when copying fdt\n", ret);
                        return 0;
                }
        } else {
                ret = fdt_create_empty_tree(fdt, fdt_sz);
                if (ret != 0) {
                        Print(L"Error %d when creating empty fdt\n", ret);
                        return 0;
                }
        }

        /* Set in EFI configuration table */
        err = uefi_call_wrapper(BS->InstallConfigurationTable, 2,
                                &EfiDtbTableGuid, fdt);
        if (EFI_ERROR(err)) {
                Print(L"Cannot set fdt in EFI configuration\n");
                return 0;
        }

        return fdt;
}

static void *open_fdt(void) {
        EFI_STATUS status;
        void *fdt;

        /* Look for a device tree configuration table entry. */
        status = LibGetSystemConfigurationTable(&EfiDtbTableGuid,
                                                (VOID**)&fdt);
        if (EFI_ERROR(status)) {
                Print(L"DTB table not found, create new one\n");
                fdt = create_new_fdt(NULL, 2048);
                if (!fdt)
                        return 0;
        }

        if (fdt_check_header(fdt) != 0) {
                Print(L"Invalid header detected on UEFI supplied FDT\n");
                return 0;
        }

        return fdt;
}

static int update_chosen(void *fdt, UINTN initrd_addr, UINTN initrd_size) {
        uint64_t initrd_start, initrd_end;
        int ret, node;

        node = fdt_subnode_offset(fdt, 0, "chosen");
        if (node < 0) {
                node = fdt_add_subnode(fdt, 0, "chosen");
                if (node < 0) {
                        /* 'node' is an error code when negative: */
                        ret = node;
                        Print(L"Error creating chosen\n");
                        return ret;
                }
        }

        initrd_start = cpu_to_fdt64(initrd_addr);
        initrd_end = cpu_to_fdt64(initrd_addr + initrd_size);

        ret = fdt_setprop(fdt, node, "linux,initrd-start",
                          &initrd_start, sizeof initrd_start);
        if (ret) {
                Print(L"Cannot create initrd-start property\n");
                return ret;
        }

        ret = fdt_setprop(fdt, node, "linux,initrd-end",
                          &initrd_end, sizeof initrd_end);
        if (ret) {
                Print(L"Cannot create initrd-end property\n");
                return ret;
        }

        return 0;
}

#define FDT_EXTRA_SIZE 0x400

/* Update fdt /chosen node with initrd address and size */
static void update_fdt(UINTN initrd_addr, UINTN initrd_size) {
        void *fdt;

        fdt = open_fdt();
        if (fdt == 0)
                return;

        if (update_chosen(fdt, initrd_addr, initrd_size) == -FDT_ERR_NOSPACE) {
                /* Copy to new tree and re-try */
                Print(L"Not enough space, creating a new fdt\n");
                fdt = create_new_fdt(fdt, fdt_totalsize(fdt) + FDT_EXTRA_SIZE);
                if (!fdt)
                        return;
                update_chosen(fdt, initrd_addr, initrd_size);
        }
}

/* linux_addr is the .linux section address */
/* We don't use cmdline in aarch64 (kernel EFI stub takes it itself from the
 * EFI LoadOptions) */
#pragma GCC diagnostic ignored "-Wunused-parameter"
EFI_STATUS linux_exec(EFI_HANDLE image,
                      CHAR8 *cmdline, UINTN cmdline_len,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size) {
        struct arm64_kernel_header *hdr;
        struct arm64_linux_pe_header *pe;
        handover_f handover;

        if (initrd_size != 0)
                update_fdt(initrd_addr, initrd_size);

        hdr = (struct arm64_kernel_header *)linux_addr;

        pe = (void *)((UINTN)linux_addr + hdr->hdr_offset);
        handover = (handover_f)((UINTN)linux_addr + pe->opt.entry_point_addr);

        Print(L"Starting EFI kernel stub\n");

        handover(image, ST, image);

        return EFI_LOAD_ERROR;
}
