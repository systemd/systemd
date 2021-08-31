/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>

#include "devicetree.h"
#include "missing_efi.h"
#include "util.h"

#define FDT_V1_SIZE (7*4)

#ifndef EFI_DT_FIXUP_PROTOCOL_GUID
#define EFI_DT_FIXUP_PROTOCOL_GUID \
        { 0xe617d64c, 0xfe08, 0x46da, {0xf4, 0xdc, 0xbb, 0xd5, 0x87, 0x0c, 0x73, 0x00} }
#endif

#define EFI_DT_FIXUP_PROTOCOL_REVISION 0x00010000

/* Add nodes and update properties */
#define EFI_DT_APPLY_FIXUPS    0x00000001
/*
 * Reserve memory according to the /reserved-memory node
 * and the memory reservation block
 */
#define EFI_DT_RESERVE_MEMORY  0x00000002

typedef struct _EFI_DT_FIXUP_PROTOCOL EFI_DT_FIXUP_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_DT_FIXUP) (
        IN EFI_DT_FIXUP_PROTOCOL *This,
        IN VOID                  *Fdt,
        IN OUT UINTN             *BufferSize,
        IN UINT32                Flags);

struct _EFI_DT_FIXUP_PROTOCOL {
        UINT64         Revision;
        EFI_DT_FIXUP   Fixup;
};

static EFI_STATUS devicetree_allocate(struct devicetree_state *state, UINTN size) {
        UINTN pages = DIV_ROUND_UP(size, EFI_PAGE_SIZE);
        EFI_STATUS err;

        assert(state);

        err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAnyPages,
                        EfiACPIReclaimMemory, pages, &state->addr);
        if (EFI_ERROR(err))
                return err;

        state->pages = pages;
        return err;
}

static UINTN devicetree_allocated(struct devicetree_state *state) {
        assert(state);
        return state->pages * EFI_PAGE_SIZE;
}

static VOID *devicetree_ptr(struct devicetree_state *state) {
        assert(state);
        assert(state->addr <= UINTPTR_MAX);
        return (VOID *)(uintptr_t)state->addr;
}

static EFI_STATUS devicetree_fixup(struct devicetree_state *state, UINTN len) {
        EFI_DT_FIXUP_PROTOCOL *fixup;
        UINTN size;
        EFI_STATUS err;

        assert(state);

        err = LibLocateProtocol(&(EFI_GUID)EFI_DT_FIXUP_PROTOCOL_GUID, (VOID **)&fixup);
        if (EFI_ERROR(err)) {
                Print(L"Could not locate device tree fixup protocol, skipping.\n");
                return EFI_SUCCESS;
        }

        size = devicetree_allocated(state);
        err = uefi_call_wrapper(fixup->Fixup, 4, fixup,
                        devicetree_ptr(state), &size,
                        EFI_DT_APPLY_FIXUPS | EFI_DT_RESERVE_MEMORY);
        if (err == EFI_BUFFER_TOO_SMALL) {
                EFI_PHYSICAL_ADDRESS oldaddr = state->addr;
                UINTN oldpages = state->pages;

                err = devicetree_allocate(state, size);
                if (EFI_ERROR(err))
                        return err;

                CopyMem(devicetree_ptr(state), (VOID *)(uintptr_t)oldaddr, len);
                err = uefi_call_wrapper(BS->FreePages, 2, oldaddr, oldpages);
                if (EFI_ERROR(err))
                        return err;

                size = devicetree_allocated(state);
                err = uefi_call_wrapper(fixup->Fixup, 4, fixup,
                                devicetree_ptr(state), &size,
                                EFI_DT_APPLY_FIXUPS | EFI_DT_RESERVE_MEMORY);
        }

        return err;
}

EFI_STATUS devicetree_install(struct devicetree_state *state,
                EFI_FILE_HANDLE root_dir, CHAR16 *name) {
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *info = NULL;
        UINTN len;
        EFI_STATUS err;

        assert(state);
        assert(root_dir);
        assert(name);

        err = LibGetSystemConfigurationTable(&(EFI_GUID)EFI_DTB_TABLE_GUID,
                                             &state->orig);
        if (EFI_ERROR(err))
                return EFI_UNSUPPORTED;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, name,
                        EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
        if (EFI_ERROR(err))
                return err;

        info = LibFileInfo(handle);
        if (!info)
                return EFI_OUT_OF_RESOURCES;
        if (info->FileSize < FDT_V1_SIZE || info->FileSize > 32 * 1024 * 1024)
                /* 32MB device tree blob doesn't seem right */
                return EFI_INVALID_PARAMETER;

        len = info->FileSize;

        err = devicetree_allocate(state, len);
        if (EFI_ERROR(err))
                return err;

        err = uefi_call_wrapper(handle->Read, 3, handle, &len,
                        devicetree_ptr(state));
        if (EFI_ERROR(err))
                return err;

        err = devicetree_fixup(state, len);
        if (EFI_ERROR(err))
                return err;

        return uefi_call_wrapper(BS->InstallConfigurationTable, 2,
                        &(EFI_GUID)EFI_DTB_TABLE_GUID, devicetree_ptr(state));
}

void devicetree_cleanup(struct devicetree_state *state) {
        EFI_STATUS err;

        if (!state->pages)
                return;

        err = uefi_call_wrapper(BS->InstallConfigurationTable, 2,
                        &(EFI_GUID)EFI_DTB_TABLE_GUID, state->orig);
        /* don't free the current device tree if we can't reinstate the old one */
        if (EFI_ERROR(err))
                return;

        uefi_call_wrapper(BS->FreePages, 2, state->addr, state->pages);
}
