/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>

#include "devicetree.h"
#include "missing_efi.h"
#include "util.h"

#define FDT_V1_SIZE (7*4)

static EFI_STATUS devicetree_allocate(struct devicetree_state *state, UINTN size) {
        UINTN pages = DIV_ROUND_UP(size, EFI_PAGE_SIZE);
        EFI_STATUS err;

        assert(state);

        err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAnyPages, EfiACPIReclaimMemory, pages,
                                &state->addr);
        if (EFI_ERROR(err))
                return err;

        state->pages = pages;
        return err;
}

static UINTN devicetree_allocated(const struct devicetree_state *state) {
        assert(state);
        return state->pages * EFI_PAGE_SIZE;
}

static VOID *devicetree_ptr(const struct devicetree_state *state) {
        assert(state);
        assert(state->addr <= UINTN_MAX);
        return (VOID *)(UINTN)state->addr;
}

static EFI_STATUS devicetree_fixup(struct devicetree_state *state, UINTN len) {
        EFI_DT_FIXUP_PROTOCOL *fixup;
        UINTN size;
        EFI_STATUS err;

        assert(state);

        err = LibLocateProtocol(&EfiDtFixupProtocol, (VOID **)&fixup);
        if (EFI_ERROR(err))
                return log_error_status_stall(EFI_SUCCESS,
                                              L"Could not locate device tree fixup protocol, skipping.");

        size = devicetree_allocated(state);
        err = uefi_call_wrapper(fixup->Fixup, 4, fixup, devicetree_ptr(state), &size,
                                EFI_DT_APPLY_FIXUPS | EFI_DT_RESERVE_MEMORY);
        if (err == EFI_BUFFER_TOO_SMALL) {
                EFI_PHYSICAL_ADDRESS oldaddr = state->addr;
                UINTN oldpages = state->pages;
                VOID *oldptr = devicetree_ptr(state);

                err = devicetree_allocate(state, size);
                if (EFI_ERROR(err))
                        return err;

                CopyMem(devicetree_ptr(state), oldptr, len);
                err = uefi_call_wrapper(BS->FreePages, 2, oldaddr, oldpages);
                if (EFI_ERROR(err))
                        return err;

                size = devicetree_allocated(state);
                err = uefi_call_wrapper(fixup->Fixup, 4, fixup, devicetree_ptr(state), &size,
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

        err = LibGetSystemConfigurationTable(&EfiDtbTableGuid, &state->orig);
        if (EFI_ERROR(err))
                return EFI_UNSUPPORTED;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, name, EFI_FILE_MODE_READ,
                                EFI_FILE_READ_ONLY);
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

        err = uefi_call_wrapper(handle->Read, 3, handle, &len, devicetree_ptr(state));
        if (EFI_ERROR(err))
                return err;

        err = devicetree_fixup(state, len);
        if (EFI_ERROR(err))
                return err;

        return uefi_call_wrapper(BS->InstallConfigurationTable, 2, &EfiDtbTableGuid, devicetree_ptr(state));
}

void devicetree_cleanup(struct devicetree_state *state) {
        EFI_STATUS err;

        if (!state->pages)
                return;

        err = uefi_call_wrapper(BS->InstallConfigurationTable, 2, &EfiDtbTableGuid, state->orig);
        /* don't free the current device tree if we can't reinstate the old one */
        if (EFI_ERROR(err))
                return;

        uefi_call_wrapper(BS->FreePages, 2, state->addr, state->pages);
        state->pages = 0;
}
