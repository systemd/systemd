/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "devicetree.h"
#include "proto/dt-fixup.h"
#include "util.h"

#define FDT_V1_SIZE (7*4)

static EFI_STATUS devicetree_allocate(struct devicetree_state *state, size_t size) {
        size_t pages = DIV_ROUND_UP(size, EFI_PAGE_SIZE);
        EFI_STATUS err;

        assert(state);

        err = BS->AllocatePages(AllocateAnyPages, EfiACPIReclaimMemory, pages, &state->addr);
        if (err != EFI_SUCCESS)
                return err;

        state->pages = pages;
        return err;
}

static size_t devicetree_allocated(const struct devicetree_state *state) {
        assert(state);
        return state->pages * EFI_PAGE_SIZE;
}

static EFI_STATUS devicetree_fixup(struct devicetree_state *state, size_t len) {
        EFI_DT_FIXUP_PROTOCOL *fixup;
        void *fixup_raw;
        size_t size;
        EFI_STATUS err;

        assert(state);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_DT_FIXUP_PROTOCOL), NULL, &fixup_raw);
        if (err != EFI_SUCCESS)
                return log_error_status(EFI_SUCCESS, "Could not locate device tree fixup protocol, skipping.");
        
        fixup = fixup_raw;
        size = devicetree_allocated(state);
        err = fixup->Fixup(fixup, PHYSICAL_ADDRESS_TO_POINTER(state->addr), &size,
                           EFI_DT_APPLY_FIXUPS | EFI_DT_RESERVE_MEMORY);
        if (err == EFI_BUFFER_TOO_SMALL) {
                EFI_PHYSICAL_ADDRESS oldaddr = state->addr;
                size_t oldpages = state->pages;
                void *oldptr = PHYSICAL_ADDRESS_TO_POINTER(state->addr);

                err = devicetree_allocate(state, size);
                if (err != EFI_SUCCESS)
                        return err;

                memcpy(PHYSICAL_ADDRESS_TO_POINTER(state->addr), oldptr, len);
                err = BS->FreePages(oldaddr, oldpages);
                if (err != EFI_SUCCESS)
                        return err;

                size = devicetree_allocated(state);
                err = fixup->Fixup(fixup, PHYSICAL_ADDRESS_TO_POINTER(state->addr), &size,
                                   EFI_DT_APPLY_FIXUPS | EFI_DT_RESERVE_MEMORY);
        }

        return err;
}

EFI_STATUS devicetree_install(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name) {
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ EFI_FILE_INFO *info = NULL;
        size_t len;
        EFI_STATUS err;

        assert(state);
        assert(root_dir);
        assert(name);

        /* Capture the original value for the devicetree table. NULL is not an error in this case so we don't
         * need to check the return value. NULL simply means the system fw had no devicetree initially (and
         * is the correct value to use to return to the initial state if needed). */
        state->orig = find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));

        err = root_dir->Open(root_dir, &handle, name, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
        if (err != EFI_SUCCESS)
                return err;

        err = get_file_info(handle, &info, NULL);
        if (err != EFI_SUCCESS)
                return err;
        if (info->FileSize < FDT_V1_SIZE || info->FileSize > 32 * 1024 * 1024)
                /* 32MB device tree blob doesn't seem right */
                return EFI_INVALID_PARAMETER;

        len = info->FileSize;

        err = devicetree_allocate(state, len);
        if (err != EFI_SUCCESS)
                return err;

        err = handle->Read(handle, &len, PHYSICAL_ADDRESS_TO_POINTER(state->addr));
        if (err != EFI_SUCCESS)
                return err;

        err = devicetree_fixup(state, len);
        if (err != EFI_SUCCESS)
                return err;

        return BS->InstallConfigurationTable(
                        MAKE_GUID_PTR(EFI_DTB_TABLE), PHYSICAL_ADDRESS_TO_POINTER(state->addr));
}

EFI_STATUS devicetree_install_from_memory(
                struct devicetree_state *state, const void *dtb_buffer, size_t dtb_length) {

        EFI_STATUS err;

        assert(state);
        assert(dtb_buffer && dtb_length > 0);

        /* Capture the original value for the devicetree table. NULL is not an error in this case so we don't
         * need to check the return value. NULL simply means the system fw had no devicetree initially (and
         * is the correct value to use to return to the initial state if needed). */
        state->orig = find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));

        err = devicetree_allocate(state, dtb_length);
        if (err != EFI_SUCCESS)
                return err;

        memcpy(PHYSICAL_ADDRESS_TO_POINTER(state->addr), dtb_buffer, dtb_length);

        err = devicetree_fixup(state, dtb_length);
        if (err != EFI_SUCCESS)
                return err;

        return BS->InstallConfigurationTable(
                        MAKE_GUID_PTR(EFI_DTB_TABLE), PHYSICAL_ADDRESS_TO_POINTER(state->addr));
}

void devicetree_cleanup(struct devicetree_state *state) {
        EFI_STATUS err;

        if (!state->pages)
                return;

        err = BS->InstallConfigurationTable(MAKE_GUID_PTR(EFI_DTB_TABLE), state->orig);
        /* don't free the current device tree if we can't reinstate the old one */
        if (err != EFI_SUCCESS)
                return;

        BS->FreePages(state->addr, state->pages);
        state->pages = 0;
}
