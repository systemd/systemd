/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBFDT
#  include <libfdt.h>
#  include "efi-log.h"
#endif

#include "devicetree.h"
#include "proto/dt-fixup.h"
#include "util.h"

/* For the libfdt-less builds, which doesn't support overlays, but has minimal DTB support (loading) */
#if !HAVE_LIBFDT
struct fdt_header {
        uint32_t magic;
        uint32_t totalsize;
        uint32_t off_dt_struct;
        uint32_t off_dt_strings;
        uint32_t off_mem_rsvmap;
        uint32_t version;
        uint32_t last_comp_version;
};
#define FDT_V1_SIZE sizeof(struct fdt_header)
#endif

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
        size_t size;
        EFI_STATUS err;

        assert(state);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_DT_FIXUP_PROTOCOL), NULL, (void **) &fixup);
        /* Skip fixup if we cannot locate device tree fixup protocol */
        if (err != EFI_SUCCESS)
                return EFI_SUCCESS;

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

EFI_STATUS devicetree_load(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name) {
        _cleanup_file_close_ EFI_FILE *handle = NULL;
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

        state->size = len;
        return EFI_SUCCESS;
}

#if HAVE_LIBFDT
static const char* devicetree_get_compatible(const void *dtb, size_t dtb_size) {
        const char *compatible;
        int len;

        assert(dtb);

        if ((uintptr_t) dtb % alignof(struct fdt_header) != 0)
                return NULL;

        if (fdt_check_full(dtb, dtb_size) < 0)
                return NULL;

        compatible = fdt_getprop(dtb, /* nodeoffset= */ 0, "compatible", &len);
        if (!compatible || len <= 0 || compatible[len - 1] != '\0')
                return NULL;

        return compatible;
}
#endif

bool firmware_devicetree_exists(void) {
        return !!find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));
}

/* This function checks if the firmware provided DeviceTree
 * and a UKI provided DeviceTree contain the same first entry
 * on their respective "compatible" fields (which usually defines
 * the actual device model). More specifically, given the FW/UKI
 * "compatible" property pair:
 *
 *      compatible = "string1", "string2";
 *      compatible = "string1", "string3";
 *
 * the function reports a match, while for
 *
 *      compatible = "string1", "string3";
 *      compatible = "string2", "string1";
 *
 * it reports a mismatch.
 *
 * Other entries might refer to SoC and therefore can't be used for matching
 */
EFI_STATUS devicetree_match(const void *uki_dtb, size_t uki_dtb_length) {
#if HAVE_LIBFDT
        const void *fw_dtb = find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));
        if (!fw_dtb)
                return EFI_UNSUPPORTED;

        if ((uintptr_t) fw_dtb % alignof(struct fdt_header) != 0 || fdt_check_header(fw_dtb) < 0)
                return EFI_UNSUPPORTED;

        const char *fw_compat = devicetree_get_compatible(fw_dtb, fdt_totalsize(fw_dtb));
        if (!fw_compat)
                return EFI_UNSUPPORTED;

        return devicetree_match_by_compatible(uki_dtb, uki_dtb_length, fw_compat);
#else
        return EFI_UNSUPPORTED;
#endif
}

EFI_STATUS devicetree_match_by_compatible(const void *uki_dtb, size_t uki_dtb_length, const char *compat) {
#if HAVE_LIBFDT
        if (!compat)
                return EFI_INVALID_PARAMETER;

        const char *dt_compat = devicetree_get_compatible(uki_dtb, uki_dtb_length);
        if (!dt_compat)
                return EFI_INVALID_PARAMETER;

        /* Only matches the first compatible string from each DT */
        return streq8(dt_compat, compat) ? EFI_SUCCESS : EFI_NOT_FOUND;
#else
        return EFI_UNSUPPORTED;
#endif
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

EFI_STATUS devicetree_install(struct devicetree_state *state) {
        assert(state);

        /*there is no devicetree, so no-op*/
        if (!state->pages)
                return EFI_SUCCESS;

        EFI_STATUS err = devicetree_fixup(state, state->size);
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
