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

EFI_STATUS devicetree_install(struct devicetree_state *state, EFI_FILE *root_dir, char16_t *name) {
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

        err = devicetree_fixup(state, len);
        if (err != EFI_SUCCESS)
                return err;

        return BS->InstallConfigurationTable(
                        MAKE_GUID_PTR(EFI_DTB_TABLE), PHYSICAL_ADDRESS_TO_POINTER(state->addr));
}

static const char* devicetree_get_compatible(const void *dtb) {
        if ((uintptr_t) dtb % alignof(FdtHeader) != 0)
                return NULL;

        const FdtHeader *dt_header = ASSERT_PTR(dtb);

        if (be32toh(dt_header->magic) != UINT32_C(0xd00dfeed))
                return NULL;

        uint32_t dt_size = be32toh(dt_header->total_size);
        uint32_t struct_off = be32toh(dt_header->off_dt_struct);
        uint32_t struct_size = be32toh(dt_header->size_dt_struct);
        uint32_t strings_off = be32toh(dt_header->off_dt_strings);
        uint32_t strings_size = be32toh(dt_header->size_dt_strings);
        uint32_t end;

        if (PTR_TO_SIZE(dtb) > SIZE_MAX - dt_size)
                return NULL;

        if (!ADD_SAFE(&end, strings_off, strings_size) || end > dt_size)
                return NULL;
        const char *strings_block = (const char *) ((const uint8_t *) dt_header + strings_off);

        if (struct_off % sizeof(uint32_t) != 0)
                return NULL;

        if (struct_size % sizeof(uint32_t) != 0 ||
            !ADD_SAFE(&end, struct_off, struct_size) ||
            end > strings_off)
                return NULL;
        const uint32_t *cursor = (const uint32_t *) ((const uint8_t *) dt_header + struct_off);

        size_t size_words = struct_size / sizeof(uint32_t);
        size_t len, name_off, len_words, s;

        for (size_t i = 0; i < end; i++) {
                switch (be32toh(cursor[i])) {
                case FDT_BEGIN_NODE:
                        if (i >= size_words || cursor[++i] != 0)
                                return NULL;
                        break;
                case FDT_NOP:
                        break;
                case FDT_PROP:
                        /* At least 3 words should present: len, name_off, c (nul-terminated string always has non-zero length) */
                        if (i + 3 >= size_words)
                                return NULL;
                        len = be32toh(cursor[++i]);
                        name_off = be32toh(cursor[++i]);
                        len_words = DIV_ROUND_UP(len, sizeof(uint32_t));

                        if (ADD_SAFE(&s, name_off, STRLEN("compatible")) &&
                            s < strings_size && streq8(strings_block + name_off, "compatible")) {
                                const char *c = (const char *) &cursor[++i];
                                if (len == 0 || i + len_words > size_words || c[len - 1] != '\0')
                                        c = NULL;

                                return c;
                        }
                        i += len_words;
                        break;
                default:
                        return NULL;
                }
        }

        return NULL;
}

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
        const void *fw_dtb = find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));
        if (!fw_dtb)
                return EFI_UNSUPPORTED;

        const char *fw_compat = devicetree_get_compatible(fw_dtb);
        if (!fw_compat)
                return EFI_UNSUPPORTED;

        return devicetree_match_by_compatible(uki_dtb, uki_dtb_length, fw_compat);
}

EFI_STATUS devicetree_match_by_compatible(const void *uki_dtb, size_t uki_dtb_length, const char *compat) {
        if ((uintptr_t) uki_dtb % alignof(FdtHeader) != 0)
                return EFI_INVALID_PARAMETER;

        const FdtHeader *dt_header = ASSERT_PTR(uki_dtb);

        if (uki_dtb_length < sizeof(FdtHeader) ||
            uki_dtb_length < be32toh(dt_header->total_size))
                return EFI_INVALID_PARAMETER;

        if (!compat)
                return EFI_INVALID_PARAMETER;

        const char *dt_compat = devicetree_get_compatible(uki_dtb);
        if (!dt_compat)
                return EFI_INVALID_PARAMETER;

        /* Only matches the first compatible string from each DT */
        return streq8(dt_compat, compat) ? EFI_SUCCESS : EFI_NOT_FOUND;
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
