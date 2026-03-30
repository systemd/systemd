/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe-reloc.h"
#include "unaligned.h"

EFI_STATUS pe_apply_base_relocations(
                uint8_t *loaded_base,
                size_t loaded_size,
                uint32_t reloc_rva,
                uint32_t reloc_size,
                uint64_t delta) {

        assert(loaded_base);

        if (reloc_size == 0 || delta == 0)
                return EFI_SUCCESS;

        if (reloc_rva > loaded_size || reloc_size > loaded_size - reloc_rva)
                return EFI_LOAD_ERROR;

        /* Walk the relocation blocks. Each block starts with a header:
         *   uint32_t VirtualAddress  (page RVA)
         *   uint32_t SizeOfBlock     (total block size including header)
         * Followed by uint16_t entries: top 4 bits = type, bottom 12 bits = offset within page. */
        const uint8_t *reloc_ptr = loaded_base + reloc_rva;
        const uint8_t *reloc_end = reloc_ptr + reloc_size;

        while (reloc_ptr < reloc_end) {
                size_t remaining = reloc_end - reloc_ptr;
                if (remaining < 8)
                        return EFI_LOAD_ERROR;

                uint32_t page_rva = unaligned_read_ne32(reloc_ptr);
                uint32_t block_size = unaligned_read_ne32(reloc_ptr + 4);

                if (block_size < 8 || block_size > remaining)
                        return EFI_LOAD_ERROR;
                if ((block_size - 8) % sizeof(uint16_t) != 0)
                        return EFI_LOAD_ERROR;

                size_t n_entries = (block_size - 8) / sizeof(uint16_t);

                for (size_t i = 0; i < n_entries; i++) {
                        uint16_t entry = unaligned_read_ne16(reloc_ptr + 8 + i * sizeof(uint16_t));
                        uint16_t type = entry >> 12;
                        uint16_t offset = entry & 0xFFF;

                        if (page_rva > UINT32_MAX - offset)
                                return EFI_LOAD_ERROR;

                        uint32_t fixup_rva = page_rva + offset;

                        switch (type) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                                /* Padding, skip. */
                                break;
                        case IMAGE_REL_BASED_DIR64:
                                if (fixup_rva > loaded_size || sizeof(uint64_t) > loaded_size - fixup_rva)
                                        return EFI_LOAD_ERROR;

                                unaligned_write_ne64(
                                                loaded_base + fixup_rva,
                                                unaligned_read_ne64(loaded_base + fixup_rva) + delta);
                                break;
                        default:
                                return EFI_LOAD_ERROR;
                        }
                }

                reloc_ptr += block_size;
        }

        return EFI_SUCCESS;
}
