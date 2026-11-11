/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe-test-util.h"

PeHeader* pe_test_init_headers(uint8_t *buf, size_t size, uint16_t n_sections) {
        assert(buf);
        assert(size >= PE_TEST_SECTION_TABLE_OFFSET + n_sections * sizeof(IMAGE_SECTION_HEADER));

        *(IMAGE_DOS_HEADER*) buf = (IMAGE_DOS_HEADER) {
                .e_magic = htole16(0x5A4D),
                .e_lfanew = htole32(PE_TEST_PE_OFFSET),
        };

        PeHeader *h = (PeHeader*) (buf + PE_TEST_PE_OFFSET);
        *h = (PeHeader) {
                .signature = htole32(UINT32_C(0x00004550)),
                .pe = {
                        .Machine = htole16(UINT16_C(0x8664)),
                        .NumberOfSections = htole16(n_sections),
                        .SizeOfOptionalHeader = htole16(PE_TEST_OPTIONAL_HEADER_SIZE),
                        .Characteristics = htole16(UINT16_C(0x0022)),
                },
                .optional = {
                        .Magic = htole16(UINT16_C(0x020B)),
                        .Subsystem = htole16(IMAGE_SUBSYSTEM_EFI_APPLICATION),
                        .pe32plus_NumberOfRvaAndSizes = htole32(16),
                },
        };

        return h;
}
