/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe-test-util.h"

PeHeader* pe_test_init_headers(uint8_t *buf, uint16_t n_sections) {
        assert(buf);

        ((IMAGE_DOS_HEADER*) buf)->e_magic = htole16(0x5A4D);
        ((IMAGE_DOS_HEADER*) buf)->e_lfanew = htole32(PE_TEST_PE_OFFSET);

        PeHeader *h = (PeHeader*) (buf + PE_TEST_PE_OFFSET);
        h->signature = htole32(UINT32_C(0x00004550));
        h->pe.Machine = htole16(UINT16_C(0x8664));
        h->pe.NumberOfSections = htole16(n_sections);
        h->pe.SizeOfOptionalHeader = htole16(PE_TEST_OPTIONAL_HEADER_SIZE);
        h->pe.Characteristics = htole16(UINT16_C(0x0022));
        h->optional.Magic = htole16(UINT16_C(0x020B));
        h->optional.Subsystem = htole16(IMAGE_SUBSYSTEM_EFI_APPLICATION);
        h->optional.pe32plus_NumberOfRvaAndSizes = htole32(16);

        return h;
}
