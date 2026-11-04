/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "pe-binary.h"

/* The PE header starts at file offset 0x40, and the optional header has 16 data directories. The section
 * table follows the optional header at file offset 0x148. */
#define PE_TEST_PE_OFFSET 0x40U
#define PE_TEST_OPTIONAL_HEADER_SIZE 0xf0U
#define PE_TEST_SECTION_TABLE_OFFSET (PE_TEST_PE_OFFSET + offsetof(PeHeader, optional) + PE_TEST_OPTIONAL_HEADER_SIZE)

/* Writes the DOS header and the headers of a PE32+ x86-64 EFI application to buf, which has to be zeroed.
 * size is the size of buf, which has to fit the headers and a section table with n_sections entries.
 * pe_load_headers() accepts the result. */
PeHeader* pe_test_init_headers(uint8_t *buf, size_t size, uint16_t n_sections);
