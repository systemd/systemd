/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct PeWriter PeWriter;
typedef struct PeWriterSection PeWriterSection;

typedef enum PeWriterFlags {
        /* PE_WRITER_ALIGN_DATA starts the data of new sections at multiples of 4096 bytes where the layout
         * of the input allows it. The extents of the first file of each new section can then be shared with
         * the output. Every new section grows by up to 4095 bytes. A memfd never shares extents with the
         * output, so the flag only helps callers that add sections from files on disk. */
        PE_WRITER_ALIGN_DATA = 1 << 0,
} PeWriterFlags;

int pe_writer_new(int fd, PeWriterFlags flags, PeWriter **ret);
PeWriter* pe_writer_free(PeWriter *w);
DEFINE_TRIVIAL_CLEANUP_FUNC(PeWriter*, pe_writer_free);

int pe_writer_find_section(const PeWriter *w, const char *name, size_t start, size_t *ret_index);
int pe_writer_replace_section(PeWriter *w, size_t index, const struct iovec *data);

int pe_writer_add_section(PeWriter *w, const char *name, uint32_t characteristics, PeWriterSection **ret);
int pe_writer_section_append_fd(PeWriterSection *s, int fd, uint64_t offset, uint64_t size);

void pe_writer_clear_dll_characteristics(PeWriter *w, uint16_t mask);

int pe_writer_write(const PeWriter *w, int output_fd);

int pe_append_signature(int fd, const void *signature, size_t size);
