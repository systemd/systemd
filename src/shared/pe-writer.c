/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "efi.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "memory-util.h"
#include "pe-binary.h"
#include "pe-writer.h"
#include "stat-util.h"
#include "string-util.h"
#include "utf8.h"

/* Real PE images have a few KiB of headers. The limit stops a malformed SizeOfHeaders from allocating a
 * large buffer. */
#define PE_WRITER_HEADERS_MAX (1024U * 1024U)

#define COFF_SYMBOL_SIZE 18U

typedef struct PeWriterChunk {
        int fd;
        uint64_t offset;
        uint64_t size;
} PeWriterChunk;

struct PeWriterSection {
        char name[sizeof_field(IMAGE_SECTION_HEADER, Name) + 1];
        uint32_t characteristics;
        PeWriterChunk *chunks;
        size_t n_chunks;
        uint64_t size;
};

typedef struct PeWriterReplacement {
        /* Contains the new data, padded with zeroes to the raw size of the section. */
        struct iovec raw;
        /* Contains the size of the new data without the padding. */
        size_t virtual_size;
        bool set;
} PeWriterReplacement;

struct PeWriter {
        int fd;

        /* Contains the input's headers. When pe_writer_new() strips the symbol table, it also clears the
         * symbol table fields in 'headers'. */
        uint8_t *headers;
        size_t headers_size;
        size_t pe_offset;
        size_t section_table_offset;
        size_t n_sections;
        bool is_signed;

        /* The input is copied up to 'data_end', which excludes a stripped symbol table. */
        uint64_t data_end;
        uint32_t file_alignment;
        uint32_t section_alignment;

        PeWriterReplacement *replacements;

        PeWriterSection **new_sections;
        size_t n_new_sections;

        uint16_t dll_characteristics_clear;
};

static PeWriterSection* pe_writer_section_free(PeWriterSection *s) {
        if (!s)
                return NULL;

        FOREACH_ARRAY(c, s->chunks, s->n_chunks)
                safe_close(c->fd);

        free(s->chunks);
        return mfree(s);
}

PeWriter* pe_writer_free(PeWriter *w) {
        if (!w)
                return NULL;

        safe_close(w->fd);
        free(w->headers);

        FOREACH_ARRAY(r, w->replacements, w->n_sections)
                iovec_done(&r->raw);
        free(w->replacements);

        FOREACH_ARRAY(s, w->new_sections, w->n_new_sections)
                pe_writer_section_free(*s);
        free(w->new_sections);

        return mfree(w);
}

/* 'fd' must refer to a regular file that contains a PE image whose section data is aligned to the file
 * alignment. pe_writer_new() reads the headers, and pe_writer_write() copies the rest of the file from 'fd'.
 * The file must not change in between, otherwise the output does not match the headers. */
int pe_writer_new(int fd, PeWriter **ret) {
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        assert(fd >= 0);
        assert(ret);

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat PE file: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "PE file is not a regular file: %m");

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return log_debug_errno(r, "Failed to load PE headers: %m");

        size_t n_sections = le16toh(pe_header->pe.NumberOfSections);
        uint32_t file_alignment = le32toh(pe_header->optional.FileAlignment),
                 section_alignment = le32toh(pe_header->optional.SectionAlignment);

        if (!ISPOWEROF2(file_alignment) || !ISPOWEROF2(section_alignment) || section_alignment < file_alignment)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Invalid PE alignment (file alignment %" PRIu32 ", section alignment %" PRIu32 ").",
                                       file_alignment, section_alignment);

        uint64_t pe_offset = le32toh(dos_header->e_lfanew),
                 section_table_offset = pe_offset + offsetof(PeHeader, optional) + le16toh(pe_header->pe.SizeOfOptionalHeader),
                 section_table_end = section_table_offset + n_sections * sizeof(IMAGE_SECTION_HEADER),
                 size_of_headers = le32toh(pe_header->optional.SizeOfHeaders);

        if (size_of_headers < section_table_end)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE headers do not contain the section table.");

        if (section_table_end > (uint64_t) st.st_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE file ends before the end of the section table.");

        /* Padding SizeOfHeaders to the file alignment adds space for more section headers. The space is
         * unused as long as the first section starts at or after the padded size. */
        uint64_t headers_size = ALIGN_TO_U64(size_of_headers, file_alignment);
        if (headers_size > PE_WRITER_HEADERS_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE headers are too large.");

        _cleanup_free_ uint8_t *headers = new0(uint8_t, headers_size);
        if (!headers)
                return log_oom_debug();

        size_t m = MIN(headers_size, (uint64_t) st.st_size);
        ssize_t n = pread(fd, headers, m, 0);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE headers: %m");
        if ((size_t) n != m)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading PE headers.");

        /* pe_writer_write() uses the section table in 'headers'. If the section table was validated in a
         * separate read, the file could change between the two reads. */
        const IMAGE_SECTION_HEADER *sections = (const IMAGE_SECTION_HEADER*) (headers + section_table_offset);
        uint64_t sections_end = headers_size;
        FOREACH_ARRAY(s, sections, n_sections) {
                uint64_t prd = le32toh(s->PointerToRawData), srd = le32toh(s->SizeOfRawData);

                if (le32toh(s->VirtualAddress) < headers_size)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE section is mapped over the headers.");

                if (srd == 0)
                        continue;

                /* Only old stubs that were stripped after linking have misaligned section data. ukify moves
                 * that data to fix the alignment, and the writer does not implement this. */
                if (prd % file_alignment != 0 || srd % file_alignment != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "PE section data is not aligned to the file alignment.");

                if (prd < headers_size)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE section data overlaps the headers.");

                if (prd + srd > (uint64_t) st.st_size)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE section data extends beyond the end of the file.");

                sections_end = MAX(sections_end, prd + srd);
        }

        /* ukify keeps all data after the sections, except a COFF symbol table at the end of the file. In a
         * signed image, the certificate table is at the end of the file. A symbol table that overlaps the
         * certificate table is kept, because stripping it would also strip the certificates. */
        uint64_t data_end = st.st_size, symbol_table_min = sections_end;
        bool strip_symbols = false;

        if (pe_header_is_signed(pe_header)) {
                const IMAGE_DATA_DIRECTORY *certificate_table =
                        pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);

                symbol_table_min = MAX(symbol_table_min,
                                       (uint64_t) le32toh(certificate_table->VirtualAddress) + le32toh(certificate_table->Size));
        }

        uint64_t symbol_table = le32toh(pe_header->pe.PointerToSymbolTable);
        if (symbol_table >= symbol_table_min) {
                uint64_t symbol_table_size = (uint64_t) le32toh(pe_header->pe.NumberOfSymbols) * COFF_SYMBOL_SIZE;

                /* The string table follows the symbol table and starts with its own size. pread() only
                 * returns fewer bytes than requested if the file ends. If the file ends right after the
                 * symbol table, there is no string table and the symbol table is stripped. If the file
                 * ends inside the size field, the check below fails and the file is kept as it is. */
                le32_t string_table_size = 0;
                n = pread(fd, &string_table_size, sizeof(string_table_size), symbol_table + symbol_table_size);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read COFF string table size: %m");
                if ((size_t) n == sizeof(string_table_size))
                        symbol_table_size += le32toh(string_table_size);

                if (symbol_table + symbol_table_size == (uint64_t) st.st_size) {
                        data_end = symbol_table;
                        strip_symbols = true;
                }
        }

        _cleanup_(pe_writer_freep) PeWriter *w = new(PeWriter, 1);
        if (!w)
                return log_oom_debug();

        *w = (PeWriter) {
                .fd = -EBADF,
                .headers = TAKE_PTR(headers),
                .headers_size = headers_size,
                .pe_offset = pe_offset,
                .section_table_offset = section_table_offset,
                .n_sections = n_sections,
                .is_signed = pe_header_is_signed(pe_header),
                .data_end = data_end,
                .file_alignment = file_alignment,
                .section_alignment = section_alignment,
        };

        w->replacements = new0(PeWriterReplacement, n_sections);
        if (!w->replacements && n_sections > 0)
                return log_oom_debug();

        w->fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (w->fd < 0)
                return log_debug_errno(errno, "Failed to duplicate PE file descriptor: %m");

        PeHeader *h = (PeHeader*) (w->headers + w->pe_offset);
        h->optional.SizeOfHeaders = htole32(headers_size);

        if (strip_symbols) {
                h->pe.PointerToSymbolTable = 0;
                h->pe.NumberOfSymbols = 0;
                h->pe.Characteristics = htole16(le16toh(h->pe.Characteristics) | IMAGE_FILE_LOCAL_SYMS_STRIPPED);
        }

        *ret = TAKE_PTR(w);
        return 0;
}

int pe_writer_find_section(const PeWriter *w, const char *name, size_t start, size_t *ret_index) {
        assert(w);
        assert(name);

        if (start >= w->n_sections)
                return -ENXIO;

        const IMAGE_SECTION_HEADER *sections = (const IMAGE_SECTION_HEADER*) (w->headers + w->section_table_offset);
        const IMAGE_SECTION_HEADER *s = pe_section_table_find(sections + start, w->n_sections - start, name);
        if (!s)
                return -ENXIO;

        if (ret_index)
                *ret_index = s - sections;

        return 0;
}

int pe_writer_replace_section(PeWriter *w, size_t index, const struct iovec *data) {
        assert(w);
        assert(index < w->n_sections);

        const IMAGE_SECTION_HEADER *sections = (const IMAGE_SECTION_HEADER*) (w->headers + w->section_table_offset),
                                   *s = sections + index;
        size_t size = data ? data->iov_len : 0, raw_size = le32toh(s->SizeOfRawData);

        if (size > raw_size)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "PE section is too small for the new data (%zu bytes, %zu available).",
                                       size, raw_size);

        /* Growing VirtualSize must not map the section over the next section in memory. */
        uint64_t va = le32toh(s->VirtualAddress);
        FOREACH_ARRAY(other, sections, w->n_sections) {
                uint64_t other_va = le32toh(other->VirtualAddress);

                if (other != s && other_va > va && va + size > other_va)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "PE section would overlap the next section in memory.");
        }

        _cleanup_free_ uint8_t *padded = new0(uint8_t, raw_size);
        if (!padded && raw_size > 0)
                return log_oom_debug();

        if (size > 0)
                memcpy(padded, data->iov_base, size);

        PeWriterReplacement *replacement = w->replacements + index;
        iovec_done(&replacement->raw);
        replacement->raw = IOVEC_MAKE(TAKE_PTR(padded), raw_size);
        replacement->virtual_size = size;
        replacement->set = true;
        return 0;
}

int pe_writer_add_section(PeWriter *w, const char *name, uint32_t characteristics, PeWriterSection **ret) {
        assert(w);
        assert(name);

        /* Longer names would need the COFF string table, which systemd-stub does not read. */
        if (isempty(name) || strlen(name) > sizeof_field(IMAGE_SECTION_HEADER, Name) ||
            !ascii_is_valid(name) || string_has_cc(name, /* ok= */ NULL))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PE section name '%s'.", name);

        /* New sections would be placed after the certificate table, which has to stay at the end of the
         * file. */
        if (w->is_signed)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Cannot add sections to a signed PE image.");

        size_t n_sections = w->n_sections + w->n_new_sections;
        if (n_sections >= UINT16_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(E2BIG), "Too many PE sections.");

        uint64_t offset = w->section_table_offset + n_sections * sizeof(IMAGE_SECTION_HEADER);
        if (offset + sizeof(IMAGE_SECTION_HEADER) > w->headers_size)
                return log_debug_errno(SYNTHETIC_ERRNO(E2BIG), "PE headers have no room for another section.");

        if (!memeqzero(w->headers + offset, sizeof(IMAGE_SECTION_HEADER)))
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PE headers contain data after the section table.");

        if (!GREEDY_REALLOC(w->new_sections, w->n_new_sections + 1))
                return log_oom_debug();

        PeWriterSection *s = new(PeWriterSection, 1);
        if (!s)
                return log_oom_debug();

        *s = (PeWriterSection) {
                .characteristics = characteristics,
        };
        memcpy(s->name, name, strlen(name));

        w->new_sections[w->n_new_sections++] = s;

        if (ret)
                *ret = s;

        return 0;
}

static int section_append_chunk(PeWriterSection *s, PeWriterChunk chunk) {
        assert(s);

        uint64_t size;
        if (!ADD_SAFE(&size, s->size, chunk.size) || size > UINT32_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "PE section '%s' is too large.", s->name);

        if (!GREEDY_REALLOC(s->chunks, s->n_chunks + 1))
                return log_oom_debug();

        s->chunks[s->n_chunks++] = chunk;
        s->size = size;
        return 0;
}

int pe_writer_section_append_fd(PeWriterSection *s, int fd, uint64_t offset, uint64_t size) {
        int r;

        assert(s);
        assert(fd >= 0);

        if (size == 0)
                return 0;

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat file for PE section '%s': %m", s->name);

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "File for PE section '%s' is not a regular file: %m", s->name);

        uint64_t end;
        if (!ADD_SAFE(&end, offset, size) || end > (uint64_t) st.st_size)
                return log_debug_errno(SYNTHETIC_ERRNO(ERANGE),
                                       "Data for PE section '%s' extends beyond the end of the file.", s->name);

        _cleanup_close_ int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return log_debug_errno(errno, "Failed to duplicate file descriptor: %m");

        r = section_append_chunk(s, (PeWriterChunk) {
                .fd = copy,
                .offset = offset,
                .size = size,
        });
        if (r < 0)
                return r;

        TAKE_FD(copy);
        return 0;
}

void pe_writer_clear_dll_characteristics(PeWriter *w, uint16_t mask) {
        assert(w);

        w->dll_characteristics_clear |= mask;
}

int pe_writer_write(const PeWriter *w, int output_fd) {
        int r;

        assert(w);
        assert(output_fd >= 0);

        r = fd_verify_regular(output_fd);
        if (r < 0)
                return log_debug_errno(r, "Output is not a regular file: %m");

        /* The output is truncated before the input files are copied. If the output is one of the input
         * files, the truncation deletes the data to copy. */
        r = fd_inode_same(output_fd, w->fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to compare output and PE file: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Output is the PE file itself.");

        FOREACH_ARRAY(s, w->new_sections, w->n_new_sections)
                FOREACH_ARRAY(c, (*s)->chunks, (*s)->n_chunks) {
                        r = fd_inode_same(output_fd, c->fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to compare output and file for PE section '%s': %m", (*s)->name);
                        if (r > 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Output is the file for PE section '%s'.", (*s)->name);
                }

        _cleanup_free_ uint8_t *headers = memdup(w->headers, w->headers_size);
        if (!headers)
                return log_oom_debug();

        PeHeader *pe_header = (PeHeader*) (headers + w->pe_offset);
        IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER*) (headers + w->section_table_offset);

        uint64_t image_end = w->headers_size;
        for (size_t i = 0; i < w->n_sections; i++) {
                if (w->replacements[i].set)
                        sections[i].VirtualSize = htole32(w->replacements[i].virtual_size);

                image_end = MAX(image_end, (uint64_t) le32toh(sections[i].VirtualAddress) + le32toh(sections[i].VirtualSize));
        }

        /* If the file ends inside the padded headers, data_end is smaller than headers_size. New section
         * data must start after the headers. */
        uint64_t file_end = MAX(w->data_end, (uint64_t) w->headers_size),
                 initialized_data = le32toh(pe_header->optional.SizeOfInitializedData),
                 va = ALIGN_TO_U64(image_end, w->section_alignment),
                 raw = ALIGN_TO_U64(file_end, w->file_alignment);

        IMAGE_SECTION_HEADER *new_sections = sections + w->n_sections;
        for (size_t i = 0; i < w->n_new_sections; i++) {
                const PeWriterSection *s = w->new_sections[i];
                uint64_t raw_size = ALIGN_TO_U64(s->size, w->file_alignment);

                if (raw + raw_size > UINT32_MAX || va + s->size > UINT32_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "PE image is too large.");

                IMAGE_SECTION_HEADER *h = new_sections + i;
                memcpy(h->Name, s->name, strlen(s->name));
                h->VirtualSize = htole32(s->size);
                h->VirtualAddress = htole32(va);
                h->SizeOfRawData = htole32(raw_size);
                h->PointerToRawData = htole32(raw);
                h->Characteristics = htole32(s->characteristics);

                initialized_data += s->size;
                image_end = va + s->size;
                file_end = raw + raw_size;

                raw += raw_size;
                va = ALIGN_TO_U64(image_end, w->section_alignment);
        }

        uint64_t size_of_image = ALIGN_TO_U64(image_end, w->section_alignment);
        if (initialized_data > UINT32_MAX || size_of_image > UINT32_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "PE image is too large.");

        pe_header->pe.NumberOfSections = htole16(w->n_sections + w->n_new_sections);
        pe_header->optional.SizeOfInitializedData = htole32(initialized_data);
        pe_header->optional.SizeOfImage = htole32(size_of_image);
        pe_header->optional.CheckSum = 0;
        pe_header->optional.DllCharacteristics =
                htole16(le16toh(pe_header->optional.DllCharacteristics) & ~w->dll_characteristics_clear);

        /* Start from an empty file, so that padding that is not written explicitly reads as zeroes. */
        if (ftruncate(output_fd, 0) < 0)
                return log_debug_errno(errno, "Failed to truncate output file: %m");

        r = pwrite_full(output_fd, headers, w->headers_size, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write PE headers: %m");

        if (w->data_end > w->headers_size) {
                r = copy_bytes_offset(w->fd, &(uint64_t) { w->headers_size }, output_fd, &(uint64_t) { w->headers_size },
                                  w->data_end - w->headers_size, /* copy_flags= */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy PE section data: %m");
                if (r == 0) /* copy_bytes_offset() returns 0 if the input file ends before data_end. */
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "PE file ended prematurely while copying section data.");
        }

        for (size_t i = 0; i < w->n_sections; i++) {
                const PeWriterReplacement *replacement = w->replacements + i;
                if (!replacement->set)
                        continue;

                r = pwrite_full(output_fd, replacement->raw.iov_base, replacement->raw.iov_len, le32toh(sections[i].PointerToRawData));
                if (r < 0)
                        return log_debug_errno(r, "Failed to write PE section data: %m");
        }

        for (size_t i = 0; i < w->n_new_sections; i++) {
                const PeWriterSection *s = w->new_sections[i];
                uint64_t offset = le32toh(new_sections[i].PointerToRawData);

                FOREACH_ARRAY(c, s->chunks, s->n_chunks) {
                        r = copy_bytes_offset(c->fd, &(uint64_t) { c->offset }, output_fd, &offset, c->size, /* copy_flags= */ 0);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to write PE section '%s': %m", s->name);
                        if (r == 0) /* copy_bytes_offset() returns 0 if the file ends before c->size bytes. */
                                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                                       "File for PE section '%s' ended prematurely.", s->name);
                }
        }

        if (ftruncate(output_fd, file_end) < 0)
                return log_debug_errno(errno, "Failed to extend output file: %m");

        return 0;
}

int pe_append_signature(int fd, const void *signature, size_t size) {
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        assert(fd >= 0);
        assert(signature || size == 0);

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat PE file: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_debug_errno(r, "PE file is not a regular file: %m");

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return r;

        const IMAGE_DATA_DIRECTORY *certificate_table =
                pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        if (!certificate_table)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE file lacks certificate table.");

        uint64_t end = st.st_size, padding = ALIGN_TO_U64(end, 8) - end, table_size = 0;
        bool is_signed = pe_header_is_signed(pe_header);
        if (is_signed) {
                /* The new certificate is appended at the end of the file. It only becomes part of the
                 * certificate table if the table ends there too. */
                if ((uint64_t) le32toh(certificate_table->VirtualAddress) + le32toh(certificate_table->Size) != end)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE certificate table does not end at the end of the file.");

                /* Each certificate in the certificate table starts at an 8 byte boundary. */
                if (padding > 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "PE certificate table is not aligned to 8 bytes.");

                table_size = le32toh(certificate_table->Size);
        }

        uint64_t certificate_size = sizeof(WIN_CERTIFICATE_HEADER) + (uint64_t) size,
                 write_size = padding + ALIGN_TO_U64(certificate_size, 8);
        table_size += ALIGN_TO_U64(certificate_size, 8);
        if (end + write_size > UINT32_MAX || table_size > UINT32_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "PE signature is too large.");

        _cleanup_free_ uint8_t *buf = new0(uint8_t, write_size);
        if (!buf)
                return log_oom_debug();

        WIN_CERTIFICATE_HEADER header = {
                .dwLength = htole32(certificate_size),
                .wRevision = htole16(0x200),
                .wCertificateType = htole16(0x0002), /* WIN_CERT_TYPE_PKCS_SIGNED_DATA */
        };
        memcpy(buf + padding, &header, sizeof(header));
        memcpy_safe(buf + padding + sizeof(header), signature, size);

        r = pwrite_full(fd, buf, write_size, end);
        if (r < 0)
                return log_debug_errno(r, "Failed to write signature: %m");

        IMAGE_DATA_DIRECTORY directory = {
                .VirtualAddress = is_signed ? certificate_table->VirtualAddress : htole32(end + padding),
                .Size = htole32(table_size),
        };

        r = pwrite_full(fd, &directory, sizeof(directory),
                        le32toh(dos_header->e_lfanew) + PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory[IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE]));
        if (r < 0)
                return log_debug_errno(r, "Failed to update PE certificate table: %m");

        uint32_t checksum;
        r = pe_checksum(fd, &checksum);
        if (r < 0)
                return log_debug_errno(r, "Failed to calculate PE file checksum: %m");

        le32_t checksum_le = htole32(checksum);
        r = pwrite_full(fd, &checksum_le, sizeof(checksum_le), le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional.CheckSum));
        if (r < 0)
                return log_debug_errno(r, "Failed to update PE checksum: %m");

        return 0;
}
