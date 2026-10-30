/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "pe-binary.h"
#include "pe-writer.h"
#include "string-util.h"
#include "tests.h"

#if HAVE_OPENSSL
#  include "authenticode.h"
#  include "crypto-util.h"
#endif

#define PE_OFFSET 0x40U
#define OPTIONAL_HEADER_SIZE 0xf0U
#define SECTION_TABLE_OFFSET (PE_OFFSET + offsetof(PeHeader, optional) + OPTIONAL_HEADER_SIZE)
#define FILE_ALIGNMENT 0x200U
#define SECTION_ALIGNMENT 0x1000U
#define STUB_SIZE 0x800U
#define STUB_DLL_CHARACTERISTICS UINT16_C(0x0160)

static const char stub_sbat[] = "sbat,1,stub\n";

/* Builds a PE32+ image with a .text section and a .sbat section, laid out like a systemd-stub built by
 * elf2efi. 'size' bytes are allocated, so callers can append data after the sections. */
static uint8_t* build_stub(size_t size, uint32_t size_of_headers) {
        ASSERT_GE(size, (size_t) STUB_SIZE);

        uint8_t *stub = ASSERT_NOT_NULL(new0(uint8_t, size));

        ((IMAGE_DOS_HEADER*) stub)->e_magic = htole16(0x5A4D);
        ((IMAGE_DOS_HEADER*) stub)->e_lfanew = htole32(PE_OFFSET);

        PeHeader *h = (PeHeader*) (stub + PE_OFFSET);
        h->signature = htole32(UINT32_C(0x00004550));
        h->pe.Machine = htole16(UINT16_C(0x8664));
        h->pe.NumberOfSections = htole16(2);
        h->pe.SizeOfOptionalHeader = htole16(OPTIONAL_HEADER_SIZE);
        h->pe.Characteristics = htole16(UINT16_C(0x0022));
        h->optional.Magic = htole16(UINT16_C(0x020B));
        h->optional.SizeOfInitializedData = htole32(0x400);
        h->optional.SectionAlignment = htole32(SECTION_ALIGNMENT);
        h->optional.FileAlignment = htole32(FILE_ALIGNMENT);
        h->optional.SizeOfImage = htole32(0x3000);
        h->optional.SizeOfHeaders = htole32(size_of_headers);
        h->optional.CheckSum = htole32(0x1234);
        h->optional.Subsystem = htole16(IMAGE_SUBSYSTEM_EFI_APPLICATION);
        h->optional.DllCharacteristics = htole16(STUB_DLL_CHARACTERISTICS);
        h->optional.pe32plus_NumberOfRvaAndSizes = htole32(16);

        IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER*) (stub + SECTION_TABLE_OFFSET);
        s[0] = (IMAGE_SECTION_HEADER) {
                .Name = ".text",
                .VirtualSize = htole32(0x180),
                .VirtualAddress = htole32(0x1000),
                .SizeOfRawData = htole32(0x200),
                .PointerToRawData = htole32(0x400),
                .Characteristics = htole32(IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ),
        };
        s[1] = (IMAGE_SECTION_HEADER) {
                .Name = ".sbat",
                .VirtualSize = htole32(strlen(stub_sbat)),
                .VirtualAddress = htole32(0x2000),
                .SizeOfRawData = htole32(0x200),
                .PointerToRawData = htole32(0x600),
                .Characteristics = htole32(IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ),
        };

        memset(stub + 0x400, 0xcc, 0x180);
        memcpy(stub + 0x600, stub_sbat, strlen(stub_sbat));

        return stub;
}

static void assert_section_data(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name,
                const void *data,
                size_t size) {

        _cleanup_free_ void *contents = NULL;
        size_t contents_size;

        ASSERT_OK(pe_read_section_data_by_name(fd, pe_header, sections, name, SIZE_MAX, &contents, &contents_size));
        ASSERT_EQ(contents_size, size);
        ASSERT_EQ(memcmp(contents, data, size), 0);
}

static void assert_zero(int fd, uint64_t offset, size_t size) {
        _cleanup_free_ uint8_t *buf = ASSERT_NOT_NULL(new(uint8_t, size));

        ASSERT_OK_EQ_ERRNO(pread(fd, buf, size, offset), (ssize_t) size);
        ASSERT_TRUE(memeqzero(buf, size));
}

TEST(add_sections) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        static const char cmdline[] = "console=ttyS0";
        _cleanup_close_ int cmdline_fd = ASSERT_OK(memfd_new_and_seal_string("cmdline", cmdline));
        PeWriterSection *s;
        ASSERT_OK(pe_writer_add_section(w, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &s));
        ASSERT_OK(pe_writer_section_append_fd(s, cmdline_fd, 0, strlen(cmdline)));

        /* The kernel is larger than a page, so the section after it starts two pages later. */
        size_t linux_size = 0x1234;
        _cleanup_free_ uint8_t *linux_data = ASSERT_NOT_NULL(new(uint8_t, linux_size + 16));
        for (size_t i = 0; i < linux_size + 16; i++)
                linux_data[i] = i & 0xff;
        _cleanup_close_ int linux_fd = ASSERT_OK(memfd_new_and_seal("linux", linux_data, linux_size + 16));

        ASSERT_OK(pe_writer_add_section(w, ".linux", IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ, &s));
        ASSERT_OK(pe_writer_section_append_fd(s, linux_fd, 16, linux_size));

        /* The section contains the data of two files. */
        _cleanup_close_ int initrd1_fd = ASSERT_OK(memfd_new_and_seal_string("initrd1", "abcde")),
                            initrd2_fd = ASSERT_OK(memfd_new_and_seal_string("initrd2", "fgh"));
        ASSERT_OK(pe_writer_add_section(w, ".initrd", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &s));
        ASSERT_OK(pe_writer_section_append_fd(s, initrd1_fd, 0, 5));
        ASSERT_OK(pe_writer_section_append_fd(s, initrd2_fd, 0, 3));

        /* Empty ranges add nothing. */
        ASSERT_OK(pe_writer_section_append_fd(s, linux_fd, 0, 0));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, &sections));

        ASSERT_EQ(le16toh(pe_header->pe.NumberOfSections), 5U);
        ASSERT_EQ(le32toh(pe_header->optional.CheckSum), 0U);
        ASSERT_EQ(le32toh(pe_header->optional.SizeOfHeaders), 0x400U);
        ASSERT_EQ(le16toh(pe_header->optional.DllCharacteristics), STUB_DLL_CHARACTERISTICS);
        ASSERT_EQ(le32toh(pe_header->optional.SizeOfInitializedData), 0x400U + strlen(cmdline) + linux_size + 8U);

        const IMAGE_SECTION_HEADER *cmdline_section = pe_header_find_section(pe_header, sections, ".cmdline");
        ASSERT_NOT_NULL(cmdline_section);
        ASSERT_EQ(le32toh(cmdline_section->VirtualAddress), 0x3000U);
        ASSERT_EQ(le32toh(cmdline_section->VirtualSize), strlen(cmdline));
        ASSERT_EQ(le32toh(cmdline_section->PointerToRawData), STUB_SIZE);
        ASSERT_EQ(le32toh(cmdline_section->SizeOfRawData), FILE_ALIGNMENT);
        ASSERT_EQ(le32toh(cmdline_section->Characteristics), IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ);

        const IMAGE_SECTION_HEADER *linux_section = pe_header_find_section(pe_header, sections, ".linux");
        ASSERT_NOT_NULL(linux_section);
        ASSERT_EQ(le32toh(linux_section->VirtualAddress), 0x4000U);
        ASSERT_EQ(le32toh(linux_section->PointerToRawData), STUB_SIZE + FILE_ALIGNMENT);
        ASSERT_EQ(le32toh(linux_section->SizeOfRawData), ALIGN_TO(linux_size, FILE_ALIGNMENT));
        ASSERT_EQ(le32toh(linux_section->Characteristics), IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ);

        const IMAGE_SECTION_HEADER *initrd_section = pe_header_find_section(pe_header, sections, ".initrd");
        ASSERT_NOT_NULL(initrd_section);
        ASSERT_EQ(le32toh(initrd_section->VirtualAddress), 0x6000U);
        ASSERT_EQ(le32toh(pe_header->optional.SizeOfImage), 0x7000U);

        assert_section_data(out, pe_header, sections, ".text", (const uint8_t[0x180]) { [0 ... 0x17f] = 0xcc }, 0x180);
        assert_section_data(out, pe_header, sections, ".sbat", stub_sbat, strlen(stub_sbat));
        assert_section_data(out, pe_header, sections, ".cmdline", cmdline, strlen(cmdline));
        assert_section_data(out, pe_header, sections, ".linux", linux_data + 16, linux_size);
        assert_section_data(out, pe_header, sections, ".initrd", "abcdefgh", 8);

        uint64_t end = le32toh(initrd_section->PointerToRawData) + le32toh(initrd_section->SizeOfRawData);
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) end);
        assert_zero(out, le32toh(initrd_section->PointerToRawData) + 8, FILE_ALIGNMENT - 8);

        /* Writing twice gives the same result, even if the output file contains data already. The padding
         * must not contain the old data. */
        _cleanup_close_ int out2 = ASSERT_OK(memfd_new("output"));
        _cleanup_free_ uint8_t *old = ASSERT_NOT_NULL(new(uint8_t, end));
        memset(old, 0xff, end);
        ASSERT_OK_EQ_ERRNO(pwrite(out2, old, end, 0), (ssize_t) end);
        ASSERT_OK(pe_writer_write(w, out2));
        ASSERT_OK_EQ_ERRNO(lseek(out2, 0, SEEK_END), (off_t) end);
        _cleanup_free_ uint8_t *first = ASSERT_NOT_NULL(new(uint8_t, end));
        _cleanup_free_ uint8_t *second = ASSERT_NOT_NULL(new(uint8_t, end));
        ASSERT_OK_EQ_ERRNO(pread(out, first, end, 0), (ssize_t) end);
        ASSERT_OK_EQ_ERRNO(pread(out2, second, end, 0), (ssize_t) end);
        ASSERT_EQ(memcmp(first, second, end), 0);
}

TEST(find_and_replace_section) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));
        size_t index;

        ASSERT_OK(pe_writer_find_section(w, ".text", 0, &index));
        ASSERT_EQ(index, 0U);
        ASSERT_ERROR(pe_writer_find_section(w, ".text", 1, &index), ENXIO);
        ASSERT_OK(pe_writer_find_section(w, ".sbat", 1, &index));
        ASSERT_EQ(index, 1U);
        ASSERT_OK(pe_writer_find_section(w, ".sbat", 0, &index));
        ASSERT_EQ(index, 1U);
        ASSERT_ERROR(pe_writer_find_section(w, ".sbat", 2, &index), ENXIO);
        ASSERT_ERROR(pe_writer_find_section(w, ".linux", 0, &index), ENXIO);

        _cleanup_free_ char *too_large = ASSERT_NOT_NULL(strrep("x", FILE_ALIGNMENT + 1));
        ASSERT_ERROR(pe_writer_replace_section(w, index, &IOVEC_MAKE_STRING(too_large)), ENOSPC);

        static const char sbat[] = "sbat,1,stub\nlinux,1,kernel\n";
        ASSERT_OK(pe_writer_replace_section(w, index, &IOVEC_MAKE_STRING(sbat)));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, &sections));

        ASSERT_EQ(le16toh(pe_header->pe.NumberOfSections), 2U);
        assert_section_data(out, pe_header, sections, ".sbat", sbat, strlen(sbat));
        assert_zero(out, 0x600 + strlen(sbat), FILE_ALIGNMENT - strlen(sbat));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) STUB_SIZE);
}

TEST(replace_section_memory_overlap) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER*) (stub + SECTION_TABLE_OFFSET);

        /* Map .sbat 0x100 bytes after .text. .text has 0x200 bytes of raw data, but growing it beyond 0x100
         * bytes maps it over .sbat. */
        s[0].VirtualSize = htole32(0x80);
        s[1].VirtualAddress = htole32(0x1100);

        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        ASSERT_OK(pe_writer_replace_section(w, 0, &IOVEC_MAKE((uint8_t[0x100]) {}, 0x100)));
        ASSERT_ERROR(pe_writer_replace_section(w, 0, &IOVEC_MAKE((uint8_t[0x101]) {}, 0x101)), ENOSPC);
}

TEST(header_space) {
        /* SizeOfHeaders ends right after the section table. Rounding it up to the file alignment adds room
         * for more section headers. */
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, SECTION_TABLE_OFFSET + 2 * sizeof(IMAGE_SECTION_HEADER));
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        size_t free_slots = (FILE_ALIGNMENT - SECTION_TABLE_OFFSET) / sizeof(IMAGE_SECTION_HEADER) - 2;
        ASSERT_GT(free_slots, 0U);
        for (size_t i = 0; i < free_slots; i++)
                ASSERT_OK(pe_writer_add_section(w, ".data", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, NULL));

        /* pe_writer_add_section() refuses a section that does not fit in the headers. The sections that
         * were added before are still written. */
        ASSERT_ERROR(pe_writer_add_section(w, ".data", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, NULL), E2BIG);

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, &sections));
        ASSERT_EQ(le16toh(pe_header->pe.NumberOfSections), 2 + free_slots);
        ASSERT_EQ(le32toh(pe_header->optional.SizeOfHeaders), FILE_ALIGNMENT);
}

TEST(header_space_not_empty) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        stub[SECTION_TABLE_OFFSET + 2 * sizeof(IMAGE_SECTION_HEADER)] = 'x';

        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));
        ASSERT_ERROR(pe_writer_add_section(w, ".data", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, NULL), EOPNOTSUPP);
}

TEST(section_names) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        ASSERT_ERROR(pe_writer_add_section(w, ".12345678", 0, NULL), EINVAL);
        ASSERT_ERROR(pe_writer_add_section(w, "", 0, NULL), EINVAL);
        ASSERT_ERROR(pe_writer_add_section(w, ".a\tb", 0, NULL), EINVAL);
        ASSERT_ERROR(pe_writer_add_section(w, ".\xc3\xa4", 0, NULL), EINVAL);
        ASSERT_OK(pe_writer_add_section(w, ".1234567", 0, NULL));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, &sections));
        ASSERT_NOT_NULL(pe_header_find_section(pe_header, sections, ".1234567"));
}

TEST(append_fd_out_of_range) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));
        PeWriterSection *s;

        ASSERT_OK(pe_writer_add_section(w, ".linux", 0, &s));
        ASSERT_ERROR(pe_writer_section_append_fd(s, fd, STUB_SIZE - 1, 2), ERANGE);
        ASSERT_ERROR(pe_writer_section_append_fd(s, fd, UINT64_MAX, 2), ERANGE);
        ASSERT_OK(pe_writer_section_append_fd(s, fd, STUB_SIZE - 1, 1));
}

TEST(dll_characteristics) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        pe_writer_clear_dll_characteristics(w, IMAGE_DLLCHARACTERISTICS_NX_COMPAT);

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, /* ret_sections= */ NULL));
        ASSERT_EQ(le16toh(pe_header->optional.DllCharacteristics),
                  (uint16_t) (STUB_DLL_CHARACTERISTICS & ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT));
}

TEST(misaligned_section) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        ((IMAGE_SECTION_HEADER*) (stub + SECTION_TABLE_OFFSET))[1].SizeOfRawData = htole32(0x100);

        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_ERROR(pe_writer_new(fd, &w), EOPNOTSUPP);
}

TEST(trailing_data) {
        /* ukify keeps data after the sections and places new sections after it. */
        size_t size = STUB_SIZE + 0x10;
        _cleanup_free_ uint8_t *stub = build_stub(size, 0x400);
        memset(stub + STUB_SIZE, 'x', 0x10);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, size));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) size);

        _cleanup_close_ int cmdline_fd = ASSERT_OK(memfd_new_and_seal_string("cmdline", "quiet"));
        PeWriterSection *s;
        ASSERT_OK(pe_writer_add_section(w, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &s));
        ASSERT_OK(pe_writer_section_append_fd(s, cmdline_fd, 0, 5));
        _cleanup_close_ int out2 = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out2));
        ASSERT_OK_EQ_ERRNO(lseek(out2, 0, SEEK_END), (off_t) (STUB_SIZE + 2 * FILE_ALIGNMENT));

        uint8_t trailing[0x10];
        ASSERT_OK_EQ_ERRNO(pread(out2, trailing, sizeof(trailing), STUB_SIZE), (ssize_t) sizeof(trailing));
        ASSERT_EQ(memcmp(trailing, stub + STUB_SIZE, sizeof(trailing)), 0);
        assert_zero(out2, size, STUB_SIZE + FILE_ALIGNMENT - size);

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out2, &pe_header, &sections));
        ASSERT_EQ(le32toh(sections[2].PointerToRawData), STUB_SIZE + FILE_ALIGNMENT);
}

TEST(short_file) {
        /* The file ends after the section table, before the end of the headers that SizeOfHeaders
         * declares. New sections must not be placed inside the headers. */
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x300);
        IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER*) (stub + SECTION_TABLE_OFFSET);
        s[0].SizeOfRawData = s[0].PointerToRawData = 0;
        s[1].SizeOfRawData = s[1].PointerToRawData = 0;

        size_t size = SECTION_TABLE_OFFSET + 2 * sizeof(IMAGE_SECTION_HEADER);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, size));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        _cleanup_close_ int cmdline_fd = ASSERT_OK(memfd_new_and_seal_string("cmdline", "quiet"));
        PeWriterSection *ws;
        ASSERT_OK(pe_writer_add_section(w, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &ws));
        ASSERT_OK(pe_writer_section_append_fd(ws, cmdline_fd, 0, 5));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) (0x400 + FILE_ALIGNMENT));

        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, &sections));
        ASSERT_EQ(le32toh(sections[2].PointerToRawData), 0x400U);
        assert_section_data(out, pe_header, sections, ".cmdline", "quiet", 5);
}

TEST(output_is_input) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("stub"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, stub, STUB_SIZE, 0), (ssize_t) STUB_SIZE);
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        _cleanup_close_ int cmdline_fd = ASSERT_OK(memfd_new("cmdline"));
        ASSERT_OK_EQ_ERRNO(pwrite(cmdline_fd, "quiet", 5, 0), (ssize_t) 5);
        PeWriterSection *s;
        ASSERT_OK(pe_writer_add_section(w, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &s));
        ASSERT_OK(pe_writer_section_append_fd(s, cmdline_fd, 0, 5));

        /* Truncating the output would delete the input data before pe_writer_write() copies it. */
        ASSERT_ERROR(pe_writer_write(w, fd), EINVAL);
        ASSERT_ERROR(pe_writer_write(w, cmdline_fd), EINVAL);
        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_END), (off_t) STUB_SIZE);
        ASSERT_OK_EQ_ERRNO(lseek(cmdline_fd, 0, SEEK_END), (off_t) 5);
}

/* The stub is followed by a COFF symbol table with two symbols, a string table, and 'extra' more bytes. */
static uint8_t* build_stub_with_symbols(size_t extra, size_t *ret_size) {
        size_t symbols_size = 2 * 18, size = STUB_SIZE + symbols_size + 8 + extra;
        uint8_t *stub = build_stub(size, 0x400);

        PeHeader *h = (PeHeader*) (stub + PE_OFFSET);
        h->pe.PointerToSymbolTable = htole32(STUB_SIZE);
        h->pe.NumberOfSymbols = htole32(2);
        memset(stub + STUB_SIZE, 'x', symbols_size);
        /* The string table size includes its own 4 byte size field. */
        stub[STUB_SIZE + symbols_size] = 8;
        memcpy(stub + STUB_SIZE + symbols_size + 4, "abc", 4);

        *ret_size = size;
        return stub;
}

TEST(symbol_table_trailing_data) {
        /* The symbol table is only stripped if it is at the end of the file. */
        size_t size;
        _cleanup_free_ uint8_t *stub = build_stub_with_symbols(1, &size);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, size));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) size);

        _cleanup_free_ uint8_t *data = ASSERT_NOT_NULL(new(uint8_t, size - STUB_SIZE));
        ASSERT_OK_EQ_ERRNO(pread(out, data, size - STUB_SIZE, STUB_SIZE), (ssize_t) (size - STUB_SIZE));
        ASSERT_EQ(memcmp(data, stub + STUB_SIZE, size - STUB_SIZE), 0);

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, /* ret_sections= */ NULL));
        ASSERT_EQ(le32toh(pe_header->pe.PointerToSymbolTable), STUB_SIZE);
        ASSERT_EQ(le32toh(pe_header->pe.NumberOfSymbols), 2U);
        ASSERT_EQ(le16toh(pe_header->pe.Characteristics), UINT16_C(0x0022));
}

TEST(symbol_table_certificate_table) {
        /* PointerToSymbolTable points at the certificate table, and NumberOfSymbols is zero. The writer
         * reads the certificate's dwLength as the string table size. The string table then ends at the end
         * of the file, but the certificate table must be kept. */
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        ((PeHeader*) (stub + PE_OFFSET))->pe.PointerToSymbolTable = htole32(STUB_SIZE);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("stub"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, stub, STUB_SIZE, 0), (ssize_t) STUB_SIZE);

        static const uint8_t signature[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        ASSERT_OK(pe_append_signature(fd, signature, sizeof(signature)));

        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));
        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) (STUB_SIZE + 16));

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, /* ret_sections= */ NULL));
        ASSERT_EQ(le32toh(pe_header->pe.PointerToSymbolTable), STUB_SIZE);
}

TEST(symbol_table) {
        size_t size;
        _cleanup_free_ uint8_t *stub = build_stub_with_symbols(0, &size);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, size));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) STUB_SIZE);

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, /* ret_sections= */ NULL));
        ASSERT_EQ(le32toh(pe_header->pe.PointerToSymbolTable), 0U);
        ASSERT_EQ(le32toh(pe_header->pe.NumberOfSymbols), 0U);
        ASSERT_TRUE(FLAGS_SET(le16toh(pe_header->pe.Characteristics), IMAGE_FILE_LOCAL_SYMS_STRIPPED));
}

TEST(signature) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new_and_seal("stub", stub, STUB_SIZE));
        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        ASSERT_OK(pe_writer_new(fd, &w));

        ASSERT_OK(pe_writer_add_section(w, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, NULL));
        _cleanup_close_ int out = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w, out));
        uint64_t unsigned_size = ASSERT_OK_ERRNO(lseek(out, 0, SEEK_END));

        /* Signatures are appended at 8 byte boundaries, so use a size that needs padding. */
        static const uint8_t signature[] = { 1, 2, 3, 4, 5 };
        ASSERT_OK(pe_append_signature(out, signature, sizeof(signature)));
        ASSERT_OK(pe_append_signature(out, signature, sizeof(signature)));

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out, &pe_header, /* ret_sections= */ NULL));
        ASSERT_TRUE(pe_header_is_signed(pe_header));

        const IMAGE_DATA_DIRECTORY *certificate_table =
                pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        ASSERT_EQ(le32toh(certificate_table->VirtualAddress), unsigned_size);
        ASSERT_EQ(le32toh(certificate_table->Size), 2U * 16U);
        ASSERT_OK_EQ_ERRNO(lseek(out, 0, SEEK_END), (off_t) (unsigned_size + 2U * 16U));

        /* Each certificate contains the WIN_CERTIFICATE header (dwLength 13, wRevision 0x200, wCertificateType
         * 2), the signature, and 3 bytes of padding. */
        static const uint8_t certificate[16] = { 13, 0, 0, 0, 0x00, 0x02, 0x02, 0x00, 1, 2, 3, 4, 5, 0, 0, 0 };
        uint8_t certificates[2 * sizeof(certificate)];
        ASSERT_OK_EQ_ERRNO(pread(out, certificates, sizeof(certificates), unsigned_size), (ssize_t) sizeof(certificates));
        ASSERT_EQ(memcmp(certificates, certificate, sizeof(certificate)), 0);
        ASSERT_EQ(memcmp(certificates + sizeof(certificate), certificate, sizeof(certificate)), 0);

        uint32_t checksum;
        ASSERT_OK(pe_checksum(out, &checksum));
        ASSERT_EQ(le32toh(pe_header->optional.CheckSum), checksum);

        /* ukify keeps the signature of a signed image when it replaces a section, so the writer does
         * too. */
        _cleanup_(pe_writer_freep) PeWriter *w2 = NULL;
        ASSERT_OK(pe_writer_new(out, &w2));
        size_t index;
        ASSERT_OK(pe_writer_find_section(w2, ".sbat", 0, &index));
        ASSERT_OK(pe_writer_replace_section(w2, index, &IOVEC_MAKE_STRING("sbat,1,new\n")));

        _cleanup_close_ int out2 = ASSERT_OK(memfd_new("output"));
        ASSERT_OK(pe_writer_write(w2, out2));
        ASSERT_OK_EQ_ERRNO(lseek(out2, 0, SEEK_END), (off_t) (unsigned_size + 2U * 16U));

        _cleanup_free_ PeHeader *pe_header2 = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections2 = NULL;
        ASSERT_OK(pe_load_headers_and_sections(out2, &pe_header2, &sections2));
        ASSERT_TRUE(pe_header_is_signed(pe_header2));
        ASSERT_EQ(le32toh(pe_header2->optional.CheckSum), 0U);
        assert_section_data(out2, pe_header2, sections2, ".sbat", "sbat,1,new\n", strlen("sbat,1,new\n"));
        /* The new data is shorter than the old data, so check that none of the old data is left. */
        assert_zero(out2, 0x600 + strlen("sbat,1,new\n"), FILE_ALIGNMENT - strlen("sbat,1,new\n"));

        /* New sections cannot go after the certificate table. */
        ASSERT_ERROR(pe_writer_add_section(w2, ".cmdline", IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, NULL), EOPNOTSUPP);
}

TEST(signature_malformed_certificate_table) {
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("stub"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, stub, STUB_SIZE, 0), (ssize_t) STUB_SIZE);

        static const uint8_t signature[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        ASSERT_OK(pe_append_signature(fd, signature, sizeof(signature)));

        /* The file contains data after the certificate table. */
        ASSERT_OK_EQ_ERRNO(pwrite(fd, (const uint8_t[8]) {}, 8, STUB_SIZE + 16), (ssize_t) 8);
        ASSERT_ERROR(pe_append_signature(fd, signature, sizeof(signature)), EBADMSG);

        /* The certificate table ends at the end of the file, but its end is not aligned to 8 bytes. */
        ASSERT_OK_ERRNO(ftruncate(fd, STUB_SIZE + 16 + 3));
        le32_t size = htole32(16 + 3);
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &size, sizeof(size),
                                  PE_OFFSET + offsetof(PeHeader, optional.pe32plus_DataDirectory[IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE].Size)),
                           (ssize_t) sizeof(size));
        ASSERT_ERROR(pe_append_signature(fd, signature, sizeof(signature)), EBADMSG);
}

TEST(signature_unaligned_input) {
        /* An unsigned image whose size is not a multiple of 8 is padded before the signature. */
        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE + 3, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("stub"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, stub, STUB_SIZE + 3, 0), (ssize_t) STUB_SIZE + 3);

        static const uint8_t signature[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        ASSERT_OK(pe_append_signature(fd, signature, sizeof(signature)));

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(fd, &pe_header, /* ret_sections= */ NULL));

        const IMAGE_DATA_DIRECTORY *certificate_table =
                pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        ASSERT_EQ(le32toh(certificate_table->VirtualAddress), (uint32_t) STUB_SIZE + 8);
        ASSERT_EQ(le32toh(certificate_table->Size), 16U);
        assert_zero(fd, STUB_SIZE + 3, 5);
}

#if HAVE_OPENSSL
TEST(authenticode_sign_pe) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *key = NULL;
        _cleanup_(X509_freep) X509 *cert = NULL;

        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return (void) log_tests_skipped("libcrypto not available");

        ASSERT_OK(rsa_pkey_new(2048, &key));
        ASSERT_OK(x509_new_self_signed(key, "systemd test", 30, &cert));

        _cleanup_free_ uint8_t *stub = build_stub(STUB_SIZE, 0x400);
        _cleanup_close_ int fd = ASSERT_OK(memfd_new("stub"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, stub, STUB_SIZE, 0), (ssize_t) STUB_SIZE);
        uint64_t unsigned_size = ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_END));

        _cleanup_free_ void *hash = NULL, *signed_hash = NULL;
        size_t hash_size, signed_hash_size;
        ASSERT_OK(pe_hash(fd, sym_EVP_sha256(), &hash, &hash_size));

        ASSERT_OK(authenticode_sign_pe(fd, cert, key));

        _cleanup_free_ PeHeader *pe_header = NULL;
        ASSERT_OK(pe_load_headers_and_sections(fd, &pe_header, /* ret_sections= */ NULL));
        ASSERT_TRUE(pe_header_is_signed(pe_header));

        const IMAGE_DATA_DIRECTORY *certificate_table =
                pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        ASSERT_EQ(le32toh(certificate_table->VirtualAddress), unsigned_size);
        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_END), (off_t) (unsigned_size + le32toh(certificate_table->Size)));

        uint32_t checksum;
        ASSERT_OK(pe_checksum(fd, &checksum));
        ASSERT_EQ(le32toh(pe_header->optional.CheckSum), checksum);

        /* The Authenticode hash does not cover the certificate table, so signing does not change it. */
        ASSERT_OK(pe_hash(fd, sym_EVP_sha256(), &signed_hash, &signed_hash_size));
        ASSERT_EQ(memcmp_nn(signed_hash, signed_hash_size, hash, hash_size), 0);
}
#endif

DEFINE_TEST_MAIN(LOG_DEBUG);
