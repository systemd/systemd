/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe.h"
#include "util.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"
#define MAX_SECTIONS 96

#if defined(__i386__)
#  define TARGET_MACHINE_TYPE 0x014CU
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0x8664U
#elif defined(__x86_64__)
#  define TARGET_MACHINE_TYPE 0x8664U
#elif defined(__aarch64__)
#  define TARGET_MACHINE_TYPE 0xAA64U
#elif defined(__arm__)
#  define TARGET_MACHINE_TYPE 0x01C2U
#elif defined(__riscv) && __riscv_xlen == 32
#  define TARGET_MACHINE_TYPE 0x5032U
#elif defined(__riscv) && __riscv_xlen == 64
#  define TARGET_MACHINE_TYPE 0x5064U
#elif defined(__loongarch__) && __loongarch_grlen == 32
#  define TARGET_MACHINE_TYPE 0x6232U
#elif defined(__loongarch__) && __loongarch_grlen == 64
#  define TARGET_MACHINE_TYPE 0x6264U
#else
#  error Unknown EFI arch
#endif

#ifndef TARGET_MACHINE_TYPE_COMPATIBILITY
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0
#endif

typedef struct DosFileHeader {
        uint8_t  Magic[2];
        uint16_t LastSize;
        uint16_t nBlocks;
        uint16_t nReloc;
        uint16_t HdrSize;
        uint16_t MinAlloc;
        uint16_t MaxAlloc;
        uint16_t ss;
        uint16_t sp;
        uint16_t Checksum;
        uint16_t ip;
        uint16_t cs;
        uint16_t RelocPos;
        uint16_t nOverlay;
        uint16_t reserved[4];
        uint16_t OEMId;
        uint16_t OEMInfo;
        uint16_t reserved2[10];
        uint32_t ExeHeader;
} _packed_ DosFileHeader;

typedef struct CoffFileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
} _packed_ CoffFileHeader;

#define OPTHDR32_MAGIC 0x10B /* PE32  OptionalHeader */
#define OPTHDR64_MAGIC 0x20B /* PE32+ OptionalHeader */

typedef struct PeOptionalHeader {
        uint16_t Magic;
        uint8_t  LinkerMajor;
        uint8_t  LinkerMinor;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializeData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        union {
                struct { /* PE32 */
                        uint32_t BaseOfData;
                        uint32_t ImageBase32;
                };
                uint64_t ImageBase64; /* PE32+ */
        };
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        /* fields with different sizes for 32/64 omitted */
} _packed_ PeOptionalHeader;

typedef struct PeFileHeader {
        uint8_t  Magic[4];
        CoffFileHeader FileHeader;
        PeOptionalHeader OptionalHeader;
} _packed_ PeFileHeader;

typedef struct PeSectionHeader {
        uint8_t  Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
} _packed_ PeSectionHeader;

#define SECTION_TABLE_BYTES_MAX (16U * 1024U * 1024U)

static bool verify_dos(const DosFileHeader *dos) {
        assert(dos);

        DISABLE_WARNING_TYPE_LIMITS;
        return memcmp(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0 &&
                dos->ExeHeader >= sizeof(DosFileHeader) &&
                (size_t) dos->ExeHeader <= SIZE_MAX - sizeof(PeFileHeader);
        REENABLE_WARNING;
}

static bool verify_pe(
                const DosFileHeader *dos,
                const PeFileHeader *pe,
                bool allow_compatibility) {

        assert(dos);
        assert(pe);

        return memcmp(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) == 0 &&
                (pe->FileHeader.Machine == TARGET_MACHINE_TYPE ||
                 (allow_compatibility && pe->FileHeader.Machine == TARGET_MACHINE_TYPE_COMPATIBILITY)) &&
                pe->FileHeader.NumberOfSections > 0 &&
                pe->FileHeader.NumberOfSections <= MAX_SECTIONS &&
                IN_SET(pe->OptionalHeader.Magic, OPTHDR32_MAGIC, OPTHDR64_MAGIC) &&
                pe->FileHeader.SizeOfOptionalHeader < SIZE_MAX - (dos->ExeHeader + offsetof(PeFileHeader, OptionalHeader));
}

static size_t section_table_offset(const DosFileHeader *dos, const PeFileHeader *pe) {
        assert(dos);
        assert(pe);

        return dos->ExeHeader + offsetof(PeFileHeader, OptionalHeader) + pe->FileHeader.SizeOfOptionalHeader;
}

static bool pe_section_name_equal(const char *a, const char *b) {

        if (a == b)
                return true;
        if (!a != !b)
                return false;

        /* Compares up to 8 characters of a and b i.e. the name size limit in the PE section header */

        for (size_t i = 0; i < sizeof_field(PeSectionHeader, Name); i++) {
                if (a[i] != b[i])
                        return false;

                if (a[i] == 0) /* Name is shorter than 8 */
                        return true;
        }

        return true;
}

static void pe_locate_sections(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                PeSectionVector sections[]) {

        assert(section_table || n_section_table == 0);
        assert(section_names);
        assert(sections);

        /* Searches for the sections listed in 'sections[]' within the section table. Validates the resulted
         * data. If 'validate_base' is non-zero also takes base offset when loaded into memory into account for
         * qchecking for overflows. */

        for (size_t i = 0; section_names[i]; i++)
                FOREACH_ARRAY(j, section_table, n_section_table) {

                        if (!pe_section_name_equal((const char*) j->Name, section_names[i]))
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, relative to the file
                         * address for the section. */
                        size_t size_max = SIZE_MAX - j->PointerToRawData;
                        if ((size_t) j->VirtualSize > size_max)
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, given the virtual
                         * address for the section */
                        size_max = SIZE_MAX - j->VirtualAddress;
                        if (j->VirtualSize > size_max)
                                continue;

                        /* 2nd overflow check: ignore sections that are impossibly large also taking the
                         * loaded base into account. */
                        if (validate_base != 0) {
                                if (validate_base > size_max)
                                        continue;
                                size_max -= validate_base;

                                if (j->VirtualAddress > size_max)
                                        continue;
                        }

                        /* At this time, the sizes and offsets have been validated. Store them away */
                        sections[i] = (PeSectionVector) {
                                .size = j->VirtualSize,
                                .file_offset = j->PointerToRawData,
                                .memory_offset = j->VirtualAddress,
                        };

                        /* First matching section wins, ignore the rest */
                        break;
                }
}

static uint32_t get_compatibility_entry_address(const DosFileHeader *dos, const PeFileHeader *pe) {
        /* The kernel may provide alternative PE entry points for different PE architectures. This allows
         * booting a 64-bit kernel on 32-bit EFI that is otherwise running on a 64-bit CPU. The locations of any
         * such compat entry points are located in a special PE section. */

        assert(dos);
        assert(pe);

        static const char *const section_names[] = { ".compat", NULL };
        PeSectionVector vector = {};
        pe_locate_sections(
                        (const PeSectionHeader *) ((const uint8_t *) dos + section_table_offset(dos, pe)),
                        pe->FileHeader.NumberOfSections,
                        section_names,
                        PTR_TO_SIZE(dos),
                        &vector);

        if (vector.size == 0) /* not found */
                return 0;

        typedef struct {
                uint8_t type;
                uint8_t size;
                uint16_t machine_type;
                uint32_t entry_point;
        } _packed_ LinuxPeCompat1;

        size_t addr = vector.memory_offset, size = vector.size;

        while (size >= sizeof(LinuxPeCompat1) && addr % alignof(LinuxPeCompat1) == 0) {
                const LinuxPeCompat1 *compat = (const LinuxPeCompat1 *) ((const uint8_t *) dos + addr);

                if (compat->type == 0 || compat->size == 0 || compat->size > size)
                        break;

                if (compat->type == 1 &&
                    compat->size >= sizeof(LinuxPeCompat1) &&
                    compat->machine_type == TARGET_MACHINE_TYPE)
                        return compat->entry_point;

                addr += compat->size;
                size -= compat->size;
        }

        return 0;
}

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_compat_address, size_t *ret_size_in_memory) {
        assert(base);
        assert(ret_compat_address);

        const DosFileHeader *dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        /* When allocating we need to also consider the virtual/uninitialized data sections, so parse it out
         * of the SizeOfImage field in the PE header and return it */
        if (ret_size_in_memory)
                *ret_size_in_memory = pe->OptionalHeader.SizeOfImage;

        /* Support for LINUX_INITRD_MEDIA_GUID was added in kernel stub 1.0. */
        if (pe->OptionalHeader.MajorImageVersion < 1)
                return EFI_UNSUPPORTED;

        if (pe->FileHeader.Machine == TARGET_MACHINE_TYPE) {
                *ret_compat_address = 0;
                return EFI_SUCCESS;
        }

        uint32_t compat_address = get_compatibility_entry_address(dos, pe);
        if (compat_address == 0)
                /* Image type not supported and no compat entry found. */
                return EFI_UNSUPPORTED;

        *ret_compat_address = compat_address;
        return EFI_SUCCESS;
}

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char *const section_names[],
                PeSectionVector sections[]) {

        const DosFileHeader *dos;
        const PeFileHeader *pe;
        size_t offset;

        assert(base);
        assert(section_names);
        assert(sections);

        dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        offset = section_table_offset(dos, pe);
        pe_locate_sections(
                        (const PeSectionHeader *) ((const uint8_t *) base + offset),
                        pe->FileHeader.NumberOfSections,
                        section_names,
                        PTR_TO_SIZE(base),
                        sections);

        return EFI_SUCCESS;
}

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const char16_t *path,
                const char *const section_names[],
                PeSectionVector sections[]) {
        _cleanup_free_ PeSectionHeader *section_table = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        DosFileHeader dos;
        PeFileHeader pe;
        size_t len, section_table_len;
        EFI_STATUS err;

        assert(dir);
        assert(path);
        assert(section_names);
        assert(sections);

        err = dir->Open(dir, &handle, (char16_t *) path, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return err;

        len = sizeof(dos);
        err = handle->Read(handle, &len, &dos);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = handle->SetPosition(handle, dos.ExeHeader);
        if (err != EFI_SUCCESS)
                return err;

        len = sizeof(pe);
        err = handle->Read(handle, &len, &pe);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(pe) || !verify_pe(&dos, &pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        DISABLE_WARNING_TYPE_LIMITS;
        if ((size_t) pe.FileHeader.NumberOfSections > SIZE_MAX / sizeof(PeSectionHeader))
                return EFI_OUT_OF_RESOURCES;
        REENABLE_WARNING;
        section_table_len = (size_t) pe.FileHeader.NumberOfSections * sizeof(PeSectionHeader);
        if (section_table_len > SECTION_TABLE_BYTES_MAX)
                return EFI_OUT_OF_RESOURCES;
        section_table = xmalloc(section_table_len);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = handle->SetPosition(handle, section_table_offset(&dos, &pe));
        if (err != EFI_SUCCESS)
                return err;

        len = section_table_len;
        err = handle->Read(handle, &len, section_table);
        if (err != EFI_SUCCESS)
                return err;
        if (len != section_table_len)
                return EFI_LOAD_ERROR;

        pe_locate_sections(
                        section_table,
                        pe.FileHeader.NumberOfSections,
                        section_names,
                        /* validate_base= */ 0, /* don't validate base */
                        sections);

        return EFI_SUCCESS;
}
