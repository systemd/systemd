/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chid.h"
#include "devicetree.h"
#include "efi-firmware.h"
#include "efi-log.h"
#include "pe.h"
#include "util.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100U

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

typedef struct PeImageDataDirectory {
        uint32_t VirtualAddress;
        uint32_t Size;
} _packed_ PeImageDataDirectory;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

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
        union {
                struct {
                        uint64_t SizeOfStackReserve64;
                        uint64_t SizeOfStackCommit64;
                        uint64_t SizeOfHeapReserve64;
                        uint64_t SizeOfHeapCommit64;
                        uint32_t LoaderFlags64;
                        uint32_t NumberOfRvaAndSizes64;

                        PeImageDataDirectory DataDirectory64[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                };
                struct {
                        uint32_t SizeOfStackReserve32;
                        uint32_t SizeOfStackCommit32;
                        uint32_t SizeOfHeapReserve32;
                        uint32_t SizeOfHeapCommit32;
                        uint32_t LoaderFlags32;
                        uint32_t NumberOfRvaAndSizes32;

                        PeImageDataDirectory DataDirectory32[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                };
        };
} _packed_ PeOptionalHeader;

typedef struct PeFileHeader {
        uint8_t  Magic[4];
        CoffFileHeader FileHeader;
        PeOptionalHeader OptionalHeader;
} _packed_ PeFileHeader;

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

static bool pe_use_this_dtb(
                const void *dtb,
                size_t dtb_size,
                const void *base,
                const Device *device,
                size_t section_nb) {

        assert(dtb);

        EFI_STATUS err;

        err = devicetree_match(dtb, dtb_size);
        if (err == EFI_SUCCESS)
                return true;
        if (err != EFI_UNSUPPORTED)
                return false;

        /* There's nothing to match against if firmware does not provide DTB and there is no .hwids section */
        if (!device || !base)
                return false;

        const char *compatible = device_get_compatible(base, device);
        if (!compatible)
                return false;

        err = devicetree_match_by_compatible(dtb, dtb_size, compatible);
        if (err == EFI_SUCCESS)
                return true;
        if (err == EFI_INVALID_PARAMETER)
                log_error_status(err, "Found bad DT blob in PE section %zu", section_nb);
        return false;
}

static bool pe_use_this_firmware(
                const void *efifw,
                size_t efifw_size,
                const void *base,
                const Device *device,
                size_t section_nb) {

        assert(efifw);

        EFI_STATUS err;

        /* if there is no hwids section, there is nothing much we can do */
        if (!device || !base)
                return false;

        const char *fwid = device_get_fwid(base, device);
        if (!fwid)
                return false;

        err = efi_firmware_match_by_fwid(efifw, efifw_size, fwid);
        if (err == EFI_SUCCESS)
                return true;
        if (err == EFI_INVALID_PARAMETER)
                log_error_status(err, "Found bad efifw blob in PE section %zu", section_nb);
        return false;
}

static void pe_locate_sections_internal(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                const void *device_table,
                const Device *device,
                PeSectionVector sections[]) {

        assert(section_table || n_section_table == 0);
        assert(section_names);
        assert(sections);

        /* Searches for the sections listed in 'sections[]' within the section table. Validates the resulted
         * data. If 'validate_base' is non-zero also takes base offset when loaded into memory into account for
         * checking for overflows. */

        for (size_t i = 0; section_names[i]; i++)
                FOREACH_ARRAY(j, section_table, n_section_table) {

                        if (!pe_section_name_equal((const char*) j->Name, section_names[i]))
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, relative to the file
                         * address for the section. */
                        size_t size_max = SIZE_MAX - j->PointerToRawData;
                        if ((size_t) j->SizeOfRawData > size_max)
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, given the virtual
                         * address for the section */
                        size_max = SIZE_MAX - j->VirtualAddress;
                        if ((size_t) j->VirtualSize > size_max)
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

                        /* Special handling for .dtbauto sections compared to plain .dtb */
                        if (pe_section_name_equal(section_names[i], ".dtbauto")) {
                                /* .dtbauto sections require validate_base for matching */
                                if (!validate_base)
                                        break;
                                if (!pe_use_this_dtb(
                                                  (const uint8_t *) SIZE_TO_PTR(validate_base) + j->VirtualAddress,
                                                  j->VirtualSize,
                                                  device_table,
                                                  device,
                                                  (PTR_TO_SIZE(j) - PTR_TO_SIZE(section_table)) / sizeof(*j)))
                                        continue;
                        }

                        /* handle efifw section which works very much like .dtbauto */
                        if (pe_section_name_equal(section_names[i], ".efifw")) {
                                /* can't match without validate_base */
                                if (!validate_base)
                                        break;
                                if (!pe_use_this_firmware(
                                                    (const uint8_t *) SIZE_TO_PTR(validate_base) + j->VirtualAddress,
                                                    j->VirtualSize,
                                                    device_table,
                                                    device,
                                                    (PTR_TO_SIZE(j) - PTR_TO_SIZE(section_table)) / sizeof(*j)))
                                        continue;
                        }

                        /* At this time, the sizes and offsets have been validated. Store them away */
                        sections[i] = (PeSectionVector) {
                                .memory_size = j->VirtualSize,
                                .memory_offset = j->VirtualAddress,
                                /* VirtualSize can be bigger than SizeOfRawData when the section requires
                                 * uninitialized data. It can also be smaller than SizeOfRawData when there's
                                 * no need for uninitialized data as SizeOfRawData is aligned to
                                 * FileAlignment and VirtualSize isn't. The actual data that's read from disk
                                 * is the minimum of these two fields. */
                                .file_size = MIN(j->SizeOfRawData, j->VirtualSize),
                                .file_offset = j->PointerToRawData,
                        };

                        /* First matching section wins, ignore the rest */
                        break;
                }
}

static bool looking_for_dtbauto(const char *const section_names[]) {
        assert(section_names);

        for (size_t i = 0; section_names[i]; i++)
                if (pe_section_name_equal(section_names[i], ".dtbauto"))
                        return true;
         return false;
}

static void pe_locate_sections(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                PeSectionVector sections[]) {

        if (!looking_for_dtbauto(section_names))
                return pe_locate_sections_internal(
                                  section_table,
                                  n_section_table,
                                  section_names,
                                  validate_base,
                                  /* device_table= */ NULL,
                                  /* device= */ NULL,
                                  sections);

        /* It doesn't make sense not to provide validate_base here */
        assert(validate_base != 0);

        const void *hwids = NULL;
        const Device *device = NULL;

        if (!firmware_devicetree_exists()) {
                /* Find HWIDs table and search for the current device */
                static const char *const hwid_section_names[] = { ".hwids", NULL };
                PeSectionVector hwids_section[1] = {};

                pe_locate_sections_internal(
                                section_table,
                                n_section_table,
                                hwid_section_names,
                                validate_base,
                                /* device_table= */ NULL,
                                /* device= */ NULL,
                                hwids_section);

                if (PE_SECTION_VECTOR_IS_SET(hwids_section)) {
                        hwids = (const uint8_t *) SIZE_TO_PTR(validate_base) + hwids_section[0].memory_offset;

                        EFI_STATUS err = chid_match(hwids, hwids_section[0].memory_size, DEVICE_TYPE_DEVICETREE, &device);
                        if (err != EFI_SUCCESS) {
                                log_error_status(err, "HWID matching failed, no DT blob will be selected: %m");
                                hwids = NULL;
                        }
                }
        }

        return pe_locate_sections_internal(
                            section_table,
                            n_section_table,
                            section_names,
                            validate_base,
                            hwids,
                            device,
                            sections);
}

static uint32_t get_compatibility_entry_address(const DosFileHeader *dos, const PeFileHeader *pe) {
        /* The kernel may provide alternative PE entry points for different PE architectures. This allows
         * booting a 64-bit kernel on 32-bit EFI that is otherwise running on a 64-bit CPU. The locations of any
         * such compat entry points are located in a special PE section. */

        assert(dos);
        assert(pe);

        static const char *const section_names[] = { ".compat", NULL };
        PeSectionVector vector[1] = {};
        pe_locate_sections(
                        (const PeSectionHeader *) ((const uint8_t *) dos + section_table_offset(dos, pe)),
                        pe->FileHeader.NumberOfSections,
                        section_names,
                        PTR_TO_SIZE(dos),
                        vector);

        if (!PE_SECTION_VECTOR_IS_SET(vector)) /* not found */
                return 0;

        typedef struct {
                uint8_t type;
                uint8_t size;
                uint16_t machine_type;
                uint32_t entry_point;
        } _packed_ LinuxPeCompat1;

        size_t addr = vector[0].memory_offset, size = vector[0].memory_size;

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

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_entry_point, uint32_t *ret_compat_entry_point, size_t *ret_size_in_memory) {
        assert(base);

        const DosFileHeader *dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        /* When allocating we need to also consider the virtual/uninitialized data sections, so parse it out
         * of the SizeOfImage field in the PE header and return it */
        size_t size_in_memory = pe->OptionalHeader.SizeOfImage;

        /* Support for LINUX_INITRD_MEDIA_GUID was added in kernel stub 1.0. */
        if (pe->OptionalHeader.MajorImageVersion < 1)
                return EFI_UNSUPPORTED;

        if (pe->FileHeader.Machine == TARGET_MACHINE_TYPE) {
                if (ret_entry_point)
                        *ret_entry_point = pe->OptionalHeader.AddressOfEntryPoint;
                if (ret_compat_entry_point)
                        *ret_compat_entry_point = 0;
                if (ret_size_in_memory)
                        *ret_size_in_memory = size_in_memory;
                return EFI_SUCCESS;
        }

        uint32_t compat_entry_point = get_compatibility_entry_address(dos, pe);
        if (compat_entry_point == 0)
                /* Image type not supported and no compat entry found. */
                return EFI_UNSUPPORTED;

        if (ret_entry_point)
                *ret_entry_point = 0;
        if (ret_compat_entry_point)
                *ret_compat_entry_point = compat_entry_point;
        if (ret_size_in_memory)
                *ret_size_in_memory = size_in_memory;

        return EFI_SUCCESS;
}

/* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only */
#define BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY 5

/* We do not expect PE inner kernels to have any relocations. However that might be wrong for some
 * architectures, or it might change in the future. If the case of relocation arise, we should transform this
 * function in a function applying the relocations. However for now, since it would not be exercised and
 * would bitrot, we leave it as a check that relocations are never expected.
 */
EFI_STATUS pe_kernel_check_no_relocation(const void *base) {
        assert(base);

        const DosFileHeader *dos = base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        const PeImageDataDirectory *data_directory;
        switch (pe->OptionalHeader.Magic) {
        case OPTHDR32_MAGIC:
                data_directory = pe->OptionalHeader.DataDirectory32;
                break;
        case OPTHDR64_MAGIC:
                data_directory = pe->OptionalHeader.DataDirectory64;
                break;
        default:
                assert_not_reached();
        }

        if (data_directory[BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY].Size != 0)
                return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains base relocations, which we do not support.");

        return EFI_SUCCESS;
}

bool pe_kernel_check_nx_compat(const void *base) {
        const DosFileHeader *dos = ASSERT_PTR(base);
        if (!verify_dos(dos))
                return false;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return false;

        return pe->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
}

EFI_STATUS pe_section_table_from_base(
                const void *base,
                const PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table) {

        assert(base);
        assert(ret_section_table);
        assert(ret_n_section_table);

        const DosFileHeader *dos = (const DosFileHeader*) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader*) ((const uint8_t*) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        *ret_section_table = (const PeSectionHeader*) ((const uint8_t*) base + section_table_offset(dos, pe));
        *ret_n_section_table = pe->FileHeader.NumberOfSections;

        return EFI_SUCCESS;
}

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char *const section_names[],
                PeSectionVector sections[]) {

        EFI_STATUS err;

        assert(base);
        assert(section_names);
        assert(sections);

        const PeSectionHeader *section_table;
        size_t n_section_table;
        err = pe_section_table_from_base(base, &section_table, &n_section_table);
        if (err != EFI_SUCCESS)
                return err;

        pe_locate_sections(
                        section_table,
                        n_section_table,
                        section_names,
                        PTR_TO_SIZE(base),
                        sections);

        return EFI_SUCCESS;
}

EFI_STATUS pe_section_table_from_file(
                EFI_FILE *handle,
                PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table) {

        EFI_STATUS err;
        size_t len;

        assert(handle);
        assert(ret_section_table);
        assert(ret_n_section_table);

        DosFileHeader dos;
        len = sizeof(dos);
        err = handle->Read(handle, &len, &dos);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = handle->SetPosition(handle, dos.ExeHeader);
        if (err != EFI_SUCCESS)
                return err;

        PeFileHeader pe;
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
        size_t n_section_table = (size_t) pe.FileHeader.NumberOfSections;
        if (n_section_table * sizeof(PeSectionHeader) > SECTION_TABLE_BYTES_MAX)
                return EFI_OUT_OF_RESOURCES;

        _cleanup_free_ PeSectionHeader *section_table = xnew(PeSectionHeader, n_section_table);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = handle->SetPosition(handle, section_table_offset(&dos, &pe));
        if (err != EFI_SUCCESS)
                return err;

        len = n_section_table * sizeof(PeSectionHeader);
        err = handle->Read(handle, &len, section_table);
        if (err != EFI_SUCCESS)
                return err;
        if (len != n_section_table * sizeof(PeSectionHeader))
                return EFI_LOAD_ERROR;

        *ret_section_table = TAKE_PTR(section_table);
        *ret_n_section_table = n_section_table;
        return EFI_SUCCESS;
}

static const PeSectionHeader* pe_section_table_find_profile_start(
                const PeSectionHeader *section_table,
                size_t n_section_table,
                unsigned profile) {

        assert(section_table || n_section_table == 0);

        if (profile == UINT_MAX) /* base profile? that starts at the beginning */
                return section_table;

        unsigned current_profile = UINT_MAX;
        FOREACH_ARRAY(p, section_table, n_section_table) {

                if (!pe_section_name_equal((const char*) p->Name, ".profile"))
                        continue;

                if (current_profile == UINT_MAX)
                        current_profile = 0;
                else
                        current_profile++;

                if (current_profile == profile) /* Found our profile! */
                        return p;
        }

        /* We reached the end of the table? Then this section does not exist */
        return NULL;
}

static size_t pe_section_table_find_profile_length(
                const PeSectionHeader *section_table,
                size_t n_section_table,
                const PeSectionHeader *start,
                unsigned profile) {

        assert(section_table);
        assert(n_section_table > 0);
        assert(start >= section_table);
        assert(start < section_table + n_section_table);

        /* Look for the next .profile (or the end of the table), this is where the sections for this
         * profile end. The base profile does not start with a .profile, the others do, hence conditionally
         * skip over the first entry. */
        const PeSectionHeader *e;
        if (profile == UINT_MAX) /* Base profile */
                e = start;
        else {
                assert(pe_section_name_equal((const char *) start->Name, ".profile"));
                e = start + 1;
        }

        for (; e < section_table + n_section_table; e++)
                if (pe_section_name_equal((const char*) e->Name, ".profile"))
                        return e - start;

        return (section_table + n_section_table) - start;
}

EFI_STATUS pe_locate_profile_sections(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char* const section_names[],
                unsigned profile,
                size_t validate_base,
                PeSectionVector sections[]) {

        assert(section_table || n_section_table == 0);
        assert(section_names);
        assert(sections);

        /* Now scan through the section table until we skipped over the right number of .profile sections */
        const PeSectionHeader *p = pe_section_table_find_profile_start(section_table, n_section_table, profile);
        if (!p)
                return EFI_NOT_FOUND;

        /* Look for the next .profile (or the end of the table), this is where the sections for this
         * profile end. */
        size_t n = pe_section_table_find_profile_length(section_table, n_section_table, p, profile);

        /* And now parse everything between the start and end of our profile */
        pe_locate_sections(
                        p,
                        n,
                        section_names,
                        validate_base,
                        sections);

        return EFI_SUCCESS;
}
