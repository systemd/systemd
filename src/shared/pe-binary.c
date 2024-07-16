/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "log.h"
#include "pe-binary.h"
#include "string-util.h"
#include "uki.h"

bool pe_header_is_64bit(const PeHeader *h) {
        assert(h);

        if (le16toh(h->optional.Magic) == UINT16_C(0x010B)) /* PE32 */
                return false;

        if (le16toh(h->optional.Magic) == UINT16_C(0x020B)) /* PE32+ */
                return true;

        assert_not_reached();
}

static size_t pe_header_size(const PeHeader *pe_header) {
        assert(pe_header);

        return offsetof(PeHeader, optional) + le16toh(pe_header->pe.SizeOfOptionalHeader);
}

const IMAGE_DATA_DIRECTORY *pe_header_get_data_directory(
                const PeHeader *h,
                size_t i) {

        assert(h);

        if (i >= le32toh(PE_HEADER_OPTIONAL_FIELD(h, NumberOfRvaAndSizes)))
                return NULL;

        return PE_HEADER_OPTIONAL_FIELD(h, DataDirectory) + i;
}

const IMAGE_SECTION_HEADER *pe_section_table_find(
                const IMAGE_SECTION_HEADER *sections,
                size_t n_sections,
                const char *name) {

        size_t n;

        assert(name);
        assert(sections || n_sections == 0);

        n = strlen(name);
        if (n > sizeof(sections[0].Name)) /* Too long? */
                return NULL;

        FOREACH_ARRAY(section, sections, n_sections)
                if (memcmp(section->Name, name, n) == 0 &&
                    memeqzero(section->Name + n, sizeof(section->Name) - n))
                        return section;

        return NULL;
}

const IMAGE_SECTION_HEADER* pe_header_find_section(
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name) {

        assert(pe_header);

        return pe_section_table_find(sections, le16toh(pe_header->pe.NumberOfSections), name);
}

int pe_load_headers(
                int fd,
                IMAGE_DOS_HEADER **ret_dos_header,
                PeHeader **ret_pe_header) {

        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        ssize_t n;

        assert(fd >= 0);

        dos_header = new(IMAGE_DOS_HEADER, 1);
        if (!dos_header)
                return log_oom_debug();

        n = pread(fd,
                  dos_header,
                  sizeof(IMAGE_DOS_HEADER),
                  0);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read DOS header: %m");
        if ((size_t) n != sizeof(IMAGE_DOS_HEADER))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading MZ executable header.");

        if (le16toh(dos_header->e_magic) != UINT16_C(0x5A4D))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks MZ executable header.");

        pe_header = new(PeHeader, 1);
        if (!pe_header)
                return log_oom_debug();

        n = pread(fd,
                  pe_header,
                  offsetof(PeHeader, optional),
                  le32toh(dos_header->e_lfanew));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable header: %m");
        if ((size_t) n != offsetof(PeHeader, optional))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable header.");

        if (le32toh(pe_header->signature) != UINT32_C(0x00004550))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks PE executable header.");

        if (le16toh(pe_header->pe.SizeOfOptionalHeader) < sizeof_field(PeHeader, optional.Magic))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size too short for magic.");

        PeHeader *pe_header_tmp = realloc(pe_header, MAX(sizeof(PeHeader), pe_header_size(pe_header)));
        if (!pe_header_tmp)
                return log_oom_debug();
        pe_header = pe_header_tmp;

        n = pread(fd,
                  &pe_header->optional,
                  le16toh(pe_header->pe.SizeOfOptionalHeader),
                  le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read PE executable optional header: %m");
        if ((size_t) n != le16toh(pe_header->pe.SizeOfOptionalHeader))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading PE executable optional header.");

        if (!IN_SET(le16toh(pe_header->optional.Magic), UINT16_C(0x010B), UINT16_C(0x020B)))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header magic invalid.");

        if (pe_header_size(pe_header) !=
            PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory) +
            sizeof(IMAGE_DATA_DIRECTORY) * (uint64_t) le32toh(PE_HEADER_OPTIONAL_FIELD(pe_header, NumberOfRvaAndSizes)))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Optional header size mismatch.");

        if (ret_dos_header)
                *ret_dos_header = TAKE_PTR(dos_header);
        if (ret_pe_header)
                *ret_pe_header = TAKE_PTR(pe_header);

        return 0;
}

int pe_load_sections(
                int fd,
                const IMAGE_DOS_HEADER *dos_header,
                const PeHeader *pe_header,
                IMAGE_SECTION_HEADER **ret_sections) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        size_t nos;
        ssize_t n;

        assert(fd >= 0);
        assert(dos_header);
        assert(pe_header);

        nos = le16toh(pe_header->pe.NumberOfSections);

        sections = new(IMAGE_SECTION_HEADER, nos);
        if (!sections)
                return log_oom_debug();

        n = pread(fd,
                  sections,
                  sizeof(IMAGE_SECTION_HEADER) * nos,
                  le32toh(dos_header->e_lfanew) + pe_header_size(pe_header));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read section table: %m");
        if ((size_t) n != sizeof(IMAGE_SECTION_HEADER) * nos)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Short read while reading section table.");

        if (ret_sections)
                *ret_sections = TAKE_PTR(sections);

        return 0;
}

int pe_read_section_data(
                int fd,
                const IMAGE_SECTION_HEADER *section,
                size_t max_size,
                void **ret,
                size_t *ret_size) {

        assert(fd >= 0);
        assert(section);

        size_t n = le32toh(section->VirtualSize);
        if (n > MIN(max_size, (size_t) SSIZE_MAX))
                return -E2BIG;

        _cleanup_free_ void *data = malloc(n+1);
        if (!data)
                return -ENOMEM;

        ssize_t ss = pread(fd, data, n, le32toh(section->PointerToRawData));
        if (ss < 0)
                return -errno;
        if ((size_t) ss != n)
                return -EIO;

        if (ret_size)
                *ret_size = n;
        else {
                /* Check that there are no embedded NUL bytes if the caller doesn't want to know the size
                 * (i.e. treats the blob as a string) */
                const char *nul;

                nul = memchr(data, 0, n);
                if (nul && !memeqzero(nul, n - (nul - (const char*) data))) /* If there's a NUL it must only be NULs from there on */
                        return -EBADMSG;
        }
        if (ret) {
                ((uint8_t*) data)[n] = 0; /* NUL terminate, no matter what */
                *ret = TAKE_PTR(data);
        }

        return 0;
}

int pe_read_section_data_by_name(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name,
                size_t max_size,
                void **ret,
                size_t *ret_size) {

        const IMAGE_SECTION_HEADER *section;

        assert(fd >= 0);
        assert(pe_header);
        assert(sections || pe_header->pe.NumberOfSections == 0);
        assert(name);

        section = pe_header_find_section(pe_header, sections, name);
        if (!section)
                return -ENXIO;

        return pe_read_section_data(fd, section, max_size, ret, ret_size);
}

bool pe_is_uki(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections) {
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (le16toh(pe_header->optional.Subsystem) != IMAGE_SUBSYSTEM_EFI_APPLICATION)
                return false;

        /* Note that the UKI spec only requires .linux, but we are stricter here, and require .osrel too,
         * since for sd-boot it just doesn't make sense to not have that. */
        return
                pe_header_find_section(pe_header, sections, ".osrel") &&
                pe_header_find_section(pe_header, sections, ".linux");
}

bool pe_is_addon(const PeHeader *pe_header, const IMAGE_SECTION_HEADER *sections) {
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (le16toh(pe_header->optional.Subsystem) != IMAGE_SUBSYSTEM_EFI_APPLICATION)
                return false;

        /* Add-ons do not have a Linux kernel, but do have either .cmdline or .dtb (currently) */
        return !pe_header_find_section(pe_header, sections, ".linux") &&
                (pe_header_find_section(pe_header, sections, ".cmdline") ||
                 pe_header_find_section(pe_header, sections, ".dtb") ||
                 pe_header_find_section(pe_header, sections, ".ucode"));
}

bool pe_is_native(const PeHeader *pe_header) {
        assert(pe_header);

#ifdef _IMAGE_FILE_MACHINE_NATIVE
        return le16toh(pe_header->pe.Machine) == _IMAGE_FILE_MACHINE_NATIVE;
#else
        return false;
#endif
}
