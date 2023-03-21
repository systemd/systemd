/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "env-file.h"
#include "os-util.h"
#include "parse-util.h"
#include "pe-header.h"
#include "string-table.h"
#include "uki-util.h"

#define MAX_SECTIONS 96

static const uint8_t dos_file_magic[2] = "MZ";
static const uint8_t pe_file_magic[4] = "PE\0\0";

static const uint8_t name_osrel[8] = ".osrel";
static const uint8_t name_linux[8] = ".linux";
static const uint8_t name_initrd[8] = ".initrd";
static const uint8_t name_cmdline[8] = ".cmdline";
static const uint8_t name_uname[8] = ".uname";

static const char * const kernel_image_type_table[_KERNEL_IMAGE_TYPE_MAX] = {
        [KERNEL_IMAGE_TYPE_UNKNOWN] = "unknown",
        [KERNEL_IMAGE_TYPE_UKI]     = "uki",
        [KERNEL_IMAGE_TYPE_PE]      = "pe",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(kernel_image_type, KernelImageType);

static int pe_sections(FILE *f, struct PeSectionHeader **ret, size_t *ret_n) {
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        struct DosFileHeader dos;
        struct PeHeader pe;
        size_t scount;
        uint64_t soff, items;

        assert(f);
        assert(ret);
        assert(ret_n);

        items = fread(&dos, 1, sizeof(dos), f);
        if (items < sizeof(dos.Magic))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "File is smaller than DOS magic (got %"PRIu64" of %zu bytes)",
                                       items, sizeof(dos.Magic));
        if (memcmp(dos.Magic, dos_file_magic, sizeof(dos_file_magic)) != 0)
                goto no_sections;

        if (items != sizeof(dos))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "File is smaller than DOS header (got %"PRIu64" of %zu bytes)",
                                       items, sizeof(dos));

        if (fseek(f, le32toh(dos.ExeHeader), SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to PE header: %m");

        items = fread(&pe, 1, sizeof(pe), f);
        if (items != sizeof(pe))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read PE header.");
        if (memcmp(pe.Magic, pe_file_magic, sizeof(pe_file_magic)) != 0)
                goto no_sections;

        soff = le32toh(dos.ExeHeader) + sizeof(pe) + le16toh(pe.FileHeader.SizeOfOptionalHeader);
        if (fseek(f, soff, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to PE section headers: %m");

        scount = le16toh(pe.FileHeader.NumberOfSections);
        if (scount > MAX_SECTIONS)
                goto no_sections;
        sections = new(struct PeSectionHeader, scount);
        if (!sections)
                return log_oom();
        items = fread(sections, sizeof(*sections), scount, f);
        if (items != scount)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read PE section header.");

        *ret = TAKE_PTR(sections);
        *ret_n = scount;
        return 0;

no_sections:
        *ret = NULL;
        *ret_n = 0;
        return 0;
}

static bool find_pe_section(
                struct PeSectionHeader *sections,
                size_t scount,
                const uint8_t *name,
                size_t namelen,
                size_t *ret) {

        assert(sections || scount == 0);
        assert(name || namelen == 0);

        for (size_t s = 0; s < scount; s++)
                if (memcmp_nn(sections[s].Name, sizeof(sections[s].Name), name, namelen) == 0) {
                        if (ret)
                                *ret = s;
                        return true;
                }

        return false;
}

static bool is_uki(struct PeSectionHeader *sections, size_t scount) {
        assert(sections || scount == 0);

        return
                find_pe_section(sections, scount, name_osrel, sizeof(name_osrel), NULL) &&
                find_pe_section(sections, scount, name_linux, sizeof(name_linux), NULL) &&
                find_pe_section(sections, scount, name_initrd, sizeof(name_initrd), NULL);
}

static int read_pe_section(
                FILE *f,
                struct PeSectionHeader *sections,
                size_t scount,
                const uint8_t *name,
                size_t name_len,
                void **ret,
                size_t *ret_n) {

        struct PeSectionHeader *section;
        _cleanup_free_ void *data = NULL;
        uint32_t size, bytes;
        uint64_t soff;
        size_t idx;

        assert(f);
        assert(sections || scount == 0);
        assert(ret);

        if (!find_pe_section(sections, scount, name, name_len, &idx)) {
                *ret = NULL;
                if (ret_n)
                        *ret_n = 0;
                return 0;
        }

        section = sections + idx;
        soff = le32toh(section->PointerToRawData);
        size = le32toh(section->VirtualSize);

        if (size > 16 * 1024)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "PE section too big.");

        if (fseek(f, soff, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to seek to PE section: %m");

        data = malloc(size+1);
        if (!data)
                return log_oom();
        ((uint8_t*) data)[size] = 0; /* safety NUL byte */

        bytes = fread(data, 1, size, f);
        if (bytes != size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read PE section.");

        *ret = TAKE_PTR(data);
        if (ret_n)
                *ret_n = size;
        return 1;
}

static int uki_read_pretty_name(
                FILE *f,
                struct PeSectionHeader *sections,
                size_t scount,
                char **ret) {

        _cleanup_free_ char *pname = NULL, *name = NULL;
        _cleanup_fclose_ FILE *s = NULL;
        _cleanup_free_ void *osrel = NULL;
        size_t osrel_size = 0;
        int r;

        assert(f);
        assert(sections || scount == 0);
        assert(ret);

        r = read_pe_section(f, sections, scount, name_osrel, sizeof(name_osrel), &osrel, &osrel_size);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        s = fmemopen(osrel, osrel_size, "r");
        if (!s)
                return log_error_errno(errno, "Failed to open embedded os-release file: %m");

        r = parse_env_file(s, NULL,
                           "PRETTY_NAME", &pname,
                           "NAME",        &name);
        if (r < 0)
                return log_error_errno(r, "Failed to parse embedded os-release file: %m");

        /* follow the same logic as os_release_pretty_name() */
        if (!isempty(pname))
                *ret = TAKE_PTR(pname);
        else if (!isempty(name))
                *ret = TAKE_PTR(name);
        else {
                char *n = strdup("Linux");
                if (!n)
                        return log_oom();

                *ret = n;
        }

        return 0;
}

static int inspect_uki(
                FILE *f,
                struct PeSectionHeader *sections,
                size_t scount,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        int r;

        assert(f);
        assert(sections || scount == 0);

        if (ret_cmdline) {
                r = read_pe_section(f, sections, scount, name_cmdline, sizeof(name_cmdline), (void**) &cmdline, NULL);
                if (r < 0)
                        return r;
        }

        if (ret_uname) {
                r = read_pe_section(f, sections, scount, name_uname, sizeof(name_uname), (void**) &uname, NULL);
                if (r < 0)
                        return r;
        }

        if (ret_pretty_name) {
                r = uki_read_pretty_name(f, sections, scount, &pname);
                if (r < 0)
                        return r;
        }

        if (ret_cmdline)
                *ret_cmdline = TAKE_PTR(cmdline);
        if (ret_uname)
                *ret_uname = TAKE_PTR(uname);
        if (ret_pretty_name)
                *ret_pretty_name = TAKE_PTR(pname);

        return 0;
}

int inspect_kernel(
                const char *filename,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        size_t scount;
        KernelImageType t;
        int r;

        assert(filename);

        f = fopen(filename, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open kernel image file '%s': %m", filename);

        r = pe_sections(f, &sections, &scount);
        if (r < 0)
                return r;

        if (!sections)
                t = KERNEL_IMAGE_TYPE_UNKNOWN;
        else if (is_uki(sections, scount)) {
                t = KERNEL_IMAGE_TYPE_UKI;
                r = inspect_uki(f, sections, scount, ret_cmdline, ret_uname, ret_pretty_name);
                if (r < 0)
                        return r;
        } else
                t = KERNEL_IMAGE_TYPE_PE;

        if (ret_type)
                *ret_type = t;

        return 0;
}
