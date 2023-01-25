/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl.h"
#include "bootctl-uki.h"
#include "env-file.h"
#include "fd-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "pe-header.h"

#define MAX_SECTIONS 96

static const uint8_t dos_file_magic[2] = "MZ";
static const uint8_t pe_file_magic[4] = "PE\0\0";

static const uint8_t name_osrel[8] = ".osrel";
static const uint8_t name_linux[8] = ".linux";
static const uint8_t name_initrd[8] = ".initrd";
static const uint8_t name_cmdline[8] = ".cmdline";
static const uint8_t name_uname[8] = ".uname";

static int pe_sections(FILE *uki, struct PeSectionHeader **ret, size_t *ret_n) {
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        struct DosFileHeader dos;
        struct PeHeader pe;
        size_t scount;
        uint64_t soff, items;

        assert(uki);
        assert(ret);
        assert(ret_n);

        items = fread(&dos, 1, sizeof(dos), uki);
        if (items != sizeof(dos))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "DOS header read error");
        if (memcmp(dos.Magic, dos_file_magic, sizeof(dos_file_magic)) != 0)
                goto no_sections;

        if (fseek(uki, le32toh(dos.ExeHeader), SEEK_SET) < 0)
                return log_error_errno(errno, "seek to PE header");

        items = fread(&pe, 1, sizeof(pe), uki);
        if (items != sizeof(pe))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PE header read error");
        if (memcmp(pe.Magic, pe_file_magic, sizeof(pe_file_magic)) != 0)
                goto no_sections;

        soff = le32toh(dos.ExeHeader) + sizeof(pe) + le16toh(pe.FileHeader.SizeOfOptionalHeader);
        if (fseek(uki, soff, SEEK_SET) < 0)
                return log_error_errno(errno, "seek to PE section headers");

        scount = le16toh(pe.FileHeader.NumberOfSections);
        if (scount > MAX_SECTIONS)
                goto no_sections;
        sections = new(struct PeSectionHeader, scount);
        if (!sections)
                return log_oom();
        items = fread(sections, sizeof(*sections), scount, uki);
        if (items != scount)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PE section header read error");

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

int verb_kernel_identify(int argc, char *argv[], void *userdata) {
        _cleanup_fclose_ FILE *uki = NULL;
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        size_t scount;
        int r;

        uki = fopen(argv[1], "re");
        if (!uki)
                return log_error_errno(errno, "Failed to open UKI file '%s': %m", argv[1]);

        r = pe_sections(uki, &sections, &scount);
        if (r < 0)
                return r;

        if (!sections)
                puts("unknown");
        else if (is_uki(sections, scount))
                puts("uki");
        else
                puts("pe");

        return EXIT_SUCCESS;
}

static int read_pe_section(
                FILE *uki,
                const struct PeSectionHeader *section,
                void **ret,
                size_t *ret_n) {

        _cleanup_free_ void *data = NULL;
        uint32_t size, bytes;
        uint64_t soff;

        assert(uki);
        assert(section);
        assert(ret);

        soff = le32toh(section->PointerToRawData);
        size = le32toh(section->VirtualSize);

        if (size > 16 * 1024)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "PE section too big");

        if (fseek(uki, soff, SEEK_SET) < 0)
                return log_error_errno(errno, "seek to PE section");

        data = malloc(size+1);
        if (!data)
                return log_oom();
        ((uint8_t*) data)[size] = 0; /* safety NUL byte */

        bytes = fread(data, 1, size, uki);
        if (bytes != size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PE section read error");

        *ret = TAKE_PTR(data);
        if (ret_n)
                *ret_n = size;
        return 0;
}

static int inspect_osrel(const void *osrel, size_t osrel_size) {
        _cleanup_fclose_ FILE *s = NULL;
        _cleanup_free_ char *pname = NULL, *name = NULL;
        int r;

        assert(osrel || osrel_size == 0);

        if (!osrel)
                return 0;

        s = fmemopen((void*) osrel, osrel_size, "r");
        if (!s)
                return log_warning_errno(errno, "Failed to open embedded os-release file, ignoring: %m");

        r = parse_env_file(s, NULL,
                           "PRETTY_NAME", &pname,
                           "NAME",        &name);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse embedded os-release file, ignoring: %m");

        printf("         OS: %s\n", os_release_pretty_name(pname, name));
        return 0;
}

static void inspect_uki(FILE *uki, struct PeSectionHeader *sections, size_t scount) {
        _cleanup_free_ char *cmdline = NULL, *uname = NULL;
        _cleanup_free_ void *osrel = NULL;
        size_t osrel_size = 0, idx;

        assert(uki);
        assert(sections || scount == 0);

        if (find_pe_section(sections, scount, name_cmdline, sizeof(name_cmdline), &idx))
                read_pe_section(uki, sections + idx, (void**) &cmdline, NULL);

        if (find_pe_section(sections, scount, name_uname, sizeof(name_uname), &idx))
                read_pe_section(uki, sections + idx, (void**) &uname, NULL);

        if (find_pe_section(sections, scount, name_osrel, sizeof(name_osrel), &idx))
                read_pe_section(uki, sections + idx, &osrel, &osrel_size);

        if (cmdline)
                printf("    Cmdline: %s\n", cmdline);
        if (uname)
                printf("    Version: %s\n", uname);

        (void) inspect_osrel(osrel, osrel_size);
}

int verb_kernel_inspect(int argc, char *argv[], void *userdata) {
        _cleanup_fclose_ FILE *uki = NULL;
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        size_t scount;
        int r;

        uki = fopen(argv[1], "re");
        if (!uki)
                return log_error_errno(errno, "Failed to open UKI file '%s': %m", argv[1]);

        r = pe_sections(uki, &sections, &scount);
        if (r < 0)
                return r;

        if (!sections)
                puts("Kernel Type: unknown");
        else if (is_uki(sections, scount)) {
                puts("Kernel Type: uki");
                inspect_uki(uki, sections, scount);
        } else
                puts("Kernel Type: pe");

        return EXIT_SUCCESS;
}
