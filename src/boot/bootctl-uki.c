/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl.h"
#include "bootctl-uki.h"
#include "fd-util.h"
#include "parse-util.h"
#include "pe-header.h"

#define MAX_SECTIONS 96

static const uint8_t dos_file_magic[2] = "MZ";
static const uint8_t pe_file_magic[4] = "PE\0\0";

static const uint8_t name_osrel[8] = ".osrel";
static const uint8_t name_linux[8] = ".linux";
static const uint8_t name_initrd[8] = ".initrd";

static int pe_sections(FILE *uki, struct PeSectionHeader **ret, uint16_t *ret_n) {
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        struct DosFileHeader dos;
        struct PeHeader pe;
        uint16_t scount;
        uint64_t soff, items;
        int rc;

        *ret = NULL;
        *ret_n = 0;

        items = fread(&dos, 1, sizeof(dos), uki);
        if (items != sizeof(dos))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "DOS header read error");
        if (memcmp(dos.Magic, dos_file_magic, sizeof(dos_file_magic)) != 0)
                return 0;

        rc = fseek(uki, le32toh(dos.ExeHeader), SEEK_SET);
        if (rc < 0)
                return log_error_errno(errno, "seek to PE header");
        items = fread(&pe, 1, sizeof(pe), uki);
        if (items != sizeof(pe))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PE header read error");
        if (memcmp(pe.Magic, pe_file_magic, sizeof(pe_file_magic)) != 0)
                return 0;

        soff = le32toh(dos.ExeHeader) + sizeof(pe) + le16toh(pe.FileHeader.SizeOfOptionalHeader);
        rc = fseek(uki, soff, SEEK_SET);
        if (rc < 0)
                return log_error_errno(errno, "seek to PE section headers");

        scount = le16toh(pe.FileHeader.NumberOfSections);
        if (scount > MAX_SECTIONS)
                return 0;
        sections = new(struct PeSectionHeader, scount);
        items = fread(sections, sizeof(*sections), scount, uki);
        if (items != scount)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PE section header read error");

        *ret = TAKE_PTR(sections);
        *ret_n = scount;
        return 0;
}

static int find_pe_section(struct PeSectionHeader *sections, uint16_t scount,
                           const uint8_t *name, size_t namelen, uint16_t *ret) {
        int s;

        for (s = 0; s < scount; s++) {
                if (memcmp_nn(sections[s].Name, sizeof(sections[s].Name),
                              name, namelen) == 0) {
                        if (ret)
                                *ret = s;
                        return 1;
                }
        }
        return 0;
}

static bool is_uki(struct PeSectionHeader *sections, uint16_t scount) {
        if (find_pe_section(sections, scount, name_osrel, sizeof(name_osrel), NULL) &&
            find_pe_section(sections, scount, name_linux, sizeof(name_linux), NULL) &&
            find_pe_section(sections, scount, name_initrd, sizeof(name_initrd), NULL)) {
                return true;
        }
        return false;
}

int verb_kernel_identify(int argc, char *argv[], void *userdata) {
        _cleanup_fclose_ FILE *uki = NULL;
        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        uint16_t scount;
        int rc;

        uki = fopen(argv[1], "r");
        if (!uki)
                return log_error_errno(errno, "Failed to open UKI file '%s': %m", argv[1]);

        rc = pe_sections(uki, &sections, &scount);
        if (rc < 0)
                return EXIT_FAILURE;

        if (sections) {
                if (is_uki(sections, scount)) {
                        puts("uki");
                        return EXIT_SUCCESS;
                }
                puts("pe");
                return EXIT_SUCCESS;
        }

        puts("unknown");
        return EXIT_SUCCESS;
}
