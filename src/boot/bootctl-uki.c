/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl.h"
#include "bootctl-uki.h"
#include "fd-util.h"
#include "parse-util.h"
#include "pe-header.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"

static const uint8_t name_osrel[8] = ".osrel";
static const uint8_t name_linux[8] = ".linux";
static const uint8_t name_initrd[8] = ".initrd";

static struct PeSectionHeader* pe_sections(FILE *uki, uint16_t *n)
{
        struct PeSectionHeader *sections;
        struct DosFileHeader dos;
        struct PeHeader pe;
        uint16_t scount;
        off_t soff;
        size_t rc;

        rc = fread(&dos, 1, sizeof(dos), uki);
        if (rc != sizeof(dos)) {
                log_error("DOS header read error");
                return NULL;
        }
        if (memcmp(dos.Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) != 0) {
                log_error("DOS header magic mismatch");
                return NULL;
        }

        fseek(uki, le32toh(dos.ExeHeader), SEEK_SET);
        rc = fread(&pe, 1, sizeof(pe), uki);
        if (rc != sizeof(pe)) {
                log_error("PE header read error");
                return NULL;
        }
        if (memcmp(pe.Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) != 0) {
                log_error("PE header magic mismatch");
                return NULL;
        }

        soff = le32toh(dos.ExeHeader) + sizeof(pe) + le16toh(pe.FileHeader.SizeOfOptionalHeader);
        fseek(uki, soff, SEEK_SET);

        scount = le16toh(pe.FileHeader.NumberOfSections);
        sections = malloc(sizeof(*sections) * scount);
        rc = fread(sections, sizeof(*sections), scount, uki);
        if (rc != scount) {
                log_error("PE section header read error");
                free(sections);
                return NULL;
        }

        *n = scount;
        return sections;
}

int verb_is_uki(int argc, char *argv[], void *userdata) {
        _cleanup_fclose_ FILE *uki = NULL;
        _cleanup_free_ struct PeSectionHeader *sections;
        bool has_osrel = false;
        bool has_linux = false;
        bool has_initrd = false;
        uint16_t scount, s;

        uki = fopen(argv[1], "rb");
        if (!uki)
                return log_error_errno(errno, "Failed to open UKI file '%s': %m", argv[1]);

        sections = pe_sections(uki, &scount);
        if (sections == NULL)
                return 1;

        for (s = 0; s < scount; s++) {
                if (memcmp(sections[s].Name, name_osrel, 8) == 0)
                        has_osrel = true;
                if (memcmp(sections[s].Name, name_linux, 8) == 0)
                        has_linux = true;
                if (memcmp(sections[s].Name, name_initrd, 8) == 0)
                        has_initrd = true;
        }

        if (has_osrel && has_linux && has_initrd) {
                if (!arg_quiet)
                        puts("yes");
                return 0;
        } else {
                if (!arg_quiet)
                        puts("no");
                return 1;
        }
}
