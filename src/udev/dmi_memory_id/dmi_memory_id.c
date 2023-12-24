/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * System Memory information
 *
 *   Copyright (C) 2000-2002 Alan Cox <alan@redhat.com>
 *   Copyright (C) 2002-2020 Jean Delvare <jdelvare@suse.de>
 *   Copyright (C) 2020 Bastien Nocera <hadess@hadess.net>
 *
 * Unless specified otherwise, all references are aimed at the "System
 * Management BIOS Reference Specification, Version 3.2.0" document,
 * available from http://www.dmtf.org/standards/smbios.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *  - Intel AP-485 revision 36
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://www.intel.com/support/processors/sb/cs-009861.htm
 *  - DMTF Common Information Model
 *    CIM Schema version 2.19.1
 *    http://www.dmtf.org/standards/cim/
 *  - IPMI 2.0 revision 1.0
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 *  - AMD publication #25481 revision 2.28
 *    "CPUID Specification"
 *    http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25481.pdf
 *  - BIOS Integrity Services Application Programming Interface version 1.0
 *    http://www.intel.com/design/archives/wfm/downloads/bisspec.htm
 *  - DMTF DSP0239 version 1.1.0
 *    "Management Component Transport Protocol (MCTP) IDs and Codes"
 *    http://www.dmtf.org/standards/pmci
 *  - "TPM Main, Part 2 TPM Structures"
 *    Specification version 1.2, level 2, revision 116
 *    https://trustedcomputinggroup.org/tpm-main-specification/
 *  - "PC Client Platform TPM Profile (PTP) Specification"
 *    Family "2.0", Level 00, Revision 00.43, January 26, 2015
 *    https://trustedcomputinggroup.org/pc-client-platform-tpm-profile-ptp-specification/
 *  - "RedFish Host Interface Specification" (DMTF DSP0270)
 *    https://www.dmtf.org/sites/default/files/DSP0270_1.0.1.pdf
 */

#include <getopt.h>

#include "alloc-util.h"
#include "build.h"
#include "fileio.h"
#include "main-func.h"
#include "string-util.h"
#include "udev-util.h"
#include "unaligned.h"

#define SUPPORTED_SMBIOS_VER 0x030300

#define OUT_OF_SPEC_STR "<OUT OF SPEC>"

#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

/*
 * Per SMBIOS v2.8.0 and later, all structures assume a little-endian
 * ordering convention.
 */
#define WORD(x)  (unaligned_read_le16(x))
#define DWORD(x) (unaligned_read_le32(x))
#define QWORD(x) (unaligned_read_le64(x))

struct dmi_header {
        uint8_t type;
        uint8_t length;
        uint16_t handle;
        const uint8_t *data;
};

static const char *arg_source_file = NULL;

static bool verify_checksum(const uint8_t *buf, size_t len) {
        uint8_t sum = 0;

        for (size_t a = 0; a < len; a++)
                sum += buf[a];
        return sum == 0;
}

/*
 * Type-independent Stuff
 */

static const char *dmi_string(const struct dmi_header *dm, uint8_t s) {
        const char *bp = (const char *) dm->data;

        if (s == 0)
                return "Not Specified";

        bp += dm->length;
        for (; s > 1 && !isempty(bp); s--)
                bp += strlen(bp) + 1;

        if (isempty(bp))
                return "<BAD INDEX>";

        return bp;
}

typedef enum {
        MEMORY_SIZE_UNIT_BYTES,
        MEMORY_SIZE_UNIT_KB
} MemorySizeUnit;

static void dmi_print_memory_size(
                const char *attr_prefix, const char *attr_suffix,
                int slot_num, uint64_t code, MemorySizeUnit unit) {
        if (unit == MEMORY_SIZE_UNIT_KB)
                code <<= 10;

        if (slot_num >= 0)
                printf("%s_%i_%s=%"PRIu64"\n", attr_prefix, slot_num, attr_suffix, code);
        else
                printf("%s_%s=%"PRIu64"\n", attr_prefix, attr_suffix, code);
}

/*
 * 7.17 Physical Memory Array (Type 16)
 */

static void dmi_memory_array_location(uint8_t code) {
        /* 7.17.1 */
        static const char *location[] = {
                [0x01] = "Other",
                [0x02] = "Unknown",
                [0x03] = "System Board Or Motherboard",
                [0x04] = "ISA Add-on Card",
                [0x05] = "EISA Add-on Card",
                [0x06] = "PCI Add-on Card",
                [0x07] = "MCA Add-on Card",
                [0x08] = "PCMCIA Add-on Card",
                [0x09] = "Proprietary Add-on Card",
                [0x0A] = "NuBus",
        };
        static const char *location_0xA0[] = {
                [0x00] = "PC-98/C20 Add-on Card",       /* 0xA0 */
                [0x01] = "PC-98/C24 Add-on Card",       /* 0xA1 */
                [0x02] = "PC-98/E Add-on Card",         /* 0xA2 */
                [0x03] = "PC-98/Local Bus Add-on Card", /* 0xA3 */
                [0x04] = "CXL Flexbus 1.0",             /* 0xA4 */
        };
        const char *str = OUT_OF_SPEC_STR;

        if (code < ELEMENTSOF(location) && location[code])
                str = location[code];
        else if (code >= 0xA0 && code < (ELEMENTSOF(location_0xA0) + 0xA0))
                str = location_0xA0[code - 0xA0];

        printf("MEMORY_ARRAY_LOCATION=%s\n", str);
}

static void dmi_memory_array_ec_type(uint8_t code) {
        /* 7.17.3 */
        static const char *type[] = {
                [0x01] = "Other",
                [0x02] = "Unknown",
                [0x03] = "None",
                [0x04] = "Parity",
                [0x05] = "Single-bit ECC",
                [0x06] = "Multi-bit ECC",
                [0x07] = "CRC",
        };

        if (code != 0x03) /* Do not print "None". */
                printf("MEMORY_ARRAY_EC_TYPE=%s\n",
                       code < ELEMENTSOF(type) && type[code] ? type[code] : OUT_OF_SPEC_STR);
}

/*
 * 7.18 Memory Device (Type 17)
 */

static void dmi_memory_device_string(
                const char *attr_suffix, unsigned slot_num,
                const struct dmi_header *h, uint8_t s) {
        char *str;

        str = strdupa_safe(dmi_string(h, s));
        str = strstrip(str);
        if (!isempty(str))
                printf("MEMORY_DEVICE_%u_%s=%s\n", slot_num, attr_suffix, str);
}

static void dmi_memory_device_width(
                const char *attr_suffix,
                unsigned slot_num, uint16_t code) {

        /* If no memory module is present, width may be 0 */
        if (!IN_SET(code, 0, 0xFFFF))
                printf("MEMORY_DEVICE_%u_%s=%u\n", slot_num, attr_suffix, code);
}

static void dmi_memory_device_size(unsigned slot_num, uint16_t code) {
        if (code == 0)
                return (void) printf("MEMORY_DEVICE_%u_PRESENT=0\n", slot_num);
        if (code == 0xFFFF)
                return;

        uint64_t s = code & 0x7FFF;
        if (!(code & 0x8000))
                s <<= 10;
        dmi_print_memory_size("MEMORY_DEVICE", "SIZE", slot_num, s, MEMORY_SIZE_UNIT_KB);
}

static void dmi_memory_device_extended_size(unsigned slot_num, uint32_t code) {
        uint64_t capacity = (uint64_t) code * 1024 * 1024;

        printf("MEMORY_DEVICE_%u_SIZE=%"PRIu64"\n", slot_num, capacity);
}

static void dmi_memory_device_rank(unsigned slot_num, uint8_t code) {
        code &= 0x0F;
        if (code != 0)
                printf("MEMORY_DEVICE_%u_RANK=%u\n", slot_num, code);
}

static void dmi_memory_device_voltage_value(
                const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        if (code == 0)
                return;
        if (code % 100 != 0)
                printf("MEMORY_DEVICE_%u_%s=%g\n", slot_num, attr_suffix, (double)code / 1000);
        else
                printf("MEMORY_DEVICE_%u_%s=%.1g\n", slot_num, attr_suffix, (double)code / 1000);
}

static void dmi_memory_device_form_factor(unsigned slot_num, uint8_t code) {
        /* 7.18.1 */
        static const char *form_factor[] = {
                [0x01] = "Other",
                [0x02] = "Unknown",
                [0x03] = "SIMM",
                [0x04] = "SIP",
                [0x05] = "Chip",
                [0x06] = "DIP",
                [0x07] = "ZIP",
                [0x08] = "Proprietary Card",
                [0x09] = "DIMM",
                [0x0A] = "TSOP",
                [0x0B] = "Row Of Chips",
                [0x0C] = "RIMM",
                [0x0D] = "SODIMM",
                [0x0E] = "SRIMM",
                [0x0F] = "FB-DIMM",
                [0x10] = "Die",
        };

        printf("MEMORY_DEVICE_%u_FORM_FACTOR=%s\n", slot_num,
               code < ELEMENTSOF(form_factor) && form_factor[code] ? form_factor[code] : OUT_OF_SPEC_STR);
}

static void dmi_memory_device_set(unsigned slot_num, uint8_t code) {
        if (code == 0xFF)
                printf("MEMORY_DEVICE_%u_SET=%s\n", slot_num, "Unknown");
        else if (code != 0)
                printf("MEMORY_DEVICE_%u_SET=%"PRIu8"\n", slot_num, code);
}

static void dmi_memory_device_type(unsigned slot_num, uint8_t code) {
        /* 7.18.2 */
        static const char *type[] = {
                [0x01] = "Other",
                [0x02] = "Unknown",
                [0x03] = "DRAM",
                [0x04] = "EDRAM",
                [0x05] = "VRAM",
                [0x06] = "SRAM",
                [0x07] = "RAM",
                [0x08] = "ROM",
                [0x09] = "Flash",
                [0x0A] = "EEPROM",
                [0x0B] = "FEPROM",
                [0x0C] = "EPROM",
                [0x0D] = "CDRAM",
                [0x0E] = "3DRAM",
                [0x0F] = "SDRAM",
                [0x10] = "SGRAM",
                [0x11] = "RDRAM",
                [0x12] = "DDR",
                [0x13] = "DDR2",
                [0x14] = "DDR2 FB-DIMM",
                [0x15] = "Reserved",
                [0x16] = "Reserved",
                [0x17] = "Reserved",
                [0x18] = "DDR3",
                [0x19] = "FBD2",
                [0x1A] = "DDR4",
                [0x1B] = "LPDDR",
                [0x1C] = "LPDDR2",
                [0x1D] = "LPDDR3",
                [0x1E] = "LPDDR4",
                [0x1F] = "Logical non-volatile device",
                [0x20] = "HBM",
                [0x21] = "HBM2",
        };

        printf("MEMORY_DEVICE_%u_TYPE=%s\n", slot_num,
               code < ELEMENTSOF(type) && type[code] ? type[code] : OUT_OF_SPEC_STR);
}

static void dmi_memory_device_type_detail(unsigned slot_num, uint16_t code) {
        /* 7.18.3 */
        static const char *detail[] = {
                [1]  = "Other",
                [2]  = "Unknown",
                [3]  = "Fast-paged",
                [4]  = "Static Column",
                [5]  = "Pseudo-static",
                [6]  = "RAMBus",
                [7]  = "Synchronous",
                [8]  = "CMOS",
                [9]  = "EDO",
                [10] = "Window DRAM",
                [11] = "Cache DRAM",
                [12] = "Non-Volatile",
                [13] = "Registered (Buffered)",
                [14] = "Unbuffered (Unregistered)",
                [15] = "LRDIMM",
        };

        if ((code & 0xFFFE) == 0)
                printf("MEMORY_DEVICE_%u_TYPE_DETAIL=%s\n", slot_num, "None");
        else {
                bool first_element = true;

                printf("MEMORY_DEVICE_%u_TYPE_DETAIL=", slot_num);
                for (size_t i = 1; i < ELEMENTSOF(detail); i++)
                        if (code & (1 << i)) {
                                printf("%s%s", first_element ? "" : " ", detail[i]);
                                first_element = false;
                        }
                printf("\n");
        }
}

static void dmi_memory_device_speed(
                const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        if (code != 0)
                printf("MEMORY_DEVICE_%u_%s=%u\n", slot_num, attr_suffix, code);
}

static void dmi_memory_device_technology(unsigned slot_num, uint8_t code) {
        /* 7.18.6 */
        static const char * const technology[] = {
                [0x01] = "Other",
                [0x02] = "Unknown",
                [0x03] = "DRAM",
                [0x04] = "NVDIMM-N",
                [0x05] = "NVDIMM-F",
                [0x06] = "NVDIMM-P",
                [0x07] = "Intel Optane DC persistent memory",
        };

        printf("MEMORY_DEVICE_%u_MEMORY_TECHNOLOGY=%s\n", slot_num,
               code < ELEMENTSOF(technology) && technology[code] ? technology[code] : OUT_OF_SPEC_STR);
}

static void dmi_memory_device_operating_mode_capability(unsigned slot_num, uint16_t code) {
        /* 7.18.7 */
        static const char * const mode[] = {
                [1] = "Other",
                [2] = "Unknown",
                [3] = "Volatile memory",
                [4] = "Byte-accessible persistent memory",
                [5] = "Block-accessible persistent memory",
        };

        if ((code & 0xFFFE) != 0) {
                bool first_element = true;

                printf("MEMORY_DEVICE_%u_MEMORY_OPERATING_MODE_CAPABILITY=", slot_num);
                for (size_t i = 1; i < ELEMENTSOF(mode); i++)
                        if (code & (1 << i)) {
                                printf("%s%s", first_element ? "" : " ", mode[i]);
                                first_element = false;
                        }
                printf("\n");
        }
}

static void dmi_memory_device_manufacturer_id(
                const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        /* 7.18.8 */
        /* 7.18.10 */
        /* LSB is 7-bit Odd Parity number of continuation codes */
        if (code != 0)
                printf("MEMORY_DEVICE_%u_%s=Bank %d, Hex 0x%02X\n", slot_num, attr_suffix,
                       (code & 0x7F) + 1, code >> 8);
}

static void dmi_memory_device_product_id(
                const char *attr_suffix,
                unsigned slot_num, uint16_t code) {
        /* 7.18.9 */
        /* 7.18.11 */
        if (code != 0)
                printf("MEMORY_DEVICE_%u_%s=0x%04X\n", slot_num, attr_suffix, code);
}

static void dmi_memory_device_size_detail(
                const char *attr_suffix,
                unsigned slot_num, uint64_t code) {
        /* 7.18.12 */
        /* 7.18.13 */
        if (!IN_SET(code, 0x0LU, 0xFFFFFFFFFFFFFFFFLU))
                dmi_print_memory_size("MEMORY_DEVICE", attr_suffix, slot_num, code, MEMORY_SIZE_UNIT_BYTES);
}

static void dmi_decode(const struct dmi_header *h,
                       unsigned *next_slot_num) {
        const uint8_t *data = h->data;
        unsigned slot_num;

        /*
         * Note: DMI types 37 and 42 are untested
         */
        switch (h->type) {
        case 16: /* 7.17 Physical Memory Array */
                log_debug("Physical Memory Array");
                if (h->length < 0x0F)
                        break;

                if (data[0x05] != 0x03) /* 7.17.2, Use == "System Memory" */
                        break;

                log_debug("Use: System Memory");
                dmi_memory_array_location(data[0x04]);
                dmi_memory_array_ec_type(data[0x06]);
                if (DWORD(data + 0x07) != 0x80000000)
                        dmi_print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", -1, DWORD(data + 0x07), MEMORY_SIZE_UNIT_KB);
                else if (h->length >= 0x17)
                        dmi_print_memory_size("MEMORY_ARRAY", "MAX_CAPACITY", -1, QWORD(data + 0x0F), MEMORY_SIZE_UNIT_BYTES);

                break;

        case 17: /* 7.18 Memory Device */
                slot_num = *next_slot_num;
                *next_slot_num = slot_num + 1;

                log_debug("Memory Device: %u", slot_num);
                if (h->length < 0x15)
                        break;

                dmi_memory_device_width("TOTAL_WIDTH", slot_num, WORD(data + 0x08));
                dmi_memory_device_width("DATA_WIDTH", slot_num, WORD(data + 0x0A));
                if (h->length >= 0x20 && WORD(data + 0x0C) == 0x7FFF)
                        dmi_memory_device_extended_size(slot_num, DWORD(data + 0x1C));
                else
                        dmi_memory_device_size(slot_num, WORD(data + 0x0C));
                dmi_memory_device_form_factor(slot_num, data[0x0E]);
                dmi_memory_device_set(slot_num, data[0x0F]);
                dmi_memory_device_string("LOCATOR", slot_num, h, data[0x10]);
                dmi_memory_device_string("BANK_LOCATOR", slot_num, h, data[0x11]);
                dmi_memory_device_type(slot_num, data[0x12]);
                dmi_memory_device_type_detail(slot_num, WORD(data + 0x13));
                if (h->length < 0x17)
                        break;

                dmi_memory_device_speed("SPEED_MTS", slot_num, WORD(data + 0x15));
                if (h->length < 0x1B)
                        break;

                dmi_memory_device_string("MANUFACTURER", slot_num, h, data[0x17]);
                dmi_memory_device_string("SERIAL_NUMBER", slot_num, h, data[0x18]);
                dmi_memory_device_string("ASSET_TAG", slot_num, h, data[0x19]);
                dmi_memory_device_string("PART_NUMBER", slot_num, h, data[0x1A]);
                if (h->length < 0x1C)
                        break;

                dmi_memory_device_rank(slot_num, data[0x1B]);
                if (h->length < 0x22)
                        break;

                dmi_memory_device_speed("CONFIGURED_SPEED_MTS", slot_num, WORD(data + 0x20));
                if (h->length < 0x28)
                        break;

                dmi_memory_device_voltage_value("MINIMUM_VOLTAGE", slot_num, WORD(data + 0x22));
                dmi_memory_device_voltage_value("MAXIMUM_VOLTAGE", slot_num, WORD(data + 0x24));
                dmi_memory_device_voltage_value("CONFIGURED_VOLTAGE", slot_num, WORD(data + 0x26));
                if (h->length < 0x34)
                        break;

                dmi_memory_device_technology(slot_num, data[0x28]);
                dmi_memory_device_operating_mode_capability(slot_num, WORD(data + 0x29));
                dmi_memory_device_string("FIRMWARE_VERSION", slot_num, h, data[0x2B]);
                dmi_memory_device_manufacturer_id("MODULE_MANUFACTURER_ID", slot_num, WORD(data + 0x2C));
                dmi_memory_device_product_id("MODULE_PRODUCT_ID", slot_num, WORD(data + 0x2E));
                dmi_memory_device_manufacturer_id("MEMORY_SUBSYSTEM_CONTROLLER_MANUFACTURER_ID",
                                                  slot_num, WORD(data + 0x30));
                dmi_memory_device_product_id("MEMORY_SUBSYSTEM_CONTROLLER_PRODUCT_ID",
                                             slot_num, WORD(data + 0x32));
                if (h->length < 0x3C)
                        break;

                dmi_memory_device_size_detail("NON_VOLATILE_SIZE", slot_num, QWORD(data + 0x34));
                if (h->length < 0x44)
                        break;

                dmi_memory_device_size_detail("VOLATILE_SIZE", slot_num, QWORD(data + 0x3C));
                if (h->length < 0x4C)
                        break;

                dmi_memory_device_size_detail("CACHE_SIZE", slot_num, QWORD(data + 0x44));
                if (h->length < 0x54)
                        break;

                dmi_memory_device_size_detail("LOGICAL_SIZE", slot_num, QWORD(data + 0x4C));

                break;
        }
}

static void dmi_table_decode(const uint8_t *buf, size_t len, uint16_t num) {
        const uint8_t *data = buf;
        unsigned next_slot_num = 0;

        /* 4 is the length of an SMBIOS structure header */
        for (uint16_t i = 0; (i < num || num == 0) && data + 4 <= buf + len; i++) {
                struct dmi_header h = (struct dmi_header) {
                        .type = data[0],
                        .length = data[1],
                        .handle = WORD(data + 2),
                        .data = data,
                };
                bool display = !IN_SET(h.type, 126, 127);
                const uint8_t *next;

                /* If a short entry is found (less than 4 bytes), not only it
                 * is invalid, but we cannot reliably locate the next entry.
                 * Better stop at this point, and let the user know their
                 * table is broken. */
                if (h.length < 4)
                        break;

                /* In quiet mode, stop decoding at end of table marker */
                if (h.type == 127)
                        break;

                /* Look for the next handle */
                next = data + h.length;
                while ((size_t)(next - buf + 1) < len && (next[0] != 0 || next[1] != 0))
                        next++;
                next += 2;

                /* Make sure the whole structure fits in the table */
                if ((size_t)(next - buf) > len)
                        break;

                if (display)
                        dmi_decode(&h, &next_slot_num);

                data = next;
        }
        if (next_slot_num > 0)
                printf("MEMORY_ARRAY_NUM_DEVICES=%u\n", next_slot_num);
}

static int dmi_table(int64_t base, uint32_t len, uint16_t num, const char *devmem, bool no_file_offset) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t size;
        int r;

        /*
         * When reading from sysfs or from a dump file, the file may be
         * shorter than announced. For SMBIOS v3 this is expected, as we
         * only know the maximum table size, not the actual table size.
         * For older implementations (and for SMBIOS v3 too), this
         * would be the result of the kernel truncating the table on
         * parse error.
         */
        r = read_full_file_full(AT_FDCWD, devmem, no_file_offset ? 0 : base, len,
                                0, NULL, (char **) &buf, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read table: %m");

        dmi_table_decode(buf, size, num);

        return 0;
}

/* Same thing for SMBIOS3 entry points */
static int smbios3_decode(const uint8_t *buf, const char *devmem, bool no_file_offset) {
        uint64_t offset;

        /* Don't let checksum run beyond the buffer */
        if (buf[0x06] > 0x20)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Entry point length too large (%"PRIu8" bytes, expected %u).",
                                       buf[0x06], 0x18U);

        if (!verify_checksum(buf, buf[0x06]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to verify checksum.");

        offset = QWORD(buf + 0x10);

#if __SIZEOF_SIZE_T__ != 8
        if (!no_file_offset && (offset >> 32) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "64-bit addresses not supported on 32-bit systems.");
#endif

        return dmi_table(offset, DWORD(buf + 0x0C), 0, devmem, no_file_offset);
}

static int smbios_decode(const uint8_t *buf, const char *devmem, bool no_file_offset) {
        /* Don't let checksum run beyond the buffer */
        if (buf[0x05] > 0x20)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Entry point length too large (%"PRIu8" bytes, expected %u).",
                                       buf[0x05], 0x1FU);

        if (!verify_checksum(buf, buf[0x05])
            || memcmp(buf + 0x10, "_DMI_", 5) != 0
            || !verify_checksum(buf + 0x10, 0x0F))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to verify checksum.");

        return dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
                         devmem, no_file_offset);
}

static int legacy_decode(const uint8_t *buf, const char *devmem, bool no_file_offset) {
        if (!verify_checksum(buf, 0x0F))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to verify checksum.");

        return dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                         devmem, no_file_offset);
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "  -F --from-dump FILE  Read DMI information from a binary file\n"
               "  -h --help            Show this help text\n"
               "     --version         Show package version\n",
               program_invocation_short_name);
        return 0;
}

static int parse_argv(int argc, char * const *argv) {
        static const struct option options[] = {
                { "from-dump", required_argument, NULL, 'F' },
                { "version",   no_argument,       NULL, 'V' },
                { "help",      no_argument,       NULL, 'h' },
                { "version",   no_argument,       NULL, 'v' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "F:hV", options, NULL)) >= 0)
                switch (c) {
                case 'F':
                        arg_source_file = optarg;
                        break;
                case 'V':
                        return version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                case 'v':
                        return version();
                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char* const* argv) {
        _cleanup_free_ uint8_t *buf = NULL;
        bool no_file_offset = false;
        size_t size;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        udev_parse_config();
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Read from dump if so instructed */
        r = read_full_file_full(AT_FDCWD,
                                arg_source_file ?: SYS_ENTRY_FILE,
                                0, 0x20, 0, NULL, (char **) &buf, &size);
        if (r < 0)
                return log_full_errno(!arg_source_file && r == -ENOENT ? LOG_DEBUG : LOG_ERR,
                                      r, "Reading \"%s\" failed: %m",
                                      arg_source_file ?: SYS_ENTRY_FILE);

        if (!arg_source_file) {
                arg_source_file = SYS_TABLE_FILE;
                no_file_offset = true;
        }

        if (size >= 24 && memory_startswith(buf, size, "_SM3_"))
                return smbios3_decode(buf, arg_source_file, no_file_offset);
        if (size >= 31 && memory_startswith(buf, size, "_SM_"))
                return smbios_decode(buf, arg_source_file, no_file_offset);
        if (size >= 15 && memory_startswith(buf, size, "_DMI_"))
                return legacy_decode(buf, arg_source_file, no_file_offset);

        return -EINVAL;
}

DEFINE_MAIN_FUNCTION(run);
