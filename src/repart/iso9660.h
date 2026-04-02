/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "sparse-endian.h"

/* ISO9660 is 5 blocks:
 * - Primary descriptor
 * - El torito descriptor
 * - Terminal descriptor
 * - El Torito boot catalog
 * - Root directory
 */
#define ISO9660_BLOCK_SIZE 2048U
#define ISO9660_START 16U
#define ISO9660_PRIMARY_DESCRIPTOR (ISO9660_START+0U)
#define ISO9660_ELTORITO_DESCRIPTOR (ISO9660_START+1U)
#define ISO9660_TERMINAL_DESCRIPTOR (ISO9660_START+2U)
#define ISO9660_BOOT_CATALOG (ISO9660_START+3U)
#define ISO9660_ROOT_DIRECTORY (ISO9660_START+4U)
#define ISO9660_SIZE 5U

struct _packed_ iso9660_volume_descriptor_header {
        uint8_t type;
        char identifier[5];
        uint8_t version;
};

struct _packed_ iso9660_terminal_descriptor {
        struct iso9660_volume_descriptor_header header;
        uint8_t data[2041];
};
assert_cc(sizeof(struct iso9660_terminal_descriptor) == 2048);

struct _packed_ iso9660_datetime {
        char year[4];
        char month[2];
        char day[2];
        char hour[2];
        char minute[2];
        char second[2];
        char deci[2];
        int8_t zone;
};

struct _packed_ iso9660_eltorito_descriptor {
        struct iso9660_volume_descriptor_header header;

        char boot_system_identifier[32];
        uint8_t unused_1[32];
        le32_t boot_catalog_sector;
        uint8_t unused_2[1973];
};

assert_cc(sizeof(struct iso9660_eltorito_descriptor) == 2048);

struct _packed_ iso9660_dir_time {
        uint8_t year;
        uint8_t month;
        uint8_t day;
        uint8_t hour;
        uint8_t minute;
        uint8_t second;
        int8_t offset;
};

struct _packed_ iso9660_directory_entry {
        uint8_t len;
        uint8_t xattr_len;
        le32_t extent_loc_little;
        be32_t extent_loc_big;
        le32_t data_len_little;
        be32_t data_len_big;
        struct iso9660_dir_time time;
        uint8_t flags;
        uint8_t unit_size;
        uint8_t gap_size;
        le16_t volume_seq_num_little;
        be16_t volume_seq_num_big;
        uint8_t ident_len;
        char ident[1]; /* variable */
};

struct _packed_ iso9660_primary_volume_descriptor {
        struct iso9660_volume_descriptor_header header;

        uint8_t unused_1;
        char system_identifier[32];
        char volume_identifier[32];
        uint8_t unused_2[8];
        le32_t volume_space_size_little;
        be32_t volume_space_size_big;
        uint8_t unused_3[32];

        le16_t volume_set_size_little;
        be16_t volume_set_size_big;
        le16_t volume_sequence_number_little;
        be16_t volume_sequence_number_big;
        le16_t logical_block_size_little;
        be16_t logical_block_size_big;

        le32_t path_table_size_little;
        be32_t path_table_size_big;

        le32_t path_table_little;
        le32_t opt_path_table_little;

        be32_t path_table_big;
        be32_t opt_path_table_big;

        struct iso9660_directory_entry root_directory_entry;

        char volume_set_identifier[128];
        char publisher_identifier[128];
        char data_preparer_identifier[128];
        char application_identifier[128];

        char copyright_file_identifier[37];
        char abstract_file_identifier[37];
        char bibliographic_file_identifier[37];

        struct iso9660_datetime volume_creation_date;
        struct iso9660_datetime volume_modification_date;
        struct iso9660_datetime volume_expiration_date;
        struct iso9660_datetime volume_effective_date;

        uint8_t file_structure_version; /* 1 */
        uint8_t unused_5;
        char application_used[512];
        uint8_t reserved[653];
};
assert_cc(sizeof(struct iso9660_primary_volume_descriptor) == 2048);

struct _packed_ el_torito_validation_entry {
        uint8_t header_indicator;
        uint8_t platform;
        uint8_t reserved[2];
        char id_string[24];
        le16_t checksum;
        uint8_t key_bytes[2];
};

struct _packed_ el_torito_initial_entry {
        uint8_t boot_indicator;
        uint8_t boot_media_type;
        le16_t load_segment;
        uint8_t system_type;
        uint8_t unused_1[1];
        le16_t sector_count;
        le32_t load_rba;
        uint8_t unused_2[20];
};

struct _packed_ el_torito_section_header {
        uint8_t header_indicator;
        uint8_t platform;
        le16_t nentries;
        char id_string[28];
};

void iso9660_datetime_zero(struct iso9660_datetime *ret);
int iso9660_datetime_from_usec(usec_t usec, bool utc, struct iso9660_datetime *ret);
int iso9660_dir_datetime_from_usec(usec_t usec, bool utc, struct iso9660_dir_time *ret);
int iso9660_set_string(char target[], size_t len, const char *source, bool allow_a_chars);

static inline void iso9660_set_const_string(char target[], size_t len, const char *source, bool allow_a_chars) {
        assert_se(iso9660_set_string(target, len, source, allow_a_chars) == 0);
}

bool iso9660_volume_name_valid(const char *name);
bool iso9660_system_name_valid(const char *name);
bool iso9660_publisher_name_valid(const char *name);
