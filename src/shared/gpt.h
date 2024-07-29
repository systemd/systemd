/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <uchar.h>

#include "sd-gpt.h"
#include "sd-id128.h"

#include "architecture.h"
#include "id128-util.h"
#include "sparse-endian.h"

/* maximum length of gpt label */
#define GPT_LABEL_MAX 36

typedef enum PartitionDesignator {
        PARTITION_ROOT, /* Primary architecture */
        PARTITION_USR,
        PARTITION_HOME,
        PARTITION_SRV,
        PARTITION_ESP,
        PARTITION_XBOOTLDR,
        PARTITION_SWAP,
        PARTITION_ROOT_VERITY, /* verity data for the PARTITION_ROOT partition */
        PARTITION_USR_VERITY,
        PARTITION_ROOT_VERITY_SIG, /* PKCS#7 signature for root hash for the PARTITION_ROOT partition */
        PARTITION_USR_VERITY_SIG,
        PARTITION_TMP,
        PARTITION_VAR,
        _PARTITION_DESIGNATOR_MAX,
        _PARTITION_DESIGNATOR_INVALID = -EINVAL,
} PartitionDesignator;

bool partition_designator_is_versioned(PartitionDesignator d);

PartitionDesignator partition_verity_of(PartitionDesignator p);
PartitionDesignator partition_verity_sig_of(PartitionDesignator p);
PartitionDesignator partition_verity_to_data(PartitionDesignator d);
PartitionDesignator partition_verity_sig_to_data(PartitionDesignator d);

const char* partition_designator_to_string(PartitionDesignator d) _const_;
PartitionDesignator partition_designator_from_string(const char *name) _pure_;

const char* gpt_partition_type_uuid_to_string(sd_id128_t id);
const char* gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static SD_ID128_UUID_STRING_MAX]);

#define GPT_PARTITION_TYPE_UUID_TO_STRING_HARDER(id) \
        gpt_partition_type_uuid_to_string_harder((id), (char[SD_ID128_UUID_STRING_MAX]) {})

Architecture gpt_partition_type_uuid_to_arch(sd_id128_t id);

typedef struct GptPartitionType {
        sd_id128_t uuid;
        const char *name;
        Architecture arch;
        PartitionDesignator designator;
} GptPartitionType;

extern const GptPartitionType gpt_partition_type_table[];

int gpt_partition_label_valid(const char *s);

GptPartitionType gpt_partition_type_from_uuid(sd_id128_t id);
int gpt_partition_type_from_string(const char *s, GptPartitionType *ret);

GptPartitionType gpt_partition_type_override_architecture(GptPartitionType type, Architecture arch);

const char* gpt_partition_type_mountpoint_nulstr(GptPartitionType type);

bool gpt_partition_type_knows_read_only(GptPartitionType type);
bool gpt_partition_type_knows_growfs(GptPartitionType type);
bool gpt_partition_type_knows_no_auto(GptPartitionType type);
bool gpt_partition_type_has_filesystem(GptPartitionType type);

typedef struct {
        uint8_t partition_type_guid[16];
        uint8_t unique_partition_guid[16];
        le64_t starting_lba;
        le64_t ending_lba;
        le64_t attributes;
        char16_t partition_name[36];
} _packed_ GptPartitionEntry;

typedef struct {
        char signature[8];
        le32_t revision;
        le32_t header_size;
        le32_t crc32;
        le32_t reserved;
        le64_t my_lba;
        le64_t alternate_lba;
        le64_t first_usable_lba;
        le64_t last_usable_lba;
        uint8_t disk_guid[16];
        le64_t partition_entry_lba;
        le32_t number_of_partition_entries;
        le32_t size_of_partition_entry;
        le32_t partition_entry_array_crc32;
} _packed_ GptHeader;

bool gpt_header_has_signature(const GptHeader *p);
