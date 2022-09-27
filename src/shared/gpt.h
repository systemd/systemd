/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-gpt.h"
#include "sd-id128.h"

#include "architecture.h"
#include "id128-util.h"

/* maximum length of gpt label */
#define GPT_LABEL_MAX 36

typedef enum PartitionDesignator {
        PARTITION_ROOT,
        PARTITION_ROOT_SECONDARY,  /* Secondary architecture */
        PARTITION_ROOT_OTHER,
        PARTITION_USR,
        PARTITION_USR_SECONDARY,
        PARTITION_USR_OTHER,
        PARTITION_HOME,
        PARTITION_SRV,
        PARTITION_ESP,
        PARTITION_XBOOTLDR,
        PARTITION_SWAP,
        PARTITION_ROOT_VERITY, /* verity data for the PARTITION_ROOT partition */
        PARTITION_ROOT_SECONDARY_VERITY, /* verity data for the PARTITION_ROOT_SECONDARY partition */
        PARTITION_ROOT_OTHER_VERITY,
        PARTITION_USR_VERITY,
        PARTITION_USR_SECONDARY_VERITY,
        PARTITION_USR_OTHER_VERITY,
        PARTITION_ROOT_VERITY_SIG, /* PKCS#7 signature for root hash for the PARTITION_ROOT partition */
        PARTITION_ROOT_SECONDARY_VERITY_SIG, /* ditto for the PARTITION_ROOT_SECONDARY partition */
        PARTITION_ROOT_OTHER_VERITY_SIG,
        PARTITION_USR_VERITY_SIG,
        PARTITION_USR_SECONDARY_VERITY_SIG,
        PARTITION_USR_OTHER_VERITY_SIG,
        PARTITION_TMP,
        PARTITION_VAR,
        PARTITION_USER_HOME,
        PARTITION_LINUX_GENERIC,
        _PARTITION_DESIGNATOR_MAX,
        _PARTITION_DESIGNATOR_INVALID = -EINVAL,
} PartitionDesignator;

bool partition_designator_is_versioned(PartitionDesignator d);

PartitionDesignator partition_verity_of(PartitionDesignator p);
PartitionDesignator partition_verity_sig_of(PartitionDesignator p);
PartitionDesignator partition_root_of_arch(Architecture arch);
PartitionDesignator partition_usr_of_arch(Architecture arch);

const char* partition_designator_to_string(PartitionDesignator d) _const_;
PartitionDesignator partition_designator_from_string(const char *name) _pure_;

const char *gpt_partition_type_uuid_to_string(sd_id128_t id);
const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static SD_ID128_UUID_STRING_MAX]);
int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret);

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

bool gpt_partition_type_is_root(sd_id128_t id);
bool gpt_partition_type_is_root_verity(sd_id128_t id);
bool gpt_partition_type_is_root_verity_sig(sd_id128_t id);
bool gpt_partition_type_is_usr(sd_id128_t id);
bool gpt_partition_type_is_usr_verity(sd_id128_t id);
bool gpt_partition_type_is_usr_verity_sig(sd_id128_t id);

const char *gpt_partition_type_mountpoint(sd_id128_t id);

bool gpt_partition_type_knows_read_only(sd_id128_t id);
bool gpt_partition_type_knows_growfs(sd_id128_t id);
bool gpt_partition_type_knows_no_auto(sd_id128_t id);
