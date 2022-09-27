/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-gpt.h"
#include "sd-id128.h"

#include "architecture.h"
#include "id128-util.h"

/* maximum length of gpt label */
#define GPT_LABEL_MAX 36

typedef enum {
        GPT_ROOT,
        GPT_ROOT_VERITY,
        GPT_ROOT_VERITY_SIG,
        GPT_USR,
        GPT_USR_VERITY,
        GPT_USR_VERITY_SIG,
        GPT_ESP,
        GPT_XBOOTLDR,
        GPT_SWAP,
        GPT_HOME,
        GPT_SRV,
        GPT_VAR,
        GPT_TMP,
        GPT_USER_HOME,
        GPT_LINUX_GENERIC,
        _GPT_PARTITION_IDENTIFIER_MAX,
        _GPT_PARTITION_IDENTIFIER_INVALID = -1,
} GptPartitionIdentifier;

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
        GptPartitionIdentifier id;
} GptPartitionType;

extern const GptPartitionType gpt_partition_type_table[];

int gpt_partition_label_valid(const char *s);

bool gpt_partition_type_is_root(sd_id128_t id);
bool gpt_partition_type_is_root_verity(sd_id128_t id);
bool gpt_partition_type_is_root_verity_sig(sd_id128_t id);
bool gpt_partition_type_is_usr(sd_id128_t id);
bool gpt_partition_type_is_usr_verity(sd_id128_t id);
bool gpt_partition_type_is_usr_verity_sig(sd_id128_t id);

const char* gpt_partition_type_mount_point(sd_id128_t id);

bool gpt_partition_type_knows_read_only(sd_id128_t id);
bool gpt_partition_type_knows_growfs(sd_id128_t id);
bool gpt_partition_type_knows_no_auto(sd_id128_t id);
