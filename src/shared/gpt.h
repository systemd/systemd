/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-gpt.h"
#include "sd-id128.h"

#include "architecture.h"
#include "id128-util.h"

/* maximum length of gpt label */
#define GPT_LABEL_MAX 36

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

        bool is_root:1;
        bool is_root_verity:1;
        bool is_root_verity_sig:1;
        bool is_usr:1;
        bool is_usr_verity:1;
        bool is_usr_verity_sig:1;
} GptPartitionType;

extern const GptPartitionType gpt_partition_type_table[];

int gpt_partition_label_valid(const char *s);

bool gpt_partition_type_is_root(sd_id128_t id);
bool gpt_partition_type_is_root_verity(sd_id128_t id);
bool gpt_partition_type_is_root_verity_sig(sd_id128_t id);
bool gpt_partition_type_is_usr(sd_id128_t id);
bool gpt_partition_type_is_usr_verity(sd_id128_t id);
bool gpt_partition_type_is_usr_verity_sig(sd_id128_t id);

bool gpt_partition_type_knows_read_only(sd_id128_t id);
bool gpt_partition_type_knows_growfs(sd_id128_t id);
bool gpt_partition_type_knows_no_auto(sd_id128_t id);
