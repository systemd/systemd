/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "tclass.h"

typedef struct HierarchyTokenBucket {
        QDisc meta;

        uint32_t default_class;
        uint32_t rate_to_quantum;
} HierarchyTokenBucket;

DEFINE_QDISC_CAST(HTB, HierarchyTokenBucket);
extern const QDiscVTable htb_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_default_class);
CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_u32);

typedef struct HierarchyTokenBucketClass {
        TClass meta;

        uint32_t priority;
        uint32_t quantum;
        uint32_t mtu;
        uint16_t overhead;
        uint64_t rate;
        uint32_t buffer;
        uint64_t ceil_rate;
        uint32_t ceil_buffer;
} HierarchyTokenBucketClass;

DEFINE_TCLASS_CAST(HTB, HierarchyTokenBucketClass);
extern const TClassVTable htb_tclass_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_class_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_class_size);
CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_class_rate);
