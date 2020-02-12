/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"
#include "tclass.h"

typedef struct HierarchyTokenBucket {
        QDisc meta;

        uint32_t default_class;
} HierarchyTokenBucket;

DEFINE_QDISC_CAST(HTB, HierarchyTokenBucket);
extern const QDiscVTable htb_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_default_class);

typedef struct HierarchyTokenBucketClass {
        TClass meta;

        uint32_t priority;
        uint64_t rate;
        uint64_t ceil_rate;
} HierarchyTokenBucketClass;

DEFINE_TCLASS_CAST(HTB, HierarchyTokenBucketClass);
extern const TClassVTable htb_tclass_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_u32);
CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_rate);
