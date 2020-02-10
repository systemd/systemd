/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct HierarchyTokenBucket {
        QDisc meta;

        uint32_t default_class;
} HierarchyTokenBucket;

DEFINE_QDISC_CAST(HTB, HierarchyTokenBucket);
extern const QDiscVTable htb_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_hierarchy_token_bucket_default_class);
