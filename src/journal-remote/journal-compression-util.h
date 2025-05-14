/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "compress.h"
#include "conf-parser-forward.h"
#include "forward.h"

typedef struct CompressionConfig {
        Compression algorithm;
        int level;
} CompressionConfig;

int compression_configs_mangle(OrderedHashmap **configs);

CONFIG_PARSER_PROTOTYPE(config_parse_compression);
