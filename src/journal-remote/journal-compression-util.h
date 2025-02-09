/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "compress.h"
#include "conf-parser.h"

typedef struct CompressionConfig {
        Compression algorithm;
        int level;
} CompressionConfig;

CONFIG_PARSER_PROTOTYPE(config_parse_compression);
