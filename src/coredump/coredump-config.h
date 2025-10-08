/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "coredump-forward.h"

typedef enum CoredumpStorage {
        COREDUMP_STORAGE_NONE,
        COREDUMP_STORAGE_EXTERNAL,
        COREDUMP_STORAGE_JOURNAL,
        _COREDUMP_STORAGE_MAX,
        _COREDUMP_STORAGE_INVALID = -EINVAL,
} CoredumpStorage;

struct CoredumpConfig {
        CoredumpStorage storage;
        bool compress;
        uint64_t process_size_max;
        uint64_t external_size_max;
        uint64_t journal_size_max;
        uint64_t keep_free;
        uint64_t max_use;
        bool enter_namespace;
};

int coredump_parse_config(CoredumpConfig *config);
uint64_t coredump_storage_size_max(const CoredumpConfig *config);

/* Defined in generated coredump-gperf.c */
const struct ConfigPerfItem* coredump_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_coredump_storage);
