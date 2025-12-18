/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "coredump-forward.h"

/* The maximum size up to which we process coredumps. We use 1G on 32-bit systems, and 32G on 64-bit systems */
#if __SIZEOF_POINTER__ == 4
#define PROCESS_SIZE_MAX ((uint64_t) (1LLU*1024LLU*1024LLU*1024LLU))
#elif __SIZEOF_POINTER__ == 8
#define PROCESS_SIZE_MAX ((uint64_t) (32LLU*1024LLU*1024LLU*1024LLU))
#else
#error "Unexpected pointer size"
#endif

/* The maximum size up to which we leave the coredump around on disk */
#define EXTERNAL_SIZE_MAX PROCESS_SIZE_MAX

/* The maximum size up to which we store the coredump in the journal */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define JOURNAL_SIZE_MAX ((size_t) (767LU*1024LU*1024LU))
#else
/* oss-fuzz limits memory usage. */
#define JOURNAL_SIZE_MAX ((size_t) (10LU*1024LU*1024LU))
#endif

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

#define COREDUMP_CONFIG_NULL                            \
        (CoredumpConfig) {                              \
                .storage = COREDUMP_STORAGE_EXTERNAL,   \
                .compress = true,                       \
                .process_size_max = PROCESS_SIZE_MAX,   \
                .external_size_max = EXTERNAL_SIZE_MAX, \
                .journal_size_max = JOURNAL_SIZE_MAX,   \
                .keep_free = UINT64_MAX,                \
                .max_use = UINT64_MAX,                  \
        }

int coredump_parse_config(CoredumpConfig *config);
uint64_t coredump_storage_size_max(const CoredumpConfig *config);

/* Defined in generated coredump-gperf.c */
const struct ConfigPerfItem* coredump_gperf_lookup(const char *str, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_coredump_storage);
