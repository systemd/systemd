/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

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

extern CoredumpStorage arg_storage;
extern bool arg_compress;
extern uint64_t arg_process_size_max;
extern uint64_t arg_external_size_max;
extern uint64_t arg_journal_size_max;
extern uint64_t arg_keep_free;
extern uint64_t arg_max_use;
extern bool arg_enter_namespace;

int coredump_parse_config(void);
uint64_t coredump_storage_size_max(void);
