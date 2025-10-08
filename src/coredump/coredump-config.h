/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

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
