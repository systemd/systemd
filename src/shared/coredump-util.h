/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum CoredumpFilter {
        COREDUMP_FILTER_PRIVATE_ANONYMOUS = 0,
        COREDUMP_FILTER_SHARED_ANONYMOUS,
        COREDUMP_FILTER_PRIVATE_FILE_BACKED,
        COREDUMP_FILTER_SHARED_FILE_BACKED,
        COREDUMP_FILTER_ELF_HEADERS,
        COREDUMP_FILTER_PRIVATE_HUGE,
        COREDUMP_FILTER_SHARED_HUGE,
        COREDUMP_FILTER_PRIVATE_DAX,
        COREDUMP_FILTER_SHARED_DAX,
        _COREDUMP_FILTER_MAX,
        _COREDUMP_FILTER_INVALID = -EINVAL,
} CoredumpFilter;

#define COREDUMP_FILTER_MASK_DEFAULT (1u << COREDUMP_FILTER_PRIVATE_ANONYMOUS | \
                                      1u << COREDUMP_FILTER_SHARED_ANONYMOUS | \
                                      1u << COREDUMP_FILTER_ELF_HEADERS | \
                                      1u << COREDUMP_FILTER_PRIVATE_HUGE)

/* The kernel doesn't like UINT64_MAX and returns ERANGE, use UINT32_MAX to support future new flags */
#define COREDUMP_FILTER_MASK_ALL UINT32_MAX

typedef enum SuidDumpMode {
        SUID_DUMP_DISABLE = 0,  /* PR_SET_DUMPABLE(2const) */
        SUID_DUMP_USER    = 1,  /* PR_SET_DUMPABLE(2const) */
        SUID_DUMP_SAFE    = 2,  /* https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#suid-dumpable */
        _SUID_DUMP_MODE_MAX,
} SuidDumpMode;

int set_dumpable(SuidDumpMode mode);

const char* coredump_filter_to_string(CoredumpFilter i) _const_;
CoredumpFilter coredump_filter_from_string(const char *s) _pure_;
int coredump_filter_mask_from_string(const char *s, uint64_t *ret);

int parse_auxv(int log_level,
               uint8_t elf_class,
               const void *auxv,
               size_t size_bytes,
               int *at_secure,
               uid_t *uid,
               uid_t *euid,
               gid_t *gid,
               gid_t *egid);

int set_coredump_filter(uint64_t value);
void disable_coredumps(void);
