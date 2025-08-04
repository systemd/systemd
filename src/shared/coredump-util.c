/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <sys/prctl.h>

#include "alloc-util.h"
#include "coredump-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "log.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unaligned.h"
#include "virt.h"

int set_dumpable(SuidDumpMode mode) {
        /* Cast mode explicitly to long, because prctl wants longs but is varargs. */
        return RET_NERRNO(prctl(PR_SET_DUMPABLE, (long) mode));
}

static const char *const coredump_filter_table[_COREDUMP_FILTER_MAX] = {
        [COREDUMP_FILTER_PRIVATE_ANONYMOUS]   = "private-anonymous",
        [COREDUMP_FILTER_SHARED_ANONYMOUS]    = "shared-anonymous",
        [COREDUMP_FILTER_PRIVATE_FILE_BACKED] = "private-file-backed",
        [COREDUMP_FILTER_SHARED_FILE_BACKED]  = "shared-file-backed",
        [COREDUMP_FILTER_ELF_HEADERS]         = "elf-headers",
        [COREDUMP_FILTER_PRIVATE_HUGE]        = "private-huge",
        [COREDUMP_FILTER_SHARED_HUGE]         = "shared-huge",
        [COREDUMP_FILTER_PRIVATE_DAX]         = "private-dax",
        [COREDUMP_FILTER_SHARED_DAX]          = "shared-dax",
};

DEFINE_STRING_TABLE_LOOKUP(coredump_filter, CoredumpFilter);

int coredump_filter_mask_from_string(const char *s, uint64_t *ret) {
        uint64_t m = 0;

        assert(s);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *n = NULL;
                CoredumpFilter v;
                int r;

                r = extract_first_word(&s, &n, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(n, "default")) {
                        m |= COREDUMP_FILTER_MASK_DEFAULT;
                        continue;
                }

                if (streq(n, "all")) {
                        m = COREDUMP_FILTER_MASK_ALL;
                        continue;
                }

                v = coredump_filter_from_string(n);
                if (v >= 0) {
                        m |= 1u << v;
                        continue;
                }

                uint64_t x;
                r = safe_atoux64(n, &x);
                if (r < 0)
                        return r;

                m |= x;
        }

        *ret = m;
        return 0;
}

#define _DEFINE_PARSE_AUXV(size, type, unaligned_read)                  \
        static int parse_auxv##size(                                    \
                        int log_level,                                  \
                        const void *auxv,                               \
                        size_t size_bytes,                              \
                        int *at_secure,                                 \
                        uid_t *uid,                                     \
                        uid_t *euid,                                    \
                        gid_t *gid,                                     \
                        gid_t *egid) {                                  \
                                                                        \
                assert(auxv || size_bytes == 0);                        \
                assert(at_secure);                                      \
                assert(uid);                                            \
                assert(euid);                                           \
                assert(gid);                                            \
                assert(egid);                                           \
                                                                        \
                if (size_bytes % (2 * sizeof(type)) != 0)               \
                        return log_full_errno(log_level,                \
                                              SYNTHETIC_ERRNO(EIO),     \
                                              "Incomplete auxv structure (%zu bytes).", \
                                              size_bytes);              \
                                                                        \
                size_t words = size_bytes / sizeof(type);               \
                                                                        \
                /* Note that we set output variables even on error. */  \
                                                                        \
                for (size_t i = 0; i + 1 < words; i += 2) {             \
                        type key, val;                                  \
                                                                        \
                        key = unaligned_read((uint8_t*) auxv + i * sizeof(type)); \
                        val = unaligned_read((uint8_t*) auxv + (i + 1) * sizeof(type)); \
                                                                        \
                        switch (key) {                                  \
                        case AT_SECURE:                                 \
                                *at_secure = val != 0;                  \
                                break;                                  \
                        case AT_UID:                                    \
                                *uid = val;                             \
                                break;                                  \
                        case AT_EUID:                                   \
                                *euid = val;                            \
                                break;                                  \
                        case AT_GID:                                    \
                                *gid = val;                             \
                                break;                                  \
                        case AT_EGID:                                   \
                                *egid = val;                            \
                                break;                                  \
                        case AT_NULL:                                   \
                                if (val != 0)                           \
                                        goto error;                     \
                                return 0;                               \
                        }                                               \
                }                                                       \
        error:                                                          \
                return log_full_errno(log_level,                        \
                                      SYNTHETIC_ERRNO(ENODATA),         \
                                      "AT_NULL terminator not found, cannot parse auxv structure."); \
        }

#define DEFINE_PARSE_AUXV(size)                                         \
        _DEFINE_PARSE_AUXV(size, uint##size##_t, unaligned_read_ne##size)

DEFINE_PARSE_AUXV(32);
DEFINE_PARSE_AUXV(64);

int parse_auxv(int log_level,
               uint8_t elf_class,
               const void *auxv,
               size_t size_bytes,
               int *at_secure,
               uid_t *uid,
               uid_t *euid,
               gid_t *gid,
               gid_t *egid) {

        switch (elf_class) {
        case ELFCLASS64:
                return parse_auxv64(log_level, auxv, size_bytes, at_secure, uid, euid, gid, egid);
        case ELFCLASS32:
                return parse_auxv32(log_level, auxv, size_bytes, at_secure, uid, euid, gid, egid);
        default:
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                                      "Unknown ELF class %d.", elf_class);
        }
}

int set_coredump_filter(uint64_t value) {
        char t[HEXADECIMAL_STR_MAX(uint64_t)];

        xsprintf(t, "0x%"PRIx64, value);

        return write_string_file("/proc/self/coredump_filter", t,
                                 WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_DISABLE_BUFFER);
}

/* Turn off core dumps but only if we're running outside of a container. */
void disable_coredumps(void) {
        int r;

        if (detect_container() > 0)
                return;

        r = write_string_file("/proc/sys/kernel/core_pattern", "|/bin/false", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_debug_errno(r, "Failed to turn off coredumps, ignoring: %m");
}
