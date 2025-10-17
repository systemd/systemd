/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "coredump-config.h"
#include "format-util.h"
#include "journal-importer.h"
#include "log.h"
#include "string-table.h"
#include "string-util.h"

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

/* Make sure to not make this larger than the maximum journal entry
 * size. See DATA_SIZE_MAX in journal-importer.h. */
assert_cc(JOURNAL_SIZE_MAX <= DATA_SIZE_MAX);

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE]     = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL]  = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage);

int coredump_parse_config(CoredumpConfig *config) {
        int r;

        assert(config);

        *config = (CoredumpConfig) {
                .storage = COREDUMP_STORAGE_EXTERNAL,
                .compress = true,
                .process_size_max = PROCESS_SIZE_MAX,
                .external_size_max = EXTERNAL_SIZE_MAX,
                .journal_size_max = JOURNAL_SIZE_MAX,
                .keep_free = UINT64_MAX,
                .max_use = UINT64_MAX,
        };

        r = config_parse_standard_file_with_dropins(
                        "systemd/coredump.conf",
                        "Coredump\0",
                        config_item_perf_lookup,
                        coredump_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        config);
        if (r < 0)
                return r;

        /* Let's make sure we fix up the maximum size we send to the journal here on the client side, for
         * efficiency reasons. journald wouldn't accept anything larger anyway. */
        if (config->journal_size_max > JOURNAL_SIZE_MAX) {
                log_full(config->storage == COREDUMP_STORAGE_JOURNAL ? LOG_WARNING : LOG_DEBUG,
                         "JournalSizeMax= set to larger value (%s) than journald would accept (%s), lowering automatically.",
                         FORMAT_BYTES(config->journal_size_max), FORMAT_BYTES(JOURNAL_SIZE_MAX));
                config->journal_size_max = JOURNAL_SIZE_MAX;
        }

#if !HAVE_DWFL_SET_SYSROOT
        if (config->enter_namespace) {
                log_warning("EnterNamespace= is enabled but libdw does not support dwfl_set_sysroot(), disabling.");
                config->enter_namespace = false;
        }
#endif

        log_debug("Selected storage '%s'.", coredump_storage_to_string(config->storage));
        log_debug("Selected compression %s.", yes_no(config->compress));

        return 0;
}

uint64_t coredump_storage_size_max(const CoredumpConfig *config) {
        switch (config->storage) {
        case COREDUMP_STORAGE_NONE:
                return 0;
        case COREDUMP_STORAGE_EXTERNAL:
                return config->external_size_max;
        case COREDUMP_STORAGE_JOURNAL:
                return config->journal_size_max;
        default:
                assert_not_reached();
        }
}
