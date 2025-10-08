/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "coredump-config.h"
#include "format-util.h"
#include "journal-importer.h"
#include "log.h"
#include "string-table.h"
#include "string-util.h"

/* Make sure to not make this larger than the maximum journal entry
 * size. See DATA_SIZE_MAX in journal-importer.h. */
assert_cc(JOURNAL_SIZE_MAX <= DATA_SIZE_MAX);

CoredumpStorage arg_storage = COREDUMP_STORAGE_EXTERNAL;
bool arg_compress = true;
uint64_t arg_process_size_max = PROCESS_SIZE_MAX;
uint64_t arg_external_size_max = EXTERNAL_SIZE_MAX;
uint64_t arg_journal_size_max = JOURNAL_SIZE_MAX;
uint64_t arg_keep_free = UINT64_MAX;
uint64_t arg_max_use = UINT64_MAX;
bool arg_enter_namespace = false;

static const char* const coredump_storage_table[_COREDUMP_STORAGE_MAX] = {
        [COREDUMP_STORAGE_NONE]     = "none",
        [COREDUMP_STORAGE_EXTERNAL] = "external",
        [COREDUMP_STORAGE_JOURNAL]  = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(coredump_storage, CoredumpStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_coredump_storage, coredump_storage, CoredumpStorage);

int coredump_parse_config(void) {
        static const ConfigTableItem items[] = {
                { "Coredump", "Storage",         config_parse_coredump_storage,    0,                      &arg_storage           },
                { "Coredump", "Compress",        config_parse_bool,                0,                      &arg_compress          },
                { "Coredump", "ProcessSizeMax",  config_parse_iec_uint64,          0,                      &arg_process_size_max  },
                { "Coredump", "ExternalSizeMax", config_parse_iec_uint64_infinity, 0,                      &arg_external_size_max },
                { "Coredump", "JournalSizeMax",  config_parse_iec_size,            0,                      &arg_journal_size_max  },
                { "Coredump", "KeepFree",        config_parse_iec_uint64,          0,                      &arg_keep_free         },
                { "Coredump", "MaxUse",          config_parse_iec_uint64,          0,                      &arg_max_use           },
#if HAVE_DWFL_SET_SYSROOT
                { "Coredump", "EnterNamespace",  config_parse_bool,                0,                      &arg_enter_namespace   },
#else
                { "Coredump", "EnterNamespace",  config_parse_warn_compat,         DISABLED_CONFIGURATION, NULL                   },
#endif
                {}
        };

        int r;

        r = config_parse_standard_file_with_dropins(
                        "systemd/coredump.conf",
                        "Coredump\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;

        /* Let's make sure we fix up the maximum size we send to the journal here on the client side, for
         * efficiency reasons. journald wouldn't accept anything larger anyway. */
        if (arg_journal_size_max > JOURNAL_SIZE_MAX) {
                log_warning("JournalSizeMax= set to larger value (%s) than journald would accept (%s), lowering automatically.",
                            FORMAT_BYTES(arg_journal_size_max), FORMAT_BYTES(JOURNAL_SIZE_MAX));
                arg_journal_size_max = JOURNAL_SIZE_MAX;
        }

        log_debug("Selected storage '%s'.", coredump_storage_to_string(arg_storage));
        log_debug("Selected compression %s.", yes_no(arg_compress));

        return 0;
}

uint64_t coredump_storage_size_max(void) {
        if (arg_storage == COREDUMP_STORAGE_EXTERNAL)
                return arg_external_size_max;
        if (arg_storage == COREDUMP_STORAGE_JOURNAL)
                return arg_journal_size_max;
        assert(arg_storage == COREDUMP_STORAGE_NONE);
        return 0;
}
