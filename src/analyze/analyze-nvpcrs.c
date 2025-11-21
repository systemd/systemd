/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "analyze-nvpcrs.h"
#include "analyze.h"
#include "conf-files.h"
#include "constants.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "strv.h"
#include "tpm2-util.h"

#if HAVE_TPM2
static int add_nvpcr_to_table(Tpm2Context **c, Table *t, const char *name) {
        int r;

        _cleanup_free_ char *h = NULL;
        uint32_t nv_index = 0;
        if (c) {
                if (!*c) {
                        r = tpm2_context_new_or_warn(/* device= */ NULL, c);
                        if (r < 0)
                                return r;
                }

                _cleanup_(iovec_done) struct iovec digest = {};
                r = tpm2_nvpcr_read(*c, /* session= */ NULL, name, &digest, &nv_index);
                if (r < 0)
                        return log_error_errno(r, "Failed to read NvPCR '%s': %m", name);

                h = hexmem(digest.iov_base, digest.iov_len);
                if (!h)
                        return log_oom();
        } else {
                r = tpm2_nvpcr_get_index(name, &nv_index);
                if (r < 0)
                        return log_error_errno(r, "Failed to get NV index of NvPCR '%s': %m", name);
        }

        r = table_add_many(
                        t,
                        TABLE_STRING, name,
                        TABLE_UINT32_HEX_0x, nv_index,
                        TABLE_STRING, h);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}
#endif

int verb_nvpcrs(int argc, char *argv[], void *userdata) {
#if HAVE_TPM2
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        bool have_tpm2 = tpm2_is_fully_supported();

        if (!have_tpm2)
                log_notice("System lacks full TPM2 support, not showing NvPCR state.");

        table = table_new("name", "nvindex", "value");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 1), 100);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        (void) table_set_sort(table, (size_t) 0);

        if (!have_tpm2)
                (void) table_hide_column_from_display(table, (size_t) 2);

        if (strv_isempty(strv_skip(argv, 1))) {
                _cleanup_strv_free_ char **l = NULL;
                r = conf_files_list_nulstr(
                                &l,
                                ".nvpcr",
                                /* root= */ NULL,
                                CONF_FILES_REGULAR|CONF_FILES_BASENAME|CONF_FILES_FILTER_MASKED|CONF_FILES_TRUNCATE_SUFFIX,
                                CONF_PATHS_NULSTR("nvpcr"));
                if (r < 0)
                        return log_error_errno(r, "Failed to find .nvpcr files: %m");

                STRV_FOREACH(i, l) {
                        r = add_nvpcr_to_table(have_tpm2 ? &c : NULL, table, *i);
                        if (r < 0)
                                return r;
                }
        } else
                for (int i = 1; i < argc; i++) {
                        r = add_nvpcr_to_table(have_tpm2 ? &c : NULL, table, argv[i]);
                        if (r < 0)
                                return r;
                }

        if (table_isempty(table) && FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF))
                log_notice("No NvPCRs defined.");
        else {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        return EXIT_SUCCESS;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support not enabled at build time.");
#endif
}
