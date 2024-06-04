/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-nvpcrs.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "recurse-dir.h"
#include "tpm2-util.h"

static int add_nvpcr_to_table(Tpm2Context **c, Table *t, const char *name) {
        int r;

        assert(c);

        if (!*c) {
                r = tpm2_context_new_or_warn(/* device= */ NULL, c);
                if (r < 0)
                        return r;
        }

        _cleanup_(iovec_done) struct iovec digest = {};
        uint32_t nv_index = 0;

        r = tpm2_nvpcr_read(*c, /* session= */ NULL, name, &digest, &nv_index);
        if (r < 0)
                return log_error_errno(r, "Failed to read NvPCR '%s': %m", name);

        _cleanup_free_ char *h = hexmem(digest.iov_base, digest.iov_len);
        if (!h)
                return log_oom();

        r = table_add_many(
                        t,
                        TABLE_UINT32_HEX_0x, nv_index,
                        TABLE_STRING, name,
                        TABLE_STRING, h);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_nvpcrs(int argc, char *argv[], void *userdata) {
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        table = table_new("nvindex", "name", "value");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 0), 100);
        (void) table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        (void) table_set_sort(table, (size_t) 1);

        if (strv_isempty(strv_skip(argv, 1))) {

                _cleanup_free_ DirectoryEntries *de = NULL;
                r = readdir_all_at(AT_FDCWD, "/run/systemd/nvpcr", RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &de);
                if (r < 0 && r != -ENOENT)
                        return log_debug_errno(r, "Failed to read /run/systemd/nvpcr: %m");

                if (de)
                        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                                const char *e;

                                if ((*i)->d_type != DT_REG)
                                        continue;

                                e = endswith((*i)->d_name, ".nvpcr");
                                if (!e)
                                        continue;

                                _cleanup_free_ char *name = strndup((*i)->d_name, e - (*i)->d_name);
                                if (!name)
                                        return log_oom();

                                r = add_nvpcr_to_table(&c, table, name);
                                if (r < 0)
                                        return r;
                        }
        } else
                for (int i = 1; i < argc; i++) {
                        r = add_nvpcr_to_table(&c, table, argv[i]);
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
}
