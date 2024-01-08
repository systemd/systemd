/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-pcrs.h"
#include "fileio.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "terminal-util.h"
#include "tpm2-util.h"

static int get_pcr_alg(const char **ret) {
        assert(ret);

        FOREACH_STRING(alg, "sha256", "sha1") {
                _cleanup_free_ char *p = NULL;

                if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/0", alg) < 0)
                        return log_oom();

                if (access(p, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to determine whether %s exists: %m", p);
                } else {
                        *ret = alg;
                        return 1;
                }
        }

        log_notice("Kernel does not support reading PCR values.");
        *ret = NULL;
        return 0;
}

static int get_current_pcr(const char *alg, uint32_t pcr, void **ret, size_t *ret_size) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        _cleanup_free_ void *buf = NULL;
        size_t ss = 0, bufsize = 0;
        int r;

        assert(alg);
        assert(ret);
        assert(ret_size);

        if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/%" PRIu32, alg, pcr) < 0)
                return log_oom();

        r = read_virtual_file(p, 4096, &s, &ss);
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s': %m", p);

        r = unhexmem_full(s, ss, /* secure = */ false, &buf, &bufsize);
        if (r < 0)
                return log_error_errno(r, "Failed to decode hex PCR data '%s': %m", s);

        *ret = TAKE_PTR(buf);
        *ret_size = bufsize;
        return 0;
}

static int add_pcr_to_table(Table *table, const char *alg, uint32_t pcr) {
        _cleanup_free_ char *h = NULL;
        const char *color = NULL;
        int r;

        if (alg) {
                _cleanup_free_ void *buf = NULL;
                size_t bufsize = 0;

                r = get_current_pcr(alg, pcr, &buf, &bufsize);
                if (r < 0)
                        return r;

                h = hexmem(buf, bufsize);
                if (!h)
                        return log_oom();

                /* Grey out PCRs that are not sensibly initialized */
                if (memeqbyte(0, buf, bufsize) ||
                    memeqbyte(0xFFU, buf, bufsize))
                        color = ANSI_GREY;
        }

        r = table_add_many(table,
                           TABLE_UINT32, pcr,
                           TABLE_STRING, tpm2_pcr_index_to_string(pcr),
                           TABLE_STRING, h,
                           TABLE_SET_COLOR, color);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

int verb_pcrs(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *alg = NULL;
        int r;

        if (tpm2_support() != TPM2_SUPPORT_FULL)
                log_notice("System lacks full TPM2 support, not showing PCR state.");
        else {
                r = get_pcr_alg(&alg);
                if (r < 0)
                        return r;
        }

        table = table_new("nr", "name", alg ?: "-");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 0), 100);
        (void) table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        if (!alg) /* hide hash column if we couldn't acquire it */
                (void) table_set_display(table, 0, 1);

        if (strv_isempty(strv_skip(argv, 1)))
                for (uint32_t pi = 0; pi < _TPM2_PCR_INDEX_MAX_DEFINED; pi++) {
                        r = add_pcr_to_table(table, alg, pi);
                        if (r < 0)
                                return r;
                }
        else {
                for (int i = 1; i < argc; i++) {
                        int pi;

                        pi = tpm2_pcr_index_from_string(argv[i]);
                        if (pi < 0)
                                return log_error_errno(pi, "PCR index \"%s\" not known.", argv[i]);

                        r = add_pcr_to_table(table, alg, pi);
                        if (r < 0)
                                return r;
                }

                (void) table_set_sort(table, (size_t) 0);
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */true);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        return EXIT_SUCCESS;
}
