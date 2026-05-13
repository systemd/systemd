/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-has-tpm2.h"
#include "format-table.h"
#include "log.h"
#include "string-util.h"
#include "time-util.h"
#include "tpm2-util.h"

int verb_has_tpm2(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return verb_has_tpm2_generic(arg_quiet);
}

int verb_identify_tpm2(int argc, char **argv, uintptr_t _data, void *userdata) {
#if HAVE_TPM2
        int r;

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        r = tpm2_context_new_or_warn(/* device= */ NULL, &c);
        if (r < 0)
                return r;

        Tpm2VendorInfo info;
        r = tpm2_get_vendor_info(c, &info);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire TPM2 vendor information: %m");

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        if (!isempty(info.family_indicator)) {
                r = table_add_many(
                                table,
                                TABLE_FIELD, "Family Indicator",
                                TABLE_STRING, info.family_indicator);
                if (r < 0)
                        return table_log_add_error(r);
        }

        _cleanup_free_ char *rv = NULL;
        if (asprintf(&rv, "%" PRIu32 ".%" PRIu32,
                     info.revision_major,
                     info.revision_minor) < 0)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Level",
                        TABLE_UINT32, info.level,
                        TABLE_FIELD, "Revision",
                        TABLE_STRING, rv);
        if (r < 0)
                return table_log_add_error(r);

        if (info.year >= 1900) {
                struct tm tm = {
                        .tm_year = info.year - 1900,
                        .tm_mon = 0,                   /* january */
                        .tm_mday = info.day_of_year,   /* timegm() will normalize this */
                };

                usec_t ts;
                r = mktime_or_timegm_usec(&tm, /* utc= */ true, &ts);
                if (r < 0)
                        log_debug_errno(r, "Failed to convert the specification date, ignoring.");
                else {
                        r = table_add_many(
                                        table,
                                        TABLE_FIELD, "Specification Date",
                                        TABLE_TIMESTAMP_DATE, ts);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (!isempty(info.manufacturer)) {
                r = table_add_many(
                                table,
                                TABLE_FIELD, "Manufacturer",
                                TABLE_STRING, info.manufacturer);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(info.vendor_string)) {
                r = table_add_many(
                                table,
                                TABLE_FIELD, "Vendor String",
                                TABLE_STRING, info.vendor_string);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info.vendor_tpm_type != 0) {
                r = table_add_many(
                                table,
                                TABLE_FIELD, "Vendor TPM Type",
                                TABLE_UINT32_HEX_0x, info.vendor_tpm_type);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Show the first two 16bit words of the firmware version as major/minor */
        _cleanup_free_ char *fw = NULL;
        if (asprintf(&fw, "%" PRIu16 ".%" PRIu16,
                     info.firmware_version_major,
                     info.firmware_version_minor) < 0)
                return log_oom();

        /* Show the second 32bit as a single value, if non-zero */
        if (info.firmware_version2 != 0 && strextendf(&fw, ".%" PRIu32, info.firmware_version2) < 0)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Firmware Version",
                        TABLE_STRING, fw);
        if (r < 0)
                return table_log_add_error(r);

        _cleanup_free_ char *m = NULL;
        if (tpm2_vendor_info_to_modalias(&info, &m) < 0)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Modalias String",
                        TABLE_STRING, m);
        if (r < 0)
                return table_log_add_error(r);

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ false);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support not enabled at build time.");
#endif
}
