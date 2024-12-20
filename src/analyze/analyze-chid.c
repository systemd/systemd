/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-chid.h"
#include "chid-fundamental.h"
#include "efi-api.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "parse-util.h"
#include "strv.h"
#include "utf8.h"
#include "virt.h"

static int parse_chid_type(const char *s, size_t *ret) {
        unsigned u;
        int r;

        assert(s);

        r = safe_atou(s, &u);
        if (r < 0)
                return r;
        if (u >= CHID_TYPES_MAX)
                return -ERANGE;

        if (ret)
                *ret = u;

        return 0;
}

static const char chid_smbios_fields_char[_CHID_SMBIOS_FIELDS_MAX] = {
        [CHID_SMBIOS_MANUFACTURER]           = 'M',
        [CHID_SMBIOS_FAMILY]                 = 'F',
        [CHID_SMBIOS_PRODUCT_NAME]           = 'P',
        [CHID_SMBIOS_PRODUCT_SKU]            = 'S',
        [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = 'm',
        [CHID_SMBIOS_BASEBOARD_PRODUCT]      = 'p',
};

static char *chid_smbios_fields_string(uint32_t combination) {
        _cleanup_free_ char *s = NULL;

        for (ChidSmbiosFields f = 0; f < _CHID_SMBIOS_FIELDS_MAX; f++) {
                char c;

                c = (combination & (UINT32_C(1) << f)) ? chid_smbios_fields_char[f] : '-';

                if (!strextend(&s, CHAR_TO_STR(c)))
                        return NULL;
        }

        return TAKE_PTR(s);
}

static int add_chid(Table *table, const EFI_GUID guids[static CHID_TYPES_MAX], size_t t) {
        int r;

        assert(table);
        assert(guids);
        assert(t < CHID_TYPES_MAX);

        sd_id128_t id = efi_guid_to_id128(guids + t);

        if (sd_id128_is_null(id))
                return 0;

        _cleanup_free_ char *flags = chid_smbios_fields_string(chid_smbios_table[t]);
        if (!flags)
                return log_oom();

        r = table_add_many(table,
                           TABLE_UINT, (unsigned) t,
                           TABLE_STRING, flags,
                           TABLE_UUID, id);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static void smbios_fields_free(char16_t *(*fields)[_CHID_SMBIOS_FIELDS_MAX]) {
        assert(fields);

        FOREACH_ARRAY(i, *fields, _CHID_SMBIOS_FIELDS_MAX)
                free(*i);
}

int verb_chid(int argc, char *argv[], void *userdata) {

        static const char *const smbios_files[_CHID_SMBIOS_FIELDS_MAX] = {
                [CHID_SMBIOS_MANUFACTURER]           = "sys_vendor",
                [CHID_SMBIOS_FAMILY]                 = "product_family",
                [CHID_SMBIOS_PRODUCT_NAME]           = "product_name",
                [CHID_SMBIOS_PRODUCT_SKU]            = "product_sku",
                [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = "board_vendor",
                [CHID_SMBIOS_BASEBOARD_PRODUCT]      = "board_name",
        };

        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Container environments do not have SMBIOS.");

        table = table_new("type", "input", "chid");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 0), 100);
        (void) table_set_align_percent(table, table_get_cell(table, 0, 1), 50);

        _cleanup_close_ int smbios_fd = open("/sys/class/dmi/id", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (smbios_fd < 0)
                return log_error_errno(errno, "Failed to open SMBIOS sysfs object: %m");

        _cleanup_(smbios_fields_free) char16_t* smbios_fields[_CHID_SMBIOS_FIELDS_MAX] = {};
        for (ChidSmbiosFields f = 0; f < _CHID_SMBIOS_FIELDS_MAX; f++) {
                _cleanup_free_ char *buf = NULL;
                size_t size;

                /* According to the CHID spec we should not generate CHIDs for SMBIOS fields that aren't set
                 * or are set to an empty string. Hence leave them NULL here. */

                if (!smbios_files[f])
                        continue;

                r = read_virtual_file_at(smbios_fd, smbios_files[f], SIZE_MAX, &buf, &size);
                if (r == -ENOENT) {
                        log_debug_errno(r, "SMBIOS field '%s' not set, skipping.", smbios_files[f]);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to read SMBIOS field '%s': %m", smbios_files[f]);

                if (size == 0 || (size == 1 && buf[0] == '\n')) {
                        log_debug("SMBIOS field '%s' is empty, skipping.", smbios_files[f]);
                        continue;
                }

                if (buf[size-1] != '\n')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected SMBIOS field '%s' to end in newline, but it doesn't, refusing.", smbios_files[f]);

                size--;

                smbios_fields[f] = utf8_to_utf16(buf, size);
                if (!smbios_fields[f])
                        return log_oom();
        }

        EFI_GUID chids[CHID_TYPES_MAX] = {};
        chid_calculate((const char16_t* const*) smbios_fields, chids);

        if (strv_isempty(strv_skip(argv, 1)))
                for (size_t t = 0; t < CHID_TYPES_MAX; t++) {
                        r = add_chid(table, chids, t);
                        if (r < 0)
                                return r;
                }
        else {
                STRV_FOREACH(as, strv_skip(argv, 1)) {
                        size_t t;
                        r = parse_chid_type(*as, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to pare CHID type: %s", *as);

                        r = add_chid(table, chids, t);
                        if (r < 0)
                                return r;
                }

                (void) table_set_sort(table, (size_t) 0);
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                _cleanup_free_ char *legend = NULL;
                bool separator = false;
                size_t w = 0;

                legend = strjoin(ansi_grey(), "LEGEND: ", ansi_normal());
                if (!legend)
                        return log_oom();

                for (ChidSmbiosFields f = 0; f < _CHID_SMBIOS_FIELDS_MAX; f++) {
                        _cleanup_free_ char *c = NULL;

                        if (smbios_fields[f]) {
                                c = utf16_to_utf8(smbios_fields[f], SIZE_MAX);
                                if (!c)
                                        return log_oom();
                        }

                        if (!strextend(&legend,
                                       ansi_grey(),
                                       separator ? " " : "",
                                       separator ? special_glyph(SPECIAL_GLYPH_HORIZONTAL_DOTTED) : "",
                                       separator ? " " : "",
                                       ansi_normal(),
                                       CHAR_TO_STR(chid_smbios_fields_char[f]),
                                       ansi_grey(),
                                       " ",
                                       special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                                       " ",
                                       ansi_normal(),
                                       smbios_files[f],
                                       ansi_grey(),
                                       " (",
                                       c ? ansi_highlight() : ansi_grey(),
                                       strna(c),
                                       ansi_grey(),
                                       ")",
                                       ansi_normal()))
                            return log_oom();

                        w += separator * 3 +
                                4 +
                                utf8_console_width(smbios_files[f]) +
                                2 +
                                utf8_console_width(strna(c)) +
                                1;

                        if (w > 79) {
                                if (!strextend(&legend, "\n        "))
                                        return log_oom();

                                separator = false;
                                w = 8;
                        } else
                                separator = true;

                }

                putchar('\n');
                puts(legend);
        }

        return EXIT_SUCCESS;
}
