/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-chid.h"
#include "ansi-color.h"
#include "chid-fundamental.h"
#include "device-util.h"
#include "edid-fundamental.h"
#include "efi-api.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "glyph-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "virt.h"

static int parse_chid_type(const char *s, size_t *ret) {
        char *e;
        unsigned u;
        int r;

        assert(s);

        if ((e = startswith(s, "ext"))) {
                r = safe_atou(e, &u);
                if (r < 0)
                        return r;
                if (u >= CHID_TYPES_MAX - EXTRA_CHID_BASE)
                        return -ERANGE;
                u += EXTRA_CHID_BASE;
        } else {
                r = safe_atou(s, &u);
                if (r < 0)
                        return r;
                if (u >= EXTRA_CHID_BASE)
                        return -ERANGE;
        }


        if (ret)
                *ret = u;

        return 0;
}

static const char *const chid_smbios_friendly[_CHID_SMBIOS_FIELDS_MAX] = {
        [CHID_SMBIOS_MANUFACTURER]           = "manufacturer",
        [CHID_SMBIOS_FAMILY]                 = "family",
        [CHID_SMBIOS_PRODUCT_NAME]           = "product-name",
        [CHID_SMBIOS_PRODUCT_SKU]            = "product-sku",
        [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = "baseboard-manufacturer",
        [CHID_SMBIOS_BASEBOARD_PRODUCT]      = "baseboard-product",
        [CHID_SMBIOS_BIOS_VENDOR]            = "bios-vendor",
        [CHID_SMBIOS_BIOS_VERSION]           = "bios-version",
        [CHID_SMBIOS_BIOS_MAJOR]             = "bios-major",
        [CHID_SMBIOS_BIOS_MINOR]             = "bios-minor",
        [CHID_SMBIOS_ENCLOSURE_TYPE]         = "enclosure-type",
        [CHID_EDID_PANEL]                    = "edid-panel",
};

static const char chid_smbios_fields_char[_CHID_SMBIOS_FIELDS_MAX] = {
        [CHID_SMBIOS_MANUFACTURER]           = 'M',
        [CHID_SMBIOS_FAMILY]                 = 'F',
        [CHID_SMBIOS_PRODUCT_NAME]           = 'P',
        [CHID_SMBIOS_PRODUCT_SKU]            = 'S',
        [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = 'm',
        [CHID_SMBIOS_BASEBOARD_PRODUCT]      = 'p',
        [CHID_SMBIOS_BIOS_VENDOR]            = 'B',
        [CHID_SMBIOS_BIOS_VERSION]           = 'v',
        [CHID_SMBIOS_BIOS_MAJOR]             = 'R',
        [CHID_SMBIOS_BIOS_MINOR]             = 'r',
        [CHID_SMBIOS_ENCLOSURE_TYPE]         = 'e',
        [CHID_EDID_PANEL]                    = 'E',
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

        if (t < EXTRA_CHID_BASE)
                r = table_add_many(table, TABLE_UINT, (unsigned) t);
        else
                r = table_add_cell_stringf(table, NULL, "ext%zu", t - EXTRA_CHID_BASE);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(table,
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

static int smbios_fields_acquire(char16_t *fields[static _CHID_SMBIOS_FIELDS_MAX]) {

        static const char *const smbios_files[_CHID_SMBIOS_FIELDS_MAX] = {
                [CHID_SMBIOS_MANUFACTURER]           = "sys_vendor",
                [CHID_SMBIOS_FAMILY]                 = "product_family",
                [CHID_SMBIOS_PRODUCT_NAME]           = "product_name",
                [CHID_SMBIOS_PRODUCT_SKU]            = "product_sku",
                [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = "board_vendor",
                [CHID_SMBIOS_BASEBOARD_PRODUCT]      = "board_name",
                [CHID_SMBIOS_BIOS_VENDOR]            = "bios_vendor",
                [CHID_SMBIOS_BIOS_VERSION]           = "bios_version",
                [CHID_SMBIOS_BIOS_MAJOR]             = "bios_release",
                [CHID_SMBIOS_BIOS_MINOR]             = "bios_release",
                [CHID_SMBIOS_ENCLOSURE_TYPE]         = "chassis_type",
        };

        int r;

        _cleanup_close_ int smbios_fd = open("/sys/class/dmi/id", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (smbios_fd < 0)
                return log_error_errno(errno, "Failed to open SMBIOS sysfs object: %m");

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

                buf[size-1] = 0;
                size--;

                switch (f) {

                case CHID_SMBIOS_BIOS_MAJOR:
                case CHID_SMBIOS_BIOS_MINOR: {
                        /* The kernel exposes this a string <major>.<minor>, split them apart again. */
                        char *dot = memchr(buf, '.', size);
                        if (!dot)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "BIOS release field '%s' contains no dot?", smbios_files[f]);

                        const char *p;
                        if (f == CHID_SMBIOS_BIOS_MAJOR) {
                                *dot = 0;
                                p = buf;
                        } else {
                                assert(f == CHID_SMBIOS_BIOS_MINOR);
                                p = dot + 1;
                        }

                        /* The kernel exports the enclosure in decimal, we need it in hex (zero left-padded) */

                        uint8_t u;
                        r = safe_atou8(p, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse BIOS release: %s", p);

                        buf = mfree(buf);
                        if (asprintf(&buf, "%02x", u) < 0)
                                return log_oom();

                        size = strlen(buf);
                        break;
                }

                case CHID_SMBIOS_ENCLOSURE_TYPE: {
                        /* The kernel exports the enclosure in decimal, we need it in hex (no padding!) */

                        uint8_t u;
                        r = safe_atou8(buf, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse enclosure type: %s", buf);

                        buf = mfree(buf);
                        if (u == 0)
                                buf = strdup(""); /* zero is mapped to empty string */
                        else
                                (void) asprintf(&buf, "%x", u);
                        if (!buf)
                                return log_oom();

                        size = strlen(buf);
                        break;
                }

                default:
                        ;
                }

                fields[f] = utf8_to_utf16(buf, size);
                if (!fields[f])
                        return log_oom();
        }

        return 0;
}

static int edid_parse(sd_device *drm_dev, char16_t **ret_panel) {
        const char *edid_content;
        size_t edid_size;
        int r;

        assert(drm_dev);
        assert(ret_panel);

        r = sd_device_get_sysattr_value_with_size(drm_dev, "edid", &edid_content, &edid_size);
        if (r < 0)
                return r;
        if (edid_size == 0)
                return -ENXIO;

        EdidHeader header;
        if (edid_parse_blob(edid_content, edid_size, &header) < 0)
                return -EBADMSG;

        _cleanup_free_ char16_t *panel_id = new0(char16_t, 8);
        if (!panel_id)
                return -ENOMEM;

        if (edid_get_panel_id(&header, panel_id) < 0)
                return -EBADMSG;

        *ret_panel = TAKE_PTR(panel_id);
        return 0;
}

static int edid_search(char16_t **ret_panel) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_strv_free_ char **drm_paths = NULL;
        _cleanup_free_ char16_t *unique_panel = NULL;
        size_t n = 0;
        int r;

        assert(ret_panel);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to create device enumerator: %m");

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to allow uninitialized device enumerator: %m");

        r = sd_device_enumerator_add_match_subsystem(e, "drm", true);
        if (r < 0)
                return log_error_errno(r, "Failed to add drm match subsystem to device enumerator: %m");

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char16_t *panel = NULL;
                const char *drm_path;

                r = sd_device_get_syspath(d, &drm_path);
                if (r < 0)
                        return log_device_error_errno(d, r, "Failed to get syspath from device: %m");

                r = edid_parse(d, &panel);
                if (ERRNO_IS_DEVICE_ABSENT(r))
                        continue;
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to parse EDID from DRM device, skipping: %m");
                        continue;
                }

                if (!unique_panel)
                        unique_panel = TAKE_PTR(panel);

                if (strv_extend_with_size(&drm_paths, &n, drm_path) < 0)
                        return log_oom();
        }

        if (n == 1) {
                *ret_panel = TAKE_PTR(unique_panel);
                return 0;
        }
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "No monitors detected, skipping EDID CHID extensions.");

        log_notice("Multiple monitors detected, skipping EDID CHID extensions.");
        STRV_FOREACH(s, drm_paths)
                log_info("Hint: use --drm-device=%s", *s);

        return -ENOTUNIQ;
}

int verb_chid(int argc, char *argv[], void *userdata) {

        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Container environments do not have SMBIOS.");

        table = table_new("type", "input", "chid");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 0), 100);
        (void) table_set_align_percent(table, table_get_cell(table, 0, 1), 50);

        _cleanup_(smbios_fields_free) char16_t* smbios_fields[_CHID_SMBIOS_FIELDS_MAX] = {};
        r = smbios_fields_acquire(smbios_fields);
        if (r < 0)
                return r;

        if (arg_drm_device_path) {
                _cleanup_(sd_device_unrefp) sd_device *drm_dev = NULL;
                r = sd_device_new_from_path(&drm_dev, arg_drm_device_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to open device %s: %m", arg_drm_device_path);

                r = device_in_subsystem(drm_dev, "drm");
                if (r < 0)
                        return log_error_errno(r, "Failed to check if the device is a DRM device: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot read EDID from a non-DRM device '%s'", arg_drm_device_path);

                r = edid_parse(drm_dev, &smbios_fields[CHID_EDID_PANEL]);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse EDID for device %s: %m", arg_drm_device_path);
        } else {
                r = edid_search(&smbios_fields[CHID_EDID_PANEL]);
                if (r < 0 && !IN_SET(r, -ENOTUNIQ, -ENODEV))
                        return r;
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
                                return log_error_errno(r, "Failed to parse CHID type: %s", *as);

                        r = add_chid(table, chids, t);
                        if (r < 0)
                                return r;
                }

                (void) table_set_sort(table, (size_t) 0);
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return r;

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
                                _cleanup_free_ char *u = NULL;

                                u = utf16_to_utf8(smbios_fields[f], SIZE_MAX);
                                if (!u)
                                        return log_oom();

                                c = cescape(u);
                                if (!c)
                                        return log_oom();
                        }

                        if (!strextend(&legend,
                                       ansi_grey(),
                                       separator ? " " : "",
                                       separator ? glyph(GLYPH_HORIZONTAL_DOTTED) : "",
                                       separator ? " " : "",
                                       ansi_normal(),
                                       CHAR_TO_STR(chid_smbios_fields_char[f]),
                                       ansi_grey(),
                                       " ",
                                       glyph(GLYPH_ARROW_RIGHT),
                                       " ",
                                       ansi_normal(),
                                       chid_smbios_friendly[f],
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
                                utf8_console_width(chid_smbios_friendly[f]) +
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
