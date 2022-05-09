/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *out = NULL; /* out should be freed after g */
        size_t out_size;
        _cleanup_fclose_ FILE *f = NULL, *g = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        /* Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        f = data_to_file(data, size);
        assert_se(f);

        r = json_parse_file(f, NULL, 0, &v, NULL, NULL);
        if (r < 0) {
                log_debug_errno(r, "failed to parse input: %m");
                return 0;
        }

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                assert_se(g = open_memstream_unlocked(&out, &out_size));

        json_variant_dump(v, 0, g ?: stdout, NULL);
        json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR|JSON_FORMAT_SOURCE, g ?: stdout, NULL);

        bool sorted = json_variant_is_sorted(v);
        log_debug("json_variant_is_sorted: %s", yes_no(sorted));

        r = json_variant_sort(&v);
        log_debug_errno(r, "json_variant_sort: %d/%m", r);

        sorted = json_variant_is_sorted(v);
        log_debug("json_variant_is_sorted: %s", yes_no(sorted));
        assert_se(r < 0 || sorted);

        bool normalized = json_variant_is_normalized(v);
        log_debug("json_variant_is_normalized: %s", yes_no(normalized));

        r = json_variant_normalize(&v);
        log_debug_errno(r, "json_variant_normalize: %d/%m", r);

        normalized = json_variant_is_normalized(v);
        log_debug("json_variant_is_normalized: %s", yes_no(normalized));
        assert_se(r < 0 || normalized);

        double real = json_variant_real(v);
        log_debug("json_variant_real: %lf", real);

        bool negative = json_variant_is_negative(v);
        log_debug("json_variant_is_negative: %s", yes_no(negative));

        bool blank = json_variant_is_blank_object(v);
        log_debug("json_variant_is_blank_object: %s", yes_no(blank));

        blank = json_variant_is_blank_array(v);
        log_debug("json_variant_is_blank_array: %s", yes_no(blank));

        size_t elements = json_variant_elements(v);
        log_debug("json_variant_elements: %zu", elements);

        for (size_t i = 0; i <= elements + 2; i++)
                (void) json_variant_by_index(v, i);

        assert_se(json_variant_equal(v, v));
        assert_se(!json_variant_equal(v, NULL));
        assert_se(!json_variant_equal(NULL, v));

        bool sensitive = json_variant_is_sensitive(v);
        log_debug("json_variant_is_sensitive: %s", yes_no(sensitive));

        json_variant_sensitive(v);

        sensitive = json_variant_is_sensitive(v);
        log_debug("json_variant_is_sensitive: %s", yes_no(sensitive));

        const char *source;
        unsigned line, column;
        assert_se(json_variant_get_source(v, &source, &line, &column) == 0);
        log_debug("json_variant_get_source: %s:%u:%u", source ?: "-", line, column);

        r = json_variant_set_field_string(&v, "a", "string-a");
        log_debug_errno(r, "json_set_field_string: %d/%m", r);

        r = json_variant_set_field_integer(&v, "b", -12345);
        log_debug_errno(r, "json_set_field_integer: %d/%m", r);

        r = json_variant_set_field_unsigned(&v, "c", 12345);
        log_debug_errno(r, "json_set_field_unsigned: %d/%m", r);

        r = json_variant_set_field_boolean(&v, "d", false);
        log_debug_errno(r, "json_set_field_boolean: %d/%m", r);

        r = json_variant_set_field_strv(&v, "e", STRV_MAKE("e-1", "e-2", "e-3"));
        log_debug_errno(r, "json_set_field_strv: %d/%m", r);

        r = json_variant_filter(&v, STRV_MAKE("a", "b", "c", "d", "e"));
        log_debug_errno(r, "json_variant_filter: %d/%m", r);

        /* I assume we can merge v with itself… */
        r = json_variant_merge(&v, v);
        log_debug_errno(r, "json_variant_merge: %d/%m", r);

        r = json_variant_append_array(&v, v);
        log_debug_errno(r, "json_variant_append_array: %d/%m", r);

        return 0;
}
