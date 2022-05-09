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

        return 0;
}
