/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fileio.h"
#include "fd-util.h"
#include "fuzz.h"
#include "json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *out = NULL; /* out should be freed after g */
        size_t out_size;
        _cleanup_fclose_ FILE *f = NULL, *g = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        if (size == 0)
                return 0;

        f = fmemopen_unlocked((char*) data, size, "re");
        assert_se(f);

        if (json_parse_file(f, NULL, &v, NULL, NULL) < 0)
                return 0;

        g = open_memstream_unlocked(&out, &out_size);
        assert_se(g);

        json_variant_dump(v, 0, g, NULL);
        json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR|JSON_FORMAT_SOURCE, g, NULL);

        return 0;
}
