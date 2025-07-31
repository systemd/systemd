/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "link-config.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(link_config_ctx_freep) LinkConfigContext *ctx = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-link-config.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        fuzz_setup_logging();

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        assert_se(link_config_ctx_new(&ctx) >= 0);
        (void) link_load_one(ctx, filename);
        return 0;
}
