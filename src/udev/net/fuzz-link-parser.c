/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "link-config.h"
#include "tests.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(link_config_ctx_freep) LinkConfigContext *ctx = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-link-config.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        if (outside_size_range(size, /* lower= */ 0, 65536))
                return 0;

        fuzz_setup_logging();

        ASSERT_OK_ZERO(fmkostemp_safe(filename, "r+", &f));
        if (size != 0)
                ASSERT_EQ(fwrite(data, size, 1, f), (size_t) 1);

        fflush(f);
        ASSERT_OK(link_config_ctx_new(&ctx));
        (void) link_load_one(ctx, filename);
        return 0;
}
