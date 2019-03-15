/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "link-config.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(link_config_ctx_freep) link_config_ctx *ctx = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-link-config.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        if (size > 65535)
                return 0;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        assert_se(link_config_ctx_new(&ctx) >= 0);
        (void) link_load_one(ctx, filename);
        return 0;
}
