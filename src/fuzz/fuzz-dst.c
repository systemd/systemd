/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "time-dst.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-dst.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *zc = NULL, *zn = NULL;
        time_t sec;
        time_t tc, tn;
        int dn = 0;
        bool is_dstc = false;
        bool is_dstn = false;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        sec = time(NULL);
        (void) time_get_dst(sec, filename,
                         &tc, &zc, &is_dstc,
                         &tn, &dn, &zn, &is_dstn);
        return 0;
}
