/* SPDX-License-Identifier: LGPL-2.1+ */

#include "device-internal.h"
#include "device-private.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-udev-database.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);
        assert_se(device_new_aux(&dev) >= 0);
        (void) device_read_db_internal_filename(dev, filename);
        return 0;
}
