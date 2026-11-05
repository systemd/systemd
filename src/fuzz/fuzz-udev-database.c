/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-internal.h"
#include "device-private.h"
#include "fd-util.h"
#include "fuzz.h"
#include "tests.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-udev-database.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        fuzz_setup_logging();

        ASSERT_OK_ZERO(fmkostemp_safe(filename, "r+", &f));
        if (size != 0)
                ASSERT_EQ(fwrite(data, size, 1, f), (size_t) 1);

        fflush(f);
        ASSERT_OK(device_new_aux(&dev));
        (void) device_read_db_internal_filename(dev, filename);
        return 0;
}
