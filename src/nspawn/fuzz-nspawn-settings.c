/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "nspawn-settings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(settings_freep) Settings *s = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        f = data_to_file(data, size);
        assert_se(f);

        fuzz_setup_logging();

        (void) settings_load(f, "/dev/null", &s);

        return 0;
}
