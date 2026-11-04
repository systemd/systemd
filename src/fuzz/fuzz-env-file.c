/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "env-file.h"
#include "fd-util.h"
#include "fuzz.h"
#include "strv.h"
#include "tests.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **rl = NULL, **rlp =  NULL;

        if (outside_size_range(size, /* lower= */ 0, 65536))
                return 0;

        f = data_to_file(data, size);
        ASSERT_NOT_NULL(f);

        fuzz_setup_logging();

        (void) load_env_file(f, /* fname= */ NULL, &rl);
        ASSERT_EQ(fseek(f, 0, SEEK_SET), 0);
        (void) load_env_file_pairs(f, /* fname= */ NULL, &rlp);

        return 0;
}
