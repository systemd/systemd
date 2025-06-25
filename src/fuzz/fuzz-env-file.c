/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "env-file.h"
#include "fd-util.h"
#include "fuzz.h"
#include "strv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **rl = NULL, **rlp =  NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        f = data_to_file(data, size);
        assert_se(f);

        fuzz_setup_logging();

        (void) load_env_file(f, NULL, &rl);
        assert_se(fseek(f, 0, SEEK_SET) == 0);
        (void) load_env_file_pairs(f, NULL, &rlp);

        return 0;
}
