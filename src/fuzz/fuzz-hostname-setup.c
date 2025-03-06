/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "hostname-setup.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *ret = NULL;

        f = data_to_file(data, size);
        assert_se(f);

        fuzz_setup_logging();

        (void) read_etc_hostname_stream(f, /* substitute_wildcards= */ true, &ret);

        return 0;
}
