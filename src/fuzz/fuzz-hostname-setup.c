/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "hostname-setup.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *ret = NULL;

        if (size == 0)
                return 0;

        f = fmemopen_unlocked((char*) data, size, "re");
        assert_se(f);

        (void) read_etc_hostname_stream(f, &ret);

        return 0;
}
