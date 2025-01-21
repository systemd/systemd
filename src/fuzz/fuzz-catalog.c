/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "catalog.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-catalog.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;

        fuzz_setup_logging();

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, data, size) == (ssize_t) size);

        (void) catalog_import_file(&h, name);

        return 0;
}
