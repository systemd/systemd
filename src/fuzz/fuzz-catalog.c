/* SPDX-License-Identifier: LGPL-2.1+ */

#include "catalog.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-catalog.XXXXXX";
        _cleanup_close_ int fd = -1;
        _cleanup_ordered_hashmap_free_free_free_ OrderedHashmap *h = NULL;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(h = ordered_hashmap_new(&catalog_hash_ops));

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, data, size) == (ssize_t) size);

        (void) catalog_import_file(h, name);

        return 0;
}
