/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "elf-util.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-core.XXXXXX";
        _cleanup_close_ int fd = -1;
        _cleanup_free_ char *buf = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *package_metadata = NULL;
        _cleanup_free_ char *out = NULL; /* out should be freed after f */
        _cleanup_fclose_ FILE *f = NULL;
        size_t out_size;
        int r;

        r = dlopen_dw();
        if (r < 0)
                return r;

        r = dlopen_elf();
        if (r < 0)
                return r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, data, size) == (ssize_t) size);
        (void) parse_elf(fd, NULL, &buf, &package_metadata);
        if (buf)
                assert_se(strlen(buf) >= 0);
        if (package_metadata) {
                f = open_memstream_unlocked(&out, &out_size);
                assert_se(f);
                json_variant_dump(package_metadata, JSON_FORMAT_NEWLINE|JSON_FORMAT_PRETTY, f, NULL);
        }

        return 0;
}
