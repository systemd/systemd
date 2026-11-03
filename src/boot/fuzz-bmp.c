/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bmp.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        const struct bmp_dib *dib;
        const struct bmp_map *map;
        const uint8_t *pixmap;

        if (outside_size_range(size, 0, 64 * 1024))
                return 0;

        fuzz_setup_logging();

        if (bmp_parse_header(data, size, &dib, &map, &pixmap) < 0)
                return 0;

        /* systemd-stub reads the DIB header through dib, the color map through map, and the pixels through
         * pixmap. */
        assert_se((const uint8_t*) dib == data + sizeof(struct bmp_file));
        assert_se((const uint8_t*) map <= pixmap);
        assert_se(pixmap <= data + size);

        return 0;
}
