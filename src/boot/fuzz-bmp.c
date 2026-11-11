/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>

#include "bmp.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        const struct bmp_dib *dib;
        const struct bmp_map *map;
        const uint8_t *pixmap;

        if (outside_size_range(size, /* lower= */ 0, 64 * 1024))
                return 0;

        fuzz_setup_logging();

        if (bmp_parse_header(data, size, &dib, &map, &pixmap) < 0)
                return 0;

        /* systemd-stub reads the DIB header through dib, the color map through map, and the pixels through
         * pixmap. */
        assert_se((const uint8_t*) dib == data + sizeof(struct bmp_file));
        assert_se((const uint8_t*) map <= pixmap);
        assert_se(pixmap <= data + size);

        uint32_t x = le32toh(dib->x), y = le32toh(dib->y);
        uint16_t depth = le16toh(dib->depth);
        uint64_t row_size = ((uint64_t) depth * x + 31) / 32 * 4;
        assert_se(y > 0);
        assert_se(row_size > 0);
        assert_se(row_size <= (uint64_t) (data + size - pixmap) / y);

        if (IN_SET(depth, 1, 4, 8))
                assert_se((size_t) (pixmap - (const uint8_t*) map) >= sizeof(struct bmp_map) << depth);

        return 0;
}
