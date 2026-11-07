/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if SD_BOOT
#  include "util.h"
#else
#  include <endian.h>
#endif

#include "bmp.h"
#include "efivars.h"

int bmp_parse_header(
                const uint8_t *bmp,
                size_t size,
                const struct bmp_dib **ret_dib,
                const struct bmp_map **ret_map,
                const uint8_t **ret_pixmap) {

        assert(bmp);

        if (size < sizeof(struct bmp_file) + SIZEOF_BMP_DIB)
                return -EINVAL;

        /* check file header */
        const struct bmp_file *file = (const struct bmp_file *) bmp;
        uint32_t file_size = le32toh(file->size), offset = le32toh(file->offset);
        if (file->signature[0] != 'B' || file->signature[1] != 'M')
                return -EINVAL;
        if (file_size != size)
                return -EINVAL;
        if (file_size < offset)
                return -EINVAL;

        /* check device-independent bitmap */
        const struct bmp_dib *dib = (const struct bmp_dib *) (bmp + sizeof(struct bmp_file));
        uint32_t dib_size = le32toh(dib->size), x = le32toh(dib->x), y = le32toh(dib->y),
                compression = le32toh(dib->compression), colors_used = le32toh(dib->colors_used);
        uint16_t depth = le16toh(dib->depth);
        if (dib_size < SIZEOF_BMP_DIB)
                return -EINVAL;

        /* On 32-bit hosts, sizeof(struct bmp_file) + dib_size wraps around when dib_size is close to
         * UINT32_MAX. The checks of the color map offset below then pass for a header that ends past the
         * end of the file. */
        if (dib_size > size - sizeof(struct bmp_file))
                return -EINVAL;

        switch (depth) {
        case 1:
        case 4:
        case 8:
        case 24:
                if (compression != 0)
                        return -EINVAL;

                break;

        case 16:
        case 32:
                if (!IN_SET(compression, 0, 3))
                        return -EINVAL;

                break;

        default:
                return -EINVAL;
        }

        if (x == 0 || y == 0)
                return -EINVAL;

        /* Bound dimensions before computing row_size to prevent overflow
         * in the (size_t) depth * x multiplication on 32-bit. */
        if (x > (size_t) 64 * 1024 * 1024 / depth ||
            y > (size_t) 64 * 1024 * 1024 / depth / x)
                return -EINVAL;

        size_t row_size = ((size_t) depth * x + 31) / 32 * 4;
        if (file_size - offset < y * row_size)
                return -EINVAL;

        /* check color table */
        const struct bmp_map *map = (const struct bmp_map *) (bmp + sizeof(struct bmp_file) + dib_size);
        if (offset < sizeof(struct bmp_file) + dib_size)
                return -EINVAL;

        if (offset > sizeof(struct bmp_file) + dib_size) {
                uint32_t map_count = 0;

                if (colors_used)
                        map_count = colors_used;
                else if (IN_SET(depth, 1, 4, 8))
                        map_count = 1 << depth;

                size_t map_size = offset - (sizeof(struct bmp_file) + dib_size);
                if (map_size != sizeof(struct bmp_map) * map_count)
                        return -EINVAL;
        }

        /* Ensure there can be no OOB accesses in bmp_to_blt() due to malformed images (e.g.: color depth 8
         * but smaller color map) via map[*in]. */
        if (IN_SET(depth, 1, 4, 8) &&
            offset - (sizeof(struct bmp_file) + dib_size) < sizeof(struct bmp_map) * (1U << depth))
                return -EINVAL;

        if (ret_dib)
                *ret_dib = dib;
        if (ret_map)
                *ret_map = map;
        if (ret_pixmap)
                *ret_pixmap = bmp + offset;

        return 0;
}
