/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>

#include "bmp.h"
#include "tests.h"

typedef struct TestBmp {
        struct bmp_file file;
        uint8_t dib[SIZEOF_BMP_DIB];
        uint8_t pixels[8];
} _packed_ TestBmp;

/* A 2×1 image with 24 bits per pixel. Each row is padded to 4 bytes, so the pixel data has 8 bytes. */
static TestBmp make_bmp(void) {
        TestBmp bmp = {
                .file = {
                        .signature = { 'B', 'M' },
                        .size = htole32(sizeof(TestBmp)),
                        .offset = htole32(offsetof(TestBmp, pixels)),
                },
        };

        struct bmp_dib dib = {
                .size = htole32(SIZEOF_BMP_DIB),
                .x = htole32(2),
                .y = htole32(1),
                .planes = htole16(1),
                .depth = htole16(24),
        };
        memcpy(bmp.dib, &dib, sizeof(bmp.dib));

        return bmp;
}

static int parse(const TestBmp *bmp, size_t size) {
        return bmp_parse_header((const uint8_t*) bmp, size, /* ret_dib= */ NULL, /* ret_map= */ NULL, /* ret_pixmap= */ NULL);
}

static void set_dib_field(TestBmp *bmp, size_t offset, const void *value, size_t size) {
        memcpy(bmp->dib + offset, value, size);
}

TEST(valid) {
        TestBmp bmp = make_bmp();
        const struct bmp_dib *dib;
        const uint8_t *pixmap;

        ASSERT_OK(bmp_parse_header((const uint8_t*) &bmp, sizeof(bmp), &dib, /* ret_map= */ NULL, &pixmap));
        ASSERT_EQ(le32toh(dib->x), 2U);
        ASSERT_EQ(le32toh(dib->y), 1U);
        ASSERT_PTR_EQ(pixmap, bmp.pixels);
}

TEST(size_mismatch) {
        TestBmp bmp = make_bmp();

        ASSERT_ERROR(parse(&bmp, sizeof(bmp) - 1), EINVAL);
        ASSERT_ERROR(parse(&bmp, sizeof(struct bmp_file)), EINVAL);
}

TEST(signature) {
        TestBmp bmp = make_bmp();

        bmp.file.signature[1] = 'X';
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

TEST(negative_height) {
        TestBmp bmp = make_bmp();

        /* A negative height means that the rows are stored top to bottom, which systemd-stub doesn't
         * support. */
        uint32_t y = htole32((uint32_t) -1);
        set_dib_field(&bmp, offsetof(struct bmp_dib, y), &y, sizeof(y));
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

TEST(dib_larger_than_file) {
        TestBmp bmp = make_bmp();

        uint32_t dib_size = htole32(UINT32_MAX - 11), colors_used = htole32(13);
        set_dib_field(&bmp, offsetof(struct bmp_dib, size), &dib_size, sizeof(dib_size));
        set_dib_field(&bmp, offsetof(struct bmp_dib, colors_used), &colors_used, sizeof(colors_used));
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

TEST(unsupported_depth) {
        TestBmp bmp = make_bmp();

        uint16_t depth = htole16(2);
        set_dib_field(&bmp, offsetof(struct bmp_dib, depth), &depth, sizeof(depth));
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

TEST(compression) {
        TestBmp bmp = make_bmp();

        uint32_t compression = htole32(1);
        set_dib_field(&bmp, offsetof(struct bmp_dib, compression), &compression, sizeof(compression));
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

TEST(missing_color_map) {
        TestBmp bmp = make_bmp();

        /* An image with 8 bits per pixel needs a color map with 256 entries. */
        uint16_t depth = htole16(8);
        set_dib_field(&bmp, offsetof(struct bmp_dib, depth), &depth, sizeof(depth));
        ASSERT_ERROR(parse(&bmp, sizeof(bmp)), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
