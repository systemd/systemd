/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitmap.h"
#include "tests.h"

int main(int argc, const char *argv[]) {
        _cleanup_bitmap_free_ Bitmap *b = NULL, *b2 = NULL;
        unsigned n = UINT_MAX, i = 0;

        test_setup_logging(LOG_DEBUG);

        b = bitmap_new();
        assert_se(b);

        ASSERT_EQ(bitmap_ensure_allocated(&b), 0);
        b = bitmap_free(b);
        ASSERT_EQ(bitmap_ensure_allocated(&b), 0);

        ASSERT_FALSE(bitmap_isset(b, 0));
        ASSERT_FALSE(bitmap_isset(b, 1));
        ASSERT_FALSE(bitmap_isset(b, 256));
        ASSERT_TRUE(bitmap_isclear(b));

        ASSERT_EQ(bitmap_set(b, 0), 0);
        ASSERT_TRUE(bitmap_isset(b, 0));
        ASSERT_FALSE(bitmap_isclear(b));
        bitmap_unset(b, 0);
        ASSERT_FALSE(bitmap_isset(b, 0));
        ASSERT_TRUE(bitmap_isclear(b));

        ASSERT_EQ(bitmap_set(b, 1), 0);
        ASSERT_TRUE(bitmap_isset(b, 1));
        ASSERT_FALSE(bitmap_isclear(b));
        bitmap_unset(b, 1);
        ASSERT_FALSE(bitmap_isset(b, 1));
        ASSERT_TRUE(bitmap_isclear(b));

        ASSERT_EQ(bitmap_set(b, 256), 0);
        ASSERT_TRUE(bitmap_isset(b, 256));
        ASSERT_FALSE(bitmap_isclear(b));
        bitmap_unset(b, 256);
        ASSERT_FALSE(bitmap_isset(b, 256));
        ASSERT_TRUE(bitmap_isclear(b));

        ASSERT_EQ(bitmap_set(b, 32), 0);
        bitmap_unset(b, 0);
        ASSERT_TRUE(bitmap_isset(b, 32));
        bitmap_unset(b, 32);

        BITMAP_FOREACH(n, NULL)
                assert_not_reached();

        ASSERT_EQ(bitmap_set(b, 0), 0);
        ASSERT_EQ(bitmap_set(b, 1), 0);
        ASSERT_EQ(bitmap_set(b, 256), 0);

        BITMAP_FOREACH(n, b) {
                ASSERT_EQ(n, i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = UINT_MAX;
        }

        ASSERT_EQ(i, UINT_MAX);

        i = 0;

        BITMAP_FOREACH(n, b) {
                ASSERT_EQ(n, i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = UINT_MAX;
        }

        ASSERT_EQ(i, UINT_MAX);

        b2 = bitmap_copy(b);
        assert_se(b2);
        ASSERT_TRUE(bitmap_equal(b, b2));
        ASSERT_TRUE(bitmap_equal(b, b));
        ASSERT_FALSE(bitmap_equal(b, NULL));
        ASSERT_FALSE(bitmap_equal(NULL, b));
        ASSERT_TRUE(bitmap_equal(NULL, NULL));

        bitmap_clear(b);
        ASSERT_TRUE(bitmap_isclear(b));
        ASSERT_FALSE(bitmap_equal(b, b2));
        b2 = bitmap_free(b2);

        assert_se(bitmap_set(b, UINT_MAX) == -ERANGE);

        b = bitmap_free(b);
        ASSERT_EQ(bitmap_ensure_allocated(&b), 0);
        ASSERT_EQ(bitmap_ensure_allocated(&b2), 0);

        assert_se(bitmap_equal(b, b2));
        ASSERT_EQ(bitmap_set(b, 0), 0);
        bitmap_unset(b, 0);
        assert_se(bitmap_equal(b, b2));

        ASSERT_EQ(bitmap_set(b, 1), 0);
        bitmap_clear(b);
        assert_se(bitmap_equal(b, b2));

        ASSERT_EQ(bitmap_set(b, 0), 0);
        ASSERT_EQ(bitmap_set(b2, 0), 0);
        assert_se(bitmap_equal(b, b2));

        return 0;
}
