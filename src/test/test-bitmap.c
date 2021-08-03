/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitmap.h"

int main(int argc, const char *argv[]) {
        _cleanup_bitmap_free_ Bitmap *b = NULL, *b2 = NULL;
        unsigned n = UINT_MAX, i = 0;

        b = bitmap_new();
        assert_se(b);

        assert_se(bitmap_ensure_allocated(&b) == 0);
        bitmap_free(b);
        b = NULL;
        assert_se(bitmap_ensure_allocated(&b) == 0);

        assert_se(bitmap_isset(b, 0) == false);
        assert_se(bitmap_isset(b, 1) == false);
        assert_se(bitmap_isset(b, 256) == false);
        assert_se(bitmap_isclear(b) == true);

        assert_se(bitmap_set(b, 0) == 0);
        assert_se(bitmap_isset(b, 0) == true);
        assert_se(bitmap_isclear(b) == false);
        bitmap_unset(b, 0);
        assert_se(bitmap_isset(b, 0) == false);
        assert_se(bitmap_isclear(b) == true);

        assert_se(bitmap_set(b, 1) == 0);
        assert_se(bitmap_isset(b, 1) == true);
        assert_se(bitmap_isclear(b) == false);
        bitmap_unset(b, 1);
        assert_se(bitmap_isset(b, 1) == false);
        assert_se(bitmap_isclear(b) == true);

        assert_se(bitmap_set(b, 256) == 0);
        assert_se(bitmap_isset(b, 256) == true);
        assert_se(bitmap_isclear(b) == false);
        bitmap_unset(b, 256);
        assert_se(bitmap_isset(b, 256) == false);
        assert_se(bitmap_isclear(b) == true);

        assert_se(bitmap_set(b, 32) == 0);
        bitmap_unset(b, 0);
        assert_se(bitmap_isset(b, 32) == true);
        bitmap_unset(b, 32);

        BITMAP_FOREACH(n, NULL)
                assert_not_reached();

        assert_se(bitmap_set(b, 0) == 0);
        assert_se(bitmap_set(b, 1) == 0);
        assert_se(bitmap_set(b, 256) == 0);

        BITMAP_FOREACH(n, b) {
                assert_se(n == i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = UINT_MAX;
        }

        assert_se(i == UINT_MAX);

        i = 0;

        BITMAP_FOREACH(n, b) {
                assert_se(n == i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = UINT_MAX;
        }

        assert_se(i == UINT_MAX);

        b2 = bitmap_copy(b);
        assert_se(b2);
        assert_se(bitmap_equal(b, b2) == true);
        assert_se(bitmap_equal(b, b) == true);
        assert_se(bitmap_equal(b, NULL) == false);
        assert_se(bitmap_equal(NULL, b) == false);
        assert_se(bitmap_equal(NULL, NULL) == true);

        bitmap_clear(b);
        assert_se(bitmap_isclear(b) == true);
        assert_se(bitmap_equal(b, b2) == false);
        bitmap_free(b2);
        b2 = NULL;

        assert_se(bitmap_set(b, UINT_MAX) == -ERANGE);

        bitmap_free(b);
        b = NULL;
        assert_se(bitmap_ensure_allocated(&b) == 0);
        assert_se(bitmap_ensure_allocated(&b2) == 0);

        assert_se(bitmap_equal(b, b2));
        assert_se(bitmap_set(b, 0) == 0);
        bitmap_unset(b, 0);
        assert_se(bitmap_equal(b, b2));

        assert_se(bitmap_set(b, 1) == 0);
        bitmap_clear(b);
        assert_se(bitmap_equal(b, b2));

        assert_se(bitmap_set(b, 0) == 0);
        assert_se(bitmap_set(b2, 0) == 0);
        assert_se(bitmap_equal(b, b2));

        return 0;
}
