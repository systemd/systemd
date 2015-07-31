/***
  This file is part of systemd

  Copyright 2015 Tom Gundersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "bitmap.h"

int main(int argc, const char *argv[]) {
        _cleanup_bitmap_free_ Bitmap *b = NULL, *b2 = NULL;
        Iterator it;
        unsigned n = (unsigned) -1, i = 0;

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

        BITMAP_FOREACH(n, NULL, it)
                assert_not_reached("NULL bitmap");

        assert_se(bitmap_set(b, 0) == 0);
        assert_se(bitmap_set(b, 1) == 0);
        assert_se(bitmap_set(b, 256) == 0);

        BITMAP_FOREACH(n, b, it) {
                assert_se(n == i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = (unsigned) -1;
        }

        assert_se(i == (unsigned) -1);

        i = 0;

        BITMAP_FOREACH(n, b, it) {
                assert_se(n == i);
                if (i == 0)
                        i = 1;
                else if (i == 1)
                        i = 256;
                else if (i == 256)
                        i = (unsigned) -1;
        }

        assert_se(i == (unsigned) -1);

        bitmap_clear(b);
        assert_se(bitmap_isclear(b) == true);

        assert_se(bitmap_set(b, (unsigned) -1) == -ERANGE);

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
