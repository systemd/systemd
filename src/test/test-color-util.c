/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "color-util.h"
#include "tests.h"

TEST(hsv_to_rgb) {
        uint8_t r, g, b;

        hsv_to_rgb(0, 0, 0, &r, &g, &b);
        assert(r == 0 && g == 0 && b == 0);

        hsv_to_rgb(60, 0, 0, &r, &g, &b);
        assert(r == 0 && g == 0 && b == 0);

        hsv_to_rgb(0, 0, 100, &r, &g, &b);
        assert(r == 255 && g == 255 && b == 255);

        hsv_to_rgb(0, 100, 100, &r, &g, &b);
        assert(r == 255 && g == 0 && b == 0);

        hsv_to_rgb(120, 100, 100, &r, &g, &b);
        assert(r == 0 && g == 255 && b == 0);

        hsv_to_rgb(240, 100, 100, &r, &g, &b);
        assert(r == 0 && g == 0 && b == 255);

        hsv_to_rgb(311, 52, 62, &r, &g, &b);
        assert(r == 158 && g == 75 && b == 143);
}

TEST(rgb_to_hsv) {

        double h, s, v;
        rgb_to_hsv(0, 0, 0, &h, &s, &v);
        assert(s <= 0);
        assert(v <= 0);

        rgb_to_hsv(1, 1, 1, &h, &s, &v);
        assert(s <= 0);
        assert(v >= 100);

        rgb_to_hsv(1, 0, 0, &h, &s, &v);
        assert(h >= 359 || h <= 1);
        assert(s >= 100);
        assert(v >= 100);

        rgb_to_hsv(0, 1, 0, &h, &s, &v);
        assert(h >= 119 && h <= 121);
        assert(s >= 100);
        assert(v >= 100);

        rgb_to_hsv(0, 0, 1, &h, &s, &v);
        assert(h >= 239 && h <= 241);
        assert(s >= 100);
        assert(v >= 100);

        rgb_to_hsv(0.5, 0.6, 0.7, &h, &s, &v);
        assert(h >= 209 && h <= 211);
        assert(s >= 28 && s <= 31);
        assert(v >= 69 && v <= 71);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
