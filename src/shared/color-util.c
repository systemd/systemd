/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

#include "color-util.h"
#include "macro.h"

void hsv_to_rgb(double h, double s, double v,
                uint8_t* ret_r, uint8_t *ret_g, uint8_t *ret_b) {

        double c, x, m, r, g, b;

        assert(s >= 0 && s <= 100);
        assert(v >= 0 && v <= 100);
        assert(ret_r);
        assert(ret_g);
        assert(ret_b);

        h = fmod(h, 360);
        c = (s / 100.0) * (v / 100.0);
        x = c * (1 - fabs(fmod(h / 60.0, 2) - 1));
        m = (v / 100) - c;

        if (h >= 0 && h < 60)
                r = c, g = x, b = 0.0;
        else if (h >= 60 && h < 120)
                r = x, g = c, b = 0.0;
        else if (h >= 120 && h < 180)
                r = 0.0, g = c, b = x;
        else if (h >= 180 && h < 240)
                r = 0.0, g = x, b = c;
        else if (h >= 240 && h < 300)
                r = x, g = 0.0, b = c;
        else
                r = c, g = 0.0, b = x;

        *ret_r = (uint8_t) ((r + m) * 255);
        *ret_g = (uint8_t) ((g + m) * 255);
        *ret_b = (uint8_t) ((b + m) * 255);
}
