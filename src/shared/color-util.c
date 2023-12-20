/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

#include "color-util.h"
#include "macro.h"

void rgb_to_hsv(double r, double g, double b,
                double *ret_h, double *ret_s, double *ret_v) {

        assert(r >= 0 && r <= 1);
        assert(g >= 0 && g <= 1);
        assert(b >= 0 && b <= 1);
        assert(ret_h);
        assert(ret_s);
        assert(ret_v);

        double max_color = fmax(r, fmax(g, b));
        double min_color = fmin(r, fmin(g, b));
        double delta = max_color - min_color;

        *ret_v = max_color * 100.0;

        if (max_color > 0)
                *ret_s = delta / max_color * 100.0;
        else {
                *ret_s = 0;
                *ret_h = NAN;
                return;
        }

        if (delta > 0) {
                if (r >= max_color)
                        *ret_h = 60 * fmod((g - b) / delta, 6);
                else if (g >= max_color)
                        *ret_h = 60 * (((b - r) / delta) + 2);
                else if (b >= max_color)
                        *ret_h = 60 * (((r - g) / delta) + 4);

                *ret_h = fmod(*ret_h, 360);
        } else
                *ret_h = NAN;
}

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
