/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "color-util.h"
#include "math-util.h"

void rgb_to_hsv(double r, double g, double b,
                double *ret_h, double *ret_s, double *ret_v) {

        assert(r >= 0 && r <= 1);
        assert(g >= 0 && g <= 1);
        assert(b >= 0 && b <= 1);

        double max_color = MAX(r, MAX(g, b));
        double min_color = MIN(r, MIN(g, b));
        double delta = max_color - min_color;

        if (ret_v)
                *ret_v = max_color * 100.0;

        if (max_color <= 0) {
                if (ret_s)
                        *ret_s = 0;
                if (ret_h)
                        *ret_h = NAN;
                return;
        }

        if (ret_s)
                *ret_s = delta / max_color * 100.0;

        if (ret_h) {
                if (delta > 0) {
                        if (r >= max_color)
                                *ret_h = 60 * (g - b) / delta;
                        else if (g >= max_color)
                                *ret_h = 60 * (((b - r) / delta) + 2);
                        else /* b >= max_color */
                                *ret_h = 60 * (((r - g) / delta) + 4);

                        /* The r-max branch produces (-60, 60); fold the negative half up. */
                        if (*ret_h < 0)
                                *ret_h += 360;
                } else
                        *ret_h = NAN;
        }
}

void hsv_to_rgb(double h, double s, double v,
                uint8_t* ret_r, uint8_t *ret_g, uint8_t *ret_b) {

        double c, x, m, r, g, b;

        assert(h >= 0 && h <= 360);
        assert(s >= 0 && s <= 100);
        assert(v >= 0 && v <= 100);
        assert(ret_r);
        assert(ret_g);
        assert(ret_b);

        c = (s / 100.0) * (v / 100.0);
        m = (v / 100) - c;

        /* Split h into sector index k ∈ [0, 6] and fractional offset f ∈ [0, 1) within the sector.
         * Within each sector exactly one of {r, g, b} equals c, one equals 0, and the third (x)
         * ramps linearly between them — ascending in even sectors, descending in odd. h == 360 is
         * the cyclic boundary equivalent to h == 0, and maps to sector 0. */
        double seg = h / 60.0;
        int k = (int) seg % 6;
        double f = seg - (int) seg;
        x = c * (k & 1 ? 1.0 - f : f);

        switch (k) {
        case 0:  r = c;   g = x;   b = 0.0; break;
        case 1:  r = x;   g = c;   b = 0.0; break;
        case 2:  r = 0.0; g = c;   b = x;   break;
        case 3:  r = 0.0; g = x;   b = c;   break;
        case 4:  r = x;   g = 0.0; b = c;   break;
        default: r = c;   g = 0.0; b = x;   break;
        }

        *ret_r = (uint8_t) ((r + m) * 255);
        *ret_g = (uint8_t) ((g + m) * 255);
        *ret_b = (uint8_t) ((b + m) * 255);
}
