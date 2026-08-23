/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "color-util.h"
#include "tests.h"

TEST(hsv_to_rgb) {
        uint8_t r, g, b;

        /* Black at any hue. */
        hsv_to_rgb(0, 0, 0, &r, &g, &b);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(g, 0);
        ASSERT_EQ(b, 0);

        hsv_to_rgb(60, 0, 0, &r, &g, &b);
        ASSERT_EQ(r, 0);
        ASSERT_EQ(g, 0);
        ASSERT_EQ(b, 0);

        /* White: s=0 must ignore hue. */
        hsv_to_rgb(0, 0, 100, &r, &g, &b);
        ASSERT_EQ(r, 255);
        ASSERT_EQ(g, 255);
        ASSERT_EQ(b, 255);

        hsv_to_rgb(180, 0, 100, &r, &g, &b);
        ASSERT_EQ(r, 255);
        ASSERT_EQ(g, 255);
        ASSERT_EQ(b, 255);

        /* Pure primary and secondary colors — one per sector boundary. */
        hsv_to_rgb(0, 100, 100, &r, &g, &b);            /* red     */
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 0);   ASSERT_EQ(b, 0);
        hsv_to_rgb(60, 100, 100, &r, &g, &b);           /* yellow  */
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 255); ASSERT_EQ(b, 0);
        hsv_to_rgb(120, 100, 100, &r, &g, &b);          /* green   */
        ASSERT_EQ(r, 0);   ASSERT_EQ(g, 255); ASSERT_EQ(b, 0);
        hsv_to_rgb(180, 100, 100, &r, &g, &b);          /* cyan    */
        ASSERT_EQ(r, 0);   ASSERT_EQ(g, 255); ASSERT_EQ(b, 255);
        hsv_to_rgb(240, 100, 100, &r, &g, &b);          /* blue    */
        ASSERT_EQ(r, 0);   ASSERT_EQ(g, 0);   ASSERT_EQ(b, 255);
        hsv_to_rgb(300, 100, 100, &r, &g, &b);          /* magenta */
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 0);   ASSERT_EQ(b, 255);

        /* Sector midpoints. Catches inverted ramp direction (k & 1 ? 1-f : f) in any single
         * sector — a regression would shift exactly one channel by ±half-intensity. */
        hsv_to_rgb(30, 100, 100, &r, &g, &b);           /* orange       — sector 0 */
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 127); ASSERT_EQ(b, 0);
        hsv_to_rgb(90, 100, 100, &r, &g, &b);           /* chartreuse   — sector 1 */
        ASSERT_EQ(r, 127); ASSERT_EQ(g, 255); ASSERT_EQ(b, 0);
        hsv_to_rgb(150, 100, 100, &r, &g, &b);          /* spring green — sector 2 */
        ASSERT_EQ(r, 0);   ASSERT_EQ(g, 255); ASSERT_EQ(b, 127);
        hsv_to_rgb(210, 100, 100, &r, &g, &b);          /* azure        — sector 3 */
        ASSERT_EQ(r, 0);   ASSERT_EQ(g, 127); ASSERT_EQ(b, 255);
        hsv_to_rgb(270, 100, 100, &r, &g, &b);          /* violet       — sector 4 */
        ASSERT_EQ(r, 127); ASSERT_EQ(g, 0);   ASSERT_EQ(b, 255);
        hsv_to_rgb(330, 100, 100, &r, &g, &b);          /* rose         — sector 5 */
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 0);   ASSERT_EQ(b, 127);

        /* Just below 360 — ensures (int) seg stays in sector 5 and doesn't wrap to 6. */
        hsv_to_rgb(359.5, 100, 100, &r, &g, &b);
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 0); ASSERT_EQ(b, 2);

        /* Exactly 360 — cyclic boundary, equivalent to 0 (red). Callers like color_for_pcr() in
         * pcrlock.c can reach this via floating-point arithmetic (e.g. 360.0/23*23 == 360.0). */
        hsv_to_rgb(360, 100, 100, &r, &g, &b);
        ASSERT_EQ(r, 255); ASSERT_EQ(g, 0); ASSERT_EQ(b, 0);

        /* Non-trivial s/v: regression check for the multiply-and-cast path. */
        hsv_to_rgb(311, 52, 62, &r, &g, &b);
        ASSERT_EQ(r, 158); ASSERT_EQ(g, 75); ASSERT_EQ(b, 143);
}

TEST(rgb_to_hsv) {

        double h, s, v;

        /* Grayscale: delta == 0, h is NaN, s == 0. */
        rgb_to_hsv(0, 0, 0, &h, &s, &v);
        ASSERT_TRUE(s <= 0);
        ASSERT_TRUE(v <= 0);

        rgb_to_hsv(1, 1, 1, &h, &s, &v);
        ASSERT_TRUE(s <= 0);
        ASSERT_TRUE(v >= 100);

        rgb_to_hsv(0.5, 0.5, 0.5, &h, &s, &v);
        ASSERT_TRUE(s <= 0);
        ASSERT_TRUE(v >= 49 && v <= 51);

        /* Pure primary colors. */
        rgb_to_hsv(1, 0, 0, &h, &s, &v);                /* red */
        ASSERT_TRUE(h >= 0 && h <= 1);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        rgb_to_hsv(0, 1, 0, &h, &s, &v);                /* green */
        ASSERT_TRUE(h >= 119 && h <= 121);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        rgb_to_hsv(0, 0, 1, &h, &s, &v);                /* blue */
        ASSERT_TRUE(h >= 239 && h <= 241);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        /* Pure secondary colors — each exercises a different "max" branch. Magenta exercises
         * the negative-hue wrap from the r-max branch (raw value is -60). */
        rgb_to_hsv(1, 1, 0, &h, &s, &v);                /* yellow  — r-max branch, positive  */
        ASSERT_TRUE(h >= 59 && h <= 61);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        rgb_to_hsv(0, 1, 1, &h, &s, &v);                /* cyan    — g-max branch            */
        ASSERT_TRUE(h >= 179 && h <= 181);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        rgb_to_hsv(1, 0, 1, &h, &s, &v);                /* magenta — r-max branch, wrapped   */
        ASSERT_TRUE(h >= 299 && h <= 301);
        ASSERT_TRUE(s >= 100);
        ASSERT_TRUE(v >= 100);

        /* Mixed values. */
        rgb_to_hsv(0.5, 0.6, 0.7, &h, &s, &v);
        ASSERT_TRUE(h >= 209 && h <= 211);
        ASSERT_TRUE(s >= 28 && s <= 31);
        ASSERT_TRUE(v >= 69 && v <= 71);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
