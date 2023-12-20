/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

void hsv_to_rgb(
                double h, double s, double v,
                uint8_t* ret_r, uint8_t *ret_g, uint8_t *ret_b);
