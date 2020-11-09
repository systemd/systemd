/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/input.h>
#include <linux/types.h>

/* linux@c7dc65737c9a607d3e6f8478659876074ad129b8 (3.12) */
#ifndef EVIOCREVOKE
#define EVIOCREVOKE _IOW('E', 0x91, int)
#endif

/* linux@06a16293f71927f756dcf37558a79c0b05a91641 (4.4) */
#ifndef EVIOCSMASK
struct input_mask {
        __u32 type;
        __u32 codes_size;
        __u64 codes_ptr;
};

#define EVIOCGMASK _IOR('E', 0x92, struct input_mask)
#define EVIOCSMASK _IOW('E', 0x93, struct input_mask)
#endif

/* linux@7611392fe8ff95ecae528b01a815ae3d72ca6b95 (3.17) */
#ifndef INPUT_PROP_POINTING_STICK
#define INPUT_PROP_POINTING_STICK 0x05
#endif

/* linux@500d4160abe9a2e88b12e319c13ae3ebd1e18108 (4.0) */
#ifndef INPUT_PROP_ACCELEROMETER
#define INPUT_PROP_ACCELEROMETER  0x06
#endif

/* linux@d09bbfd2a8408a995419dff0d2ba906013cf4cc9 (3.11) */
#ifndef BTN_DPAD_UP
#define BTN_DPAD_UP    0x220
#define BTN_DPAD_DOWN  0x221
#define BTN_DPAD_LEFT  0x222
#define BTN_DPAD_RIGHT 0x223
#endif

/* linux@358f24704f2f016af7d504b357cdf32606091d07 (3.13) */
#ifndef KEY_ALS_TOGGLE
#define KEY_ALS_TOGGLE 0x230
#endif
