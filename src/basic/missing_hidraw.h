/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/hidraw.h>

/* b31c9d9dc343146b9f4ce67b4eee748c49296e99 (6.12) */
#ifndef HIDIOCREVOKE
#define HIDIOCREVOKE _IOW('H', 0x0D, int)
#endif
