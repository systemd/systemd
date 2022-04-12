/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/hidraw.h>

/* Proposed, pending */
#ifndef HIDIOCREVOKE
#define HIDIOCREVOKE _IOW('H', 0x0D, int)
#endif
