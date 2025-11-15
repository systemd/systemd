/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* This is for avoiding conflicts between musl's sys/prctl.h and linux/prctl.h. */

#include <features.h>
#include <linux/prctl.h>        /* IWYU pragma: export */

int prctl(int, ...);
