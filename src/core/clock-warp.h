/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int clock_reset_timewarp(void);
void clock_apply_epoch(bool allow_backwards);
