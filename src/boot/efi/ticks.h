/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <efilib.h>

UINT64 ticks_read(void);
UINT64 ticks_freq(void);
UINT64 time_usec(void);
