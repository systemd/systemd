/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Dummy EFI header for tests
 */
#pragma once

#undef SD_BOOT
#define SD_BOOT 1

#include "efi-fundamental.h"

#undef SD_BOOT
#define SD_BOOT 0
