/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <elf.h> /* IWYU pragma: export */

/* AT_HWCAP3 was added in glibc 2.39. */
#ifndef AT_HWCAP3
#define AT_HWCAP3 29
#endif
