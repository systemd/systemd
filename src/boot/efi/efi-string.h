/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <uchar.h>

size_t strnlen8(const char *s, size_t n);
size_t strnlen16(const char16_t *s, size_t n);

size_t strlen8(const char *s);
size_t strlen16(const char16_t *s);
