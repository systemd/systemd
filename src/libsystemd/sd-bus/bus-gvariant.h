/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

int bus_gvariant_get_size(const char *signature) _pure_;
int bus_gvariant_get_alignment(const char *signature) _pure_;
int bus_gvariant_is_fixed_size(const char *signature) _pure_;

size_t bus_gvariant_determine_word_size(size_t sz, size_t extra);
void bus_gvariant_write_word_le(void *p, size_t sz, size_t value);
size_t bus_gvariant_read_word_le(void *p, size_t sz);
