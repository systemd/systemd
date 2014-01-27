/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>

/*
 * Our default bloom filter has the following parameters:
 *
 * m=512   (bits in the filter)
 * k=8     (hash functions)
 *
 * We use SipHash24 as hash function with a number of (originally
 * randomized) but fixed hash keys.
 *
 */

#define DEFAULT_BLOOM_SIZE (512/8) /* m: filter size */
#define DEFAULT_BLOOM_N_HASH 8     /* k: number of hash functions */

void bloom_add_pair(uint64_t filter[], size_t size, unsigned n_hash, const char *a, const char *b);
void bloom_add_prefixes(uint64_t filter[], size_t size, unsigned n_hash, const char *a, const char *b, char sep);

bool bloom_validate_parameters(size_t size, unsigned n_hash);
