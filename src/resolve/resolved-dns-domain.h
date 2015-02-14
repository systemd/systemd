/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#pragma once


#include "hashmap.h"
#include "in-addr-util.h"

#define DNS_LABEL_MAX 63
#define DNS_NAME_MAX 255

int dns_label_unescape(const char **name, char *dest, size_t sz);
int dns_label_escape(const char *p, size_t l, char **ret);

int dns_label_apply_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);
int dns_label_undo_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);

int dns_name_normalize(const char *s, char **_ret);

unsigned long dns_name_hash_func(const void *s, const uint8_t hash_key[HASH_KEY_SIZE]);
int dns_name_compare_func(const void *a, const void *b);
extern const struct hash_ops dns_name_hash_ops;

int dns_name_equal(const char *x, const char *y);
int dns_name_endswith(const char *name, const char *suffix);

int dns_name_reverse(int family, const union in_addr_union *a, char **ret);
int dns_name_address(const char *p, int *family, union in_addr_union *a);

int dns_name_root(const char *name);
int dns_name_single_label(const char *name);
