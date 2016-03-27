/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef HAVE_GCRYPT
#include <gcrypt.h>

void initialize_libgcrypt(bool secmem);
int string_hashsum(const char *s, size_t len, int md_algorithm, char **out);
#endif

static inline int string_hashsum_sha224(const char *s, size_t len, char **out) {
#ifdef HAVE_GCRYPT
        return string_hashsum(s, len, GCRY_MD_SHA224, out);
#else
        return -EOPNOTSUPP;
#endif
}
