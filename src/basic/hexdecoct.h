#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

char octchar(int x) _const_;
int unoctchar(char c) _const_;

char decchar(int x) _const_;
int undecchar(char c) _const_;

char hexchar(int x) _const_;
int unhexchar(char c) _const_;

char *hexmem(const void *p, size_t l);
int unhexmem(const char *p, size_t l, void **mem, size_t *len);

char base32hexchar(int x) _const_;
int unbase32hexchar(char c) _const_;

char base64char(int x) _const_;
int unbase64char(char c) _const_;

char *base32hexmem(const void *p, size_t l, bool padding);
int unbase32hexmem(const char *p, size_t l, bool padding, void **mem, size_t *len);

ssize_t base64mem(const void *p, size_t l, char **out);
int base64_append(char **prefix, int plen,
                  const void *p, size_t l,
                  int margin, int width);
int unbase64mem(const char *p, size_t l, void **mem, size_t *len);

void hexdump(FILE *f, const void *p, size_t s);
