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

/* A type-safe atomic refcounter */

typedef struct {
        volatile unsigned _value;
} RefCount;

#define REFCNT_GET(r) ((r)._value)
#define REFCNT_INC(r) (__sync_add_and_fetch(&(r)._value, 1))
#define REFCNT_DEC(r) (__sync_sub_and_fetch(&(r)._value, 1))

#define REFCNT_INIT ((RefCount) { ._value = 1 })
