/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering
***/

/* A type-safe atomic refcounter.
 *
 * DO NOT USE THIS UNLESS YOU ACTUALLY CARE ABOUT THREAD SAFETY! */

typedef struct {
        volatile unsigned _value;
} RefCount;

#define REFCNT_GET(r) ((r)._value)
#define REFCNT_INC(r) (__sync_add_and_fetch(&(r)._value, 1))
#define REFCNT_DEC(r) (__sync_sub_and_fetch(&(r)._value, 1))

#define REFCNT_INIT ((RefCount) { ._value = 1 })
