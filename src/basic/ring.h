/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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


typedef struct Ring Ring;

struct Ring {
        uint8_t *buf;           /* buffer or NULL */
        size_t size;            /* actual size of @buf */
        size_t start;           /* start position of ring */
        size_t used;            /* number of actually used bytes */
};

/* flush buffer so it is empty again */
void ring_flush(Ring *r);

/* flush buffer, free allocated data and reset to initial state */
void ring_clear(Ring *r);

/* get pointers to buffer data and their length */
size_t ring_peek(Ring *r, struct iovec *vec);

/* copy data into external linear buffer */
size_t ring_copy(Ring *r, void *buf, size_t size);

/* push data to the end of the buffer */
int ring_push(Ring *r, const void *u8, size_t size);

/* pull data from the front of the buffer */
void ring_pull(Ring *r, size_t size);

/* return size of occupied buffer in bytes */
static inline size_t ring_get_size(Ring *r) {
        return r->used;
}
