/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "macro.h"
#include "ring.h"

#define RING_MASK(_r, _v) ((_v) & ((_r)->size - 1))

void ring_flush(struct ring *r) {
        assert(r);

        r->start = 0;
        r->used = 0;
}

void ring_clear(struct ring *r) {
        free(r->buf);
        zero(*r);
}

/*
 * Get data pointers for current ring-buffer data. @vec must be an array of 2
 * iovec objects. They are filled according to the data available in the
 * ring-buffer. 0, 1 or 2 is returned according to the number of iovec objects
 * that were filled (0 meaning buffer is empty).
 *
 * Hint: "struct iovec" is defined in <sys/uio.h> and looks like this:
 *     struct iovec {
 *         void *iov_base;
 *         size_t iov_len;
 *     };
 */
size_t ring_peek(struct ring *r, struct iovec *vec) {
        assert(r);

        if (r->used == 0) {
                return 0;
        } else if (r->start + r->used <= r->size) {
                if (vec) {
                        vec[0].iov_base = &r->buf[r->start];
                        vec[0].iov_len = r->used;
                }
                return 1;
        } else {
                if (vec) {
                        vec[0].iov_base = &r->buf[r->start];
                        vec[0].iov_len = r->size - r->start;
                        vec[1].iov_base = r->buf;
                        vec[1].iov_len = r->used - (r->size - r->start);
                }
                return 2;
        }
}

/*
 * Copy data from the ring buffer into the linear external buffer @buf. Copy
 * at most @size bytes. If the ring buffer size is smaller, copy less bytes and
 * return the number of bytes copied.
 */
size_t ring_copy(struct ring *r, void *buf, size_t size) {
        size_t l;

        assert(r);
        assert(buf);

        if (size > r->used)
                size = r->used;

        if (size > 0) {
                l = r->size - r->start;
                if (size <= l) {
                        memcpy(buf, &r->buf[r->start], size);
                } else {
                        memcpy(buf, &r->buf[r->start], l);
                        memcpy((uint8_t*)buf + l, r->buf, size - l);
                }
        }

        return size;
}

/*
 * Resize ring-buffer to size @nsize. @nsize must be a power-of-2, otherwise
 * ring operations will behave incorrectly.
 */
static int ring_resize(struct ring *r, size_t nsize) {
        uint8_t *buf;
        size_t l;

        assert(r);
        assert(nsize > 0);

        buf = malloc(nsize);
        if (!buf)
                return -ENOMEM;

        if (r->used > 0) {
                l = r->size - r->start;
                if (r->used <= l) {
                        memcpy(buf, &r->buf[r->start], r->used);
                } else {
                        memcpy(buf, &r->buf[r->start], l);
                        memcpy(&buf[l], r->buf, r->used - l);
                }
        }

        free(r->buf);
        r->buf = buf;
        r->size = nsize;
        r->start = 0;

        return 0;
}

/*
 * Resize ring-buffer to provide enough room for @add bytes of new data. This
 * resizes the buffer if it is too small. It returns -ENOMEM on OOM and 0 on
 * success.
 */
static int ring_grow(struct ring *r, size_t add) {
        size_t need;

        assert(r);

        if (r->size - r->used >= add)
                return 0;

        need = r->used + add;
        if (need <= r->used)
                return -ENOMEM;
        else if (need < 4096)
                need = 4096;

        need = ALIGN_POWER2(need);
        if (need == 0)
                return -ENOMEM;

        return ring_resize(r, need);
}

/*
 * Push @len bytes from @u8 into the ring buffer. The buffer is resized if it
 * is too small. -ENOMEM is returned on OOM, 0 on success.
 */
int ring_push(struct ring *r, const void *u8, size_t size) {
        int err;
        size_t pos, l;

        assert(r);
        assert(u8);

        if (size == 0)
                return 0;

        err = ring_grow(r, size);
        if (err < 0)
                return err;

        pos = RING_MASK(r, r->start + r->used);
        l = r->size - pos;
        if (l >= size) {
                memcpy(&r->buf[pos], u8, size);
        } else {
                memcpy(&r->buf[pos], u8, l);
                memcpy(r->buf, (const uint8_t*)u8 + l, size - l);
        }

        r->used += size;

        return 0;
}

/*
 * Remove @len bytes from the start of the ring-buffer. Note that we protect
 * against overflows so removing more bytes than available is safe.
 */
void ring_pull(struct ring *r, size_t size) {
        assert(r);

        if (size > r->used)
                size = r->used;

        r->start = RING_MASK(r, r->start + size);
        r->used -= size;
}
