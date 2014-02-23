/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Timezone file reading code from glibc 2.16.

  Copyright (C) 1991-2012 Free Software Foundation, Inc.
  Copyright 2012 Kay Sievers

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
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <endian.h>
#include <byteswap.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "time-dst.h"
#include "util.h"

/*
 * If tzh_version is '2' or greater, the above is followed by a second instance
 * of tzhead and a second instance of the data in which each coded transition
 * time uses 8 rather than 4 chars, then a POSIX-TZ-environment-variable-style
 * string for use in handling instants after the last transition time stored in
 * the file * (with nothing between the newlines if there is no POSIX
 * representation for such instants).
 */
#define TZ_MAGIC                "TZif"
struct tzhead {
        char tzh_magic[4];      /* TZ_MAGIC */
        char tzh_version[1];    /* '\0' or '2' as of 2005 */
        char tzh_reserved[15];  /* reserved--must be zero */
        char tzh_ttisgmtcnt[4]; /* coded number of trans. time flags */
        char tzh_ttisstdcnt[4]; /* coded number of trans. time flags */
        char tzh_leapcnt[4];    /* coded number of leap seconds */
        char tzh_timecnt[4];    /* coded number of transition times */
        char tzh_typecnt[4];    /* coded number of local time types */
        char tzh_charcnt[4];    /* coded number of abbr. chars */
};

struct ttinfo {
        long int offset;        /* Seconds east of GMT.  */
        unsigned char isdst;    /* Used to set tm_isdst.  */
        unsigned char idx;      /* Index into `zone_names'.  */
        unsigned char isstd;    /* Transition times are in standard time.  */
        unsigned char isgmt;    /* Transition times are in GMT.  */
};

struct leap {
        time_t transition;      /* Time the transition takes effect.  */
        long int change;        /* Seconds of correction to apply.  */
};

static inline int decode(const void *ptr) {
        return be32toh(*(int *)ptr);
}

static inline int64_t decode64(const void *ptr) {
        return be64toh(*(int64_t *)ptr);
}

int time_get_dst(time_t date, const char *tzfile,
                 time_t *switch_cur, char **zone_cur, bool *dst_cur,
                 time_t *switch_next, int *delta_next, char **zone_next, bool *dst_next) {
        unsigned char *type_idxs = 0;
        size_t num_types = 0;
        struct ttinfo *types = NULL;
        char *zone_names = NULL;
        struct stat st;
        size_t num_isstd, num_isgmt;
        struct tzhead tzhead;
        size_t chars;
        size_t i;
        size_t total_size;
        size_t types_idx;
        int trans_width = 4;
        size_t tzspec_len;
        size_t num_leaps;
        size_t lo, hi;
        size_t num_transitions = 0;
        _cleanup_free_ time_t *transitions = NULL;
        _cleanup_fclose_ FILE *f;

        f = fopen(tzfile, "re");
        if (f == NULL)
                return -errno;

        if (fstat(fileno(f), &st) < 0)
                return -errno;

read_again:
        if (fread((void *)&tzhead, sizeof(tzhead), 1, f) != 1 ||
            memcmp(tzhead.tzh_magic, TZ_MAGIC, sizeof(tzhead.tzh_magic)) != 0)
                return -EINVAL;

        num_transitions = (size_t)decode(tzhead.tzh_timecnt);
        num_types = (size_t)decode(tzhead.tzh_typecnt);
        chars = (size_t)decode(tzhead.tzh_charcnt);
        num_leaps = (size_t)decode(tzhead.tzh_leapcnt);
        num_isstd = (size_t)decode(tzhead.tzh_ttisstdcnt);
        num_isgmt = (size_t)decode(tzhead.tzh_ttisgmtcnt);

        /* For platforms with 64-bit time_t we use the new format if available.  */
        if (sizeof(time_t) == 8 && trans_width == 4 && tzhead.tzh_version[0] != '\0') {
                size_t to_skip;

                /* We use the 8-byte format.  */
                trans_width = 8;

                /* Position the stream before the second header.  */
                to_skip = (num_transitions * (4 + 1)
                           + num_types * 6
                           + chars
                           + num_leaps * 8 + num_isstd + num_isgmt);
                if (fseek(f, to_skip, SEEK_CUR) != 0)
                        return -EINVAL;

                goto read_again;
        }

        if (num_transitions > ((SIZE_MAX - (__alignof__(struct ttinfo) - 1)) / (sizeof(time_t) + 1)))
                 return -EINVAL;

        total_size = num_transitions * (sizeof(time_t) + 1);
        total_size = ((total_size + __alignof__(struct ttinfo) - 1) & ~(__alignof__(struct ttinfo) - 1));
        types_idx = total_size;
        if (num_leaps > (SIZE_MAX - total_size) / sizeof(struct ttinfo))
                return -EINVAL;

        total_size += num_types * sizeof(struct ttinfo);
        if (chars > SIZE_MAX - total_size)
                return -EINVAL;

        total_size += chars;
        if (__alignof__(struct leap) - 1 > SIZE_MAX - total_size)
                 return -EINVAL;

        total_size = ((total_size + __alignof__(struct leap) - 1) & ~(__alignof__(struct leap) - 1));
        if (num_leaps > (SIZE_MAX - total_size) / sizeof(struct leap))
                return -EINVAL;

        total_size += num_leaps * sizeof(struct leap);
        tzspec_len = 0;
        if (sizeof(time_t) == 8 && trans_width == 8) {
                off_t rem = st.st_size - ftello(f);

                if (rem < 0 || (size_t) rem < (num_transitions * (8 + 1) + num_types * 6 + chars))
                        return -EINVAL;
                tzspec_len = (size_t) rem - (num_transitions * (8 + 1) + num_types * 6 + chars);
                if (num_leaps > SIZE_MAX / 12 || tzspec_len < num_leaps * 12)
                        return -EINVAL;
                tzspec_len -= num_leaps * 12;
                if (tzspec_len < num_isstd)
                        return -EINVAL;
                tzspec_len -= num_isstd;
                if (tzspec_len == 0 || tzspec_len - 1 < num_isgmt)
                        return -EINVAL;
                tzspec_len -= num_isgmt + 1;
                if (SIZE_MAX - total_size < tzspec_len)
                        return -EINVAL;
        }

        transitions = malloc0(total_size + tzspec_len);
        if (transitions == NULL)
                return -EINVAL;

        type_idxs = (unsigned char *)transitions + (num_transitions
                                                    * sizeof(time_t));
        types = (struct ttinfo *)((char *)transitions + types_idx);
        zone_names = (char *)types + num_types * sizeof(struct ttinfo);

        if (sizeof(time_t) == 4 || trans_width == 8) {
                if (fread(transitions, trans_width + 1, num_transitions, f) != num_transitions)
                        return -EINVAL;
        } else {
                if (fread(transitions, 4, num_transitions, f) != num_transitions ||
                    fread(type_idxs, 1, num_transitions, f) != num_transitions)
                        return -EINVAL;
        }

        /* Check for bogus indices in the data file, so we can hereafter
           safely use type_idxs[T] as indices into `types' and never crash.  */
        for (i = 0; i < num_transitions; ++i)
                if (type_idxs[i] >= num_types)
                        return -EINVAL;

        if (BYTE_ORDER == BIG_ENDIAN ? sizeof(time_t) == 8 && trans_width == 4
                                     : sizeof(time_t) == 4 || trans_width == 4) {
                /* Decode the transition times, stored as 4-byte integers in
                   network (big-endian) byte order.  We work from the end of
                   the array so as not to clobber the next element to be
                   processed when sizeof (time_t) > 4.  */
                i = num_transitions;
                while (i-- > 0)
                        transitions[i] = decode((char *)transitions + i * 4);
        } else if (BYTE_ORDER != BIG_ENDIAN && sizeof(time_t) == 8) {
                /* Decode the transition times, stored as 8-byte integers in
                   network (big-endian) byte order.  */
                for (i = 0; i < num_transitions; ++i)
                        transitions[i] = decode64((char *)transitions + i * 8);
        }

        for (i = 0; i < num_types; ++i) {
                unsigned char x[4];
                int c;

                if (fread(x, 1, sizeof(x), f) != sizeof(x))
                        return -EINVAL;
                c = getc(f);
                if ((unsigned int)c > 1u)
                        return -EINVAL;
                types[i].isdst = c;
                c = getc(f);
                if ((size_t) c > chars)
                        /* Bogus index in data file.  */
                        return -EINVAL;
                types[i].idx = c;
                types[i].offset = (long int)decode(x);
        }

        if (fread(zone_names, 1, chars, f) != chars)
                return -EINVAL;

        for (i = 0; i < num_isstd; ++i) {
                int c = getc(f);
                if (c == EOF)
                        return -EINVAL;
                types[i].isstd = c != 0;
        }

        while (i < num_types)
                types[i++].isstd = 0;

        for (i = 0; i < num_isgmt; ++i) {
                int c = getc(f);
                if (c == EOF)
                        return -EINVAL;
                types[i].isgmt = c != 0;
        }

        while (i < num_types)
                types[i++].isgmt = 0;

        if (num_transitions == 0)
               return -EINVAL;

        if (date < transitions[0] || date >= transitions[num_transitions - 1])
               return -EINVAL;

        /* Find the first transition after TIMER, and
           then pick the type of the transition before it.  */
        lo = 0;
        hi = num_transitions - 1;

        /* Assume that DST is changing twice a year and guess initial
           search spot from it.
           Half of a gregorian year has on average 365.2425 * 86400 / 2
           = 15778476 seconds.  */
        i = (transitions[num_transitions - 1] - date) / 15778476;
        if (i < num_transitions) {
                i = num_transitions - 1 - i;
                if (date < transitions[i]) {
                        if (i < 10 || date >= transitions[i - 10]) {
                                /* Linear search.  */
                                while (date < transitions[i - 1])
                                        i--;
                                goto found;
                        }
                        hi = i - 10;
                } else {
                        if (i + 10 >= num_transitions || date < transitions[i + 10]) {
                                /* Linear search.  */
                                while (date >= transitions[i])
                                        i++;
                                goto found;
                        }
                        lo = i + 10;
                }
        }

        /* Binary search. */
        while (lo + 1 < hi) {
                i = (lo + hi) / 2;
                if (date < transitions[i])
                        hi = i;
                else
                        lo = i;
        }
        i = hi;

found:
        if (switch_cur)
                *switch_cur = transitions[i-1];
        if (zone_cur)
                *zone_cur = strdup(&zone_names[types[type_idxs[i - 1]].idx]);
        if (dst_cur)
                *dst_cur = types[type_idxs[i-1]].isdst;

        if (switch_next)
                *switch_next = transitions[i];
        if (delta_next)
                *delta_next = (types[type_idxs[i]].offset - types[type_idxs[i-1]].offset) / 60;
        if (zone_next)
                *zone_next = strdup(&zone_names[types[type_idxs[i]].idx]);
        if (dst_next)
                *dst_next = types[type_idxs[i]].isdst;

        return 0;
}
