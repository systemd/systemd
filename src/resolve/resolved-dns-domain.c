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

#include "resolved-dns-domain.h"

int dns_label_unescape(const char **name, char *dest, size_t sz) {
        const char *n;
        char *d;
        int r = 0;

        assert(name);
        assert(*name);
        assert(dest);

        n = *name;
        d = dest;

        for (;;) {
                if (*n == '.') {
                        n++;
                        break;
                }

                if (*n == 0)
                        break;

                if (sz <= 0)
                        return -ENOSPC;

                if (r >= DNS_LABEL_MAX)
                        return -EINVAL;

                if (*n == '\\') {
                        /* Escaped character */

                        n++;

                        if (*n == 0)
                                /* Ending NUL */
                                return -EINVAL;

                        else if (*n == '\\' || *n == '.') {
                                /* Escaped backslash or dot */
                                *(d++) = *(n++);
                                sz--;
                                r++;

                        } else if (n[0] >= '0' && n[0] <= '9') {
                                unsigned k;

                                /* Escaped literal ASCII character */

                                if (!(n[1] >= '0' && n[1] <= '9') ||
                                    !(n[2] >= '0' && n[2] <= '9'))
                                        return -EINVAL;

                                k = ((unsigned) (n[0] - '0') * 100) +
                                        ((unsigned) (n[1] - '0') * 10) +
                                        ((unsigned) (n[2] - '0'));

                                /* Don't allow CC characters or anything that doesn't fit in 8bit */
                                if (k < ' ' || k > 255 || k == 127)
                                        return -EINVAL;

                                *(d++) = (char) k;
                                sz--;
                                r++;

                                n += 3;
                        } else
                                return -EINVAL;

                } else if (*n >= ' ' && *n != 127) {

                        /* Normal character */
                        *(d++) = *(n++);
                        sz--;
                        r++;
                } else
                        return -EINVAL;
        }

        /* Empty label that is not at the end? */
        if (r == 0 && *n)
                return -EINVAL;

        if (sz >= 1)
                *d = 0;

        *name = n;
        return r;
}

int dns_label_escape(const char *p, size_t l, char **ret) {
        _cleanup_free_ char *s = NULL;
        char *q;
        int r;

        assert(p);
        assert(ret);

        if (l > DNS_LABEL_MAX)
                return -EINVAL;

        s = malloc(l * 4 + 1);
        if (!s)
                return -ENOMEM;

        q = s;
        while (l > 0) {

                if (*p == '.' || *p == '\\') {

                        /* Dot or backslash */
                        *(q++) = '\\';
                        *(q++) = *p;

                } else if (*p == '_' ||
                           *p == '-' ||
                           (*p >= '0' && *p <= '9') ||
                           (*p >= 'a' && *p <= 'z') ||
                           (*p >= 'A' && *p <= 'Z')) {

                        /* Proper character */
                        *(q++) = *p;
                } else if (*p >= ' ' && *p != 127) {

                        /* Everything else */
                        *(q++) = '\\';
                        *(q++) = '0' + (char) ((unsigned) *p / 100);
                        *(q++) = '0' + (char) (((unsigned) *p / 10) % 10);
                        *(q++) = '0' + (char) ((unsigned) *p % 10);

                } else
                        return -EINVAL;

                p++;
                l--;
        }

        *q = 0;
        *ret = s;
        r = q - s;
        s = NULL;

        return r;
}

int dns_name_normalize(const char *s, char **_ret) {
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        const char *p = s;
        bool first = true;
        int r;

        assert(s);
        assert(_ret);

        for (;;) {
                _cleanup_free_ char *t = NULL;
                char label[DNS_LABEL_MAX];

                r = dns_label_unescape(&p, label, sizeof(label));
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (*p != 0)
                                return -EINVAL;
                        break;
                }

                r = dns_label_escape(label, r, &t);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(ret, allocated, n + !first + strlen(t) + 1))
                        return -ENOMEM;

                if (!first)
                        ret[n++] = '.';
                else
                        first = false;

                memcpy(ret + n, t, r);
                n += r;
        }

        if (n > DNS_NAME_MAX)
                return -EINVAL;

        if (!GREEDY_REALLOC(ret, allocated, n + 1))
                return -ENOMEM;

        ret[n] = 0;
        *_ret = ret;
        ret = NULL;

        return 0;
}

unsigned long dns_name_hash_func(const void *s, const uint8_t hash_key[HASH_KEY_SIZE]) {
        const char *p = s;
        unsigned long ul = hash_key[0];
        int r;

        assert(p);

        while (*p) {
                char label[DNS_LABEL_MAX+1];

                r = dns_label_unescape(&p, label, sizeof(label));
                if (r < 0)
                        break;

                label[r] = 0;
                ascii_strlower(label);

                ul = ul * hash_key[1] + ul + string_hash_func(label, hash_key);
        }

        return ul;
}

int dns_name_compare_func(const void *a, const void *b) {
        const char *x = a, *y = b;
        int r, q;

        assert(a);
        assert(b);

        for (;;) {
                char la[DNS_LABEL_MAX+1], lb[DNS_LABEL_MAX+1];

                if (*x == 0 && *y == 0)
                        return 0;

                r = dns_label_unescape(&x, la, sizeof(la));
                q = dns_label_unescape(&y, lb, sizeof(lb));
                if (r < 0 || q < 0)
                        return r - q;

                la[r] = lb[q] = 0;
                r = strcasecmp(la, lb);
                if (r != 0)
                        return r;
        }
}

int dns_name_equal(const char *x, const char *y) {
        int r, q;

        assert(x);
        assert(y);

        for (;;) {
                char la[DNS_LABEL_MAX+1], lb[DNS_LABEL_MAX+1];

                if (*x == 0 && *y == 0)
                        return true;

                r = dns_label_unescape(&x, la, sizeof(la));
                if (r < 0)
                        return r;

                q = dns_label_unescape(&y, lb, sizeof(lb));
                if (q < 0)
                        return q;

                la[r] = lb[q] = 0;
                if (strcasecmp(la, lb))
                        return false;
        }
}

int dns_name_endswith(const char *name, const char *suffix) {
        const char *n, *s, *saved_n = NULL;
        int r, q;

        assert(name);
        assert(suffix);

        n = name;
        s = suffix;

        for (;;) {
                char ln[DNS_LABEL_MAX+1], ls[DNS_LABEL_MAX+1];

                r = dns_label_unescape(&n, ln, sizeof(ln));
                if (r < 0)
                        return r;

                if (!saved_n)
                        saved_n = n;

                q = dns_label_unescape(&s, ls, sizeof(ls));
                if (r < 0)
                        return r;

                if (r == 0 && q == 0)
                        return true;
                if (r == 0 && saved_n == n)
                        return false;

                ln[r] = ls[q] = 0;

                if (r != q || strcasecmp(ln, ls)) {

                        /* Not the same, let's jump back, and try with the next label again */
                        s = suffix;
                        n = saved_n;
                        saved_n = NULL;
                }
        }
}

int dns_name_reverse(int family, const union in_addr_union *a, char **ret) {
        const uint8_t *p;
        int r;

        assert(a);
        assert(ret);

        p = (const uint8_t*) a;

        if (family == AF_INET)
                r = asprintf(ret, "%u.%u.%u.%u.in-addr.arpa", p[3], p[2], p[1], p[0]);
        else if (family == AF_INET6)
                r = asprintf(ret, "%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.%c.ip6.arpa",
                             hexchar(p[15] & 0xF), hexchar(p[15] >> 4), hexchar(p[14] & 0xF), hexchar(p[14] >> 4),
                             hexchar(p[13] & 0xF), hexchar(p[13] >> 4), hexchar(p[12] & 0xF), hexchar(p[12] >> 4),
                             hexchar(p[11] & 0xF), hexchar(p[11] >> 4), hexchar(p[10] & 0xF), hexchar(p[10] >> 4),
                             hexchar(p[ 9] & 0xF), hexchar(p[ 9] >> 4), hexchar(p[ 8] & 0xF), hexchar(p[ 8] >> 4),
                             hexchar(p[ 7] & 0xF), hexchar(p[ 7] >> 4), hexchar(p[ 6] & 0xF), hexchar(p[ 6] >> 4),
                             hexchar(p[ 5] & 0xF), hexchar(p[ 5] >> 4), hexchar(p[ 4] & 0xF), hexchar(p[ 4] >> 4),
                             hexchar(p[ 3] & 0xF), hexchar(p[ 3] >> 4), hexchar(p[ 2] & 0xF), hexchar(p[ 2] >> 4),
                             hexchar(p[ 1] & 0xF), hexchar(p[ 1] >> 4), hexchar(p[ 0] & 0xF), hexchar(p[ 0] >> 4));
        else
                return -EAFNOSUPPORT;
        if (r < 0)
                return -ENOMEM;

        return 0;
}

int dns_name_root(const char *name) {
        char label[DNS_LABEL_MAX+1];
        int r;

        assert(name);

        r = dns_label_unescape(&name, label, sizeof(label));
        if (r < 0)
                return r;

        return r == 0 && *name == 0;
}

int dns_name_single_label(const char *name) {
        char label[DNS_LABEL_MAX+1];
        int r;

        assert(name);

        r = dns_label_unescape(&name, label, sizeof(label));
        if (r < 0)
                return r;

        if (r == 0)
                return 0;

        r = dns_label_unescape(&name, label, sizeof(label));
        if (r < 0)
                return r;

        return r == 0 && *name == 0;
}
