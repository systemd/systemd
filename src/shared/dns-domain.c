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

#ifdef HAVE_LIBIDN
#include <idna.h>
#include <stringprep.h>
#endif

#include "alloc-util.h"
#include "dns-domain.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

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

                } else if ((uint8_t) *n >= (uint8_t) ' ' && *n != 127) {

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

/* @label_terminal: terminal character of a label, updated to point to the terminal character of
 *                  the previous label (always skipping one dot) or to NULL if there are no more
 *                  labels. */
int dns_label_unescape_suffix(const char *name, const char **label_terminal, char *dest, size_t sz) {
        const char *terminal;
        int r;

        assert(name);
        assert(label_terminal);
        assert(dest);

        /* no more labels */
        if (!*label_terminal) {
                if (sz >= 1)
                        *dest = 0;

                return 0;
        }

        assert(**label_terminal == '.' || **label_terminal == 0);

        /* skip current terminal character */
        terminal = *label_terminal - 1;

        /* point name to the last label, and terminal to the preceding terminal symbol (or make it a NULL pointer) */
        for (;;) {
                if (terminal < name) {
                        /* reached the first label, so indicate that there are no more */
                        terminal = NULL;
                        break;
                }

                /* find the start of the last label */
                if (*terminal == '.') {
                        const char *y;
                        unsigned slashes = 0;

                        for (y = terminal - 1; y >= name && *y == '\\'; y--)
                                slashes ++;

                        if (slashes % 2 == 0) {
                                /* the '.' was not escaped */
                                name = terminal + 1;
                                break;
                        } else {
                                terminal = y;
                                continue;
                        }
                }

                terminal --;
        }

        r = dns_label_unescape(&name, dest, sz);
        if (r < 0)
                return r;

        *label_terminal = terminal;

        return r;
}

int dns_label_escape(const char *p, size_t l, char *dest, size_t sz) {
        char *q;

        /* DNS labels must be between 1 and 63 characters long. A
         * zero-length label does not exist. See RFC 2182, Section
         * 11. */

        if (l <= 0 || l > DNS_LABEL_MAX)
                return -EINVAL;
        if (sz < 1)
                return -ENOSPC;

        assert(p);
        assert(dest);

        q = dest;
        while (l > 0) {

                if (*p == '.' || *p == '\\') {

                        /* Dot or backslash */

                        if (sz < 3)
                                return -ENOSPC;

                        *(q++) = '\\';
                        *(q++) = *p;

                        sz -= 2;

                } else if (*p == '_' ||
                           *p == '-' ||
                           (*p >= '0' && *p <= '9') ||
                           (*p >= 'a' && *p <= 'z') ||
                           (*p >= 'A' && *p <= 'Z')) {

                        /* Proper character */

                        if (sz < 2)
                                return -ENOSPC;

                        *(q++) = *p;
                        sz -= 1;

                } else if ((uint8_t) *p >= (uint8_t) ' ' && *p != 127) {

                        /* Everything else */

                        if (sz < 5)
                                return -ENOSPC;

                        *(q++) = '\\';
                        *(q++) = '0' + (char) ((uint8_t) *p / 100);
                        *(q++) = '0' + (char) (((uint8_t) *p / 10) % 10);
                        *(q++) = '0' + (char) ((uint8_t) *p % 10);

                        sz -= 4;

                } else
                        return -EINVAL;

                p++;
                l--;
        }

        *q = 0;
        return (int) (q - dest);
}

int dns_label_escape_new(const char *p, size_t l, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(p);
        assert(ret);

        if (l <= 0 || l > DNS_LABEL_MAX)
                return -EINVAL;

        s = new(char, DNS_LABEL_ESCAPED_MAX);
        if (!s)
                return -ENOMEM;

        r = dns_label_escape(p, l, s, DNS_LABEL_ESCAPED_MAX);
        if (r < 0)
                return r;

        *ret = s;
        s = NULL;

        return r;
}

int dns_label_apply_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max) {
#ifdef HAVE_LIBIDN
        _cleanup_free_ uint32_t *input = NULL;
        size_t input_size, l;
        const char *p;
        bool contains_8bit = false;
        char buffer[DNS_LABEL_MAX+1];

        assert(encoded);
        assert(decoded);

        /* Converts an U-label into an A-label */

        if (encoded_size <= 0)
                return -EINVAL;

        for (p = encoded; p < encoded + encoded_size; p++)
                if ((uint8_t) *p > 127)
                        contains_8bit = true;

        if (!contains_8bit) {
                if (encoded_size > DNS_LABEL_MAX)
                        return -EINVAL;

                return 0;
        }

        input = stringprep_utf8_to_ucs4(encoded, encoded_size, &input_size);
        if (!input)
                return -ENOMEM;

        if (idna_to_ascii_4i(input, input_size, buffer, 0) != 0)
                return -EINVAL;

        l = strlen(buffer);

        /* Verify that the the result is not longer than one DNS label. */
        if (l <= 0 || l > DNS_LABEL_MAX)
                return -EINVAL;
        if (l > decoded_max)
                return -ENOSPC;

        memcpy(decoded, buffer, l);

        /* If there's room, append a trailing NUL byte, but only then */
        if (decoded_max > l)
                decoded[l] = 0;

        return (int) l;
#else
        return 0;
#endif
}

int dns_label_undo_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max) {
#ifdef HAVE_LIBIDN
        size_t input_size, output_size;
        _cleanup_free_ uint32_t *input = NULL;
        _cleanup_free_ char *result = NULL;
        uint32_t *output = NULL;
        size_t w;

        /* To be invoked after unescaping. Converts an A-label into an U-label. */

        assert(encoded);
        assert(decoded);

        if (encoded_size <= 0 || encoded_size > DNS_LABEL_MAX)
                return -EINVAL;

        if (encoded_size < sizeof(IDNA_ACE_PREFIX)-1)
                return 0;

        if (memcmp(encoded, IDNA_ACE_PREFIX, sizeof(IDNA_ACE_PREFIX) -1) != 0)
                return 0;

        input = stringprep_utf8_to_ucs4(encoded, encoded_size, &input_size);
        if (!input)
                return -ENOMEM;

        output_size = input_size;
        output = newa(uint32_t, output_size);

        idna_to_unicode_44i(input, input_size, output, &output_size, 0);

        result = stringprep_ucs4_to_utf8(output, output_size, NULL, &w);
        if (!result)
                return -ENOMEM;
        if (w <= 0)
                return -EINVAL;
        if (w > decoded_max)
                return -ENOSPC;

        memcpy(decoded, result, w);

        /* Append trailing NUL byte if there's space, but only then. */
        if (decoded_max > w)
                decoded[w] = 0;

        return w;
#else
        return 0;
#endif
}

int dns_name_concat(const char *a, const char *b, char **_ret) {
        _cleanup_free_ char *ret = NULL;
        size_t n = 0, allocated = 0;
        const char *p = a;
        bool first = true;
        int r;

        assert(a);

        for (;;) {
                char label[DNS_LABEL_MAX];
                int k;

                r = dns_label_unescape(&p, label, sizeof(label));
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (*p != 0)
                                return -EINVAL;

                        if (b) {
                                /* Now continue with the second string, if there is one */
                                p = b;
                                b = NULL;
                                continue;
                        }

                        break;
                }

                k = dns_label_undo_idna(label, r, label, sizeof(label));
                if (k < 0)
                        return k;
                if (k > 0)
                        r = k;

                if (_ret) {
                        if (!GREEDY_REALLOC(ret, allocated, n + !first + DNS_LABEL_ESCAPED_MAX))
                                return -ENOMEM;

                        r = dns_label_escape(label, r, ret + n + !first, DNS_LABEL_ESCAPED_MAX);
                        if (r < 0)
                                return r;

                        if (!first)
                                ret[n] = '.';
                } else {
                        char escaped[DNS_LABEL_ESCAPED_MAX];

                        r = dns_label_escape(label, r, escaped, sizeof(escaped));
                        if (r < 0)
                                return r;
                }

                if (!first)
                        n++;
                else
                        first = false;

                n += r;
        }

        if (_ret) {
                if (!GREEDY_REALLOC(ret, allocated, n + 1))
                        return -ENOMEM;

                ret[n] = 0;
                *_ret = ret;
                ret = NULL;
        }

        return 0;
}

void dns_name_hash_func(const void *s, struct siphash *state) {
        const char *p = s;
        int r;

        assert(p);

        while (*p) {
                char label[DNS_LABEL_MAX+1];
                int k;

                r = dns_label_unescape(&p, label, sizeof(label));
                if (r < 0)
                        break;

                k = dns_label_undo_idna(label, r, label, sizeof(label));
                if (k < 0)
                        break;
                if (k > 0)
                        r = k;

                if (r == 0)
                        break;

                label[r] = 0;
                ascii_strlower(label);

                string_hash_func(label, state);
        }

        /* enforce that all names are terminated by the empty label */
        string_hash_func("", state);
}

int dns_name_compare_func(const void *a, const void *b) {
        const char *x, *y;
        int r, q, k, w;

        assert(a);
        assert(b);

        x = (const char *) a + strlen(a);
        y = (const char *) b + strlen(b);

        for (;;) {
                char la[DNS_LABEL_MAX+1], lb[DNS_LABEL_MAX+1];

                if (x == NULL && y == NULL)
                        return 0;

                r = dns_label_unescape_suffix(a, &x, la, sizeof(la));
                q = dns_label_unescape_suffix(b, &y, lb, sizeof(lb));
                if (r < 0 || q < 0)
                        return r - q;

                k = dns_label_undo_idna(la, r, la, sizeof(la));
                w = dns_label_undo_idna(lb, q, lb, sizeof(lb));
                if (k < 0 || w < 0)
                        return k - w;
                if (k > 0)
                        r = k;
                if (w > 0)
                        r = w;

                la[r] = lb[q] = 0;
                r = strcasecmp(la, lb);
                if (r != 0)
                        return r;
        }
}

const struct hash_ops dns_name_hash_ops = {
        .hash = dns_name_hash_func,
        .compare = dns_name_compare_func
};

int dns_name_equal(const char *x, const char *y) {
        int r, q, k, w;

        assert(x);
        assert(y);

        for (;;) {
                char la[DNS_LABEL_MAX+1], lb[DNS_LABEL_MAX+1];

                if (*x == 0 && *y == 0)
                        return true;

                r = dns_label_unescape(&x, la, sizeof(la));
                if (r < 0)
                        return r;
                if (r > 0) {
                        k = dns_label_undo_idna(la, r, la, sizeof(la));
                        if (k < 0)
                                return k;
                        if (k > 0)
                                r = k;
                }

                q = dns_label_unescape(&y, lb, sizeof(lb));
                if (q < 0)
                        return q;
                if (q > 0) {
                        w = dns_label_undo_idna(lb, q, lb, sizeof(lb));
                        if (w < 0)
                                return w;
                        if (w > 0)
                                q = w;
                }

                /* If one name had fewer labels than the other, this
                 * will show up as empty label here, which the
                 * strcasecmp() below will properly consider different
                 * from a non-empty label. */

                la[r] = lb[q] = 0;
                if (strcasecmp(la, lb) != 0)
                        return false;
        }
}

int dns_name_endswith(const char *name, const char *suffix) {
        const char *n, *s, *saved_n = NULL;
        int r, q, k, w;

        assert(name);
        assert(suffix);

        n = name;
        s = suffix;

        for (;;) {
                char ln[DNS_LABEL_MAX+1], ls[DNS_LABEL_MAX+1];

                r = dns_label_unescape(&n, ln, sizeof(ln));
                if (r < 0)
                        return r;
                if (r > 0) {
                        k = dns_label_undo_idna(ln, r, ln, sizeof(ln));
                        if (k < 0)
                                return k;
                        if (k > 0)
                                r = k;
                }

                if (!saved_n)
                        saved_n = n;

                q = dns_label_unescape(&s, ls, sizeof(ls));
                if (q < 0)
                        return q;
                if (q > 0) {
                        w = dns_label_undo_idna(ls, q, ls, sizeof(ls));
                        if (w < 0)
                                return w;
                        if (w > 0)
                                q = w;
                }

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

int dns_name_change_suffix(const char *name, const char *old_suffix, const char *new_suffix, char **ret) {
        const char *n, *s, *saved_before = NULL, *saved_after = NULL, *prefix;
        int r, q, k, w;

        assert(name);
        assert(old_suffix);
        assert(new_suffix);
        assert(ret);

        n = name;
        s = old_suffix;

        for (;;) {
                char ln[DNS_LABEL_MAX+1], ls[DNS_LABEL_MAX+1];

                if (!saved_before)
                        saved_before = n;

                r = dns_label_unescape(&n, ln, sizeof(ln));
                if (r < 0)
                        return r;
                if (r > 0) {
                        k = dns_label_undo_idna(ln, r, ln, sizeof(ln));
                        if (k < 0)
                                return k;
                        if (k > 0)
                                r = k;
                }

                if (!saved_after)
                        saved_after = n;

                q = dns_label_unescape(&s, ls, sizeof(ls));
                if (q < 0)
                        return q;
                if (q > 0) {
                        w = dns_label_undo_idna(ls, q, ls, sizeof(ls));
                        if (w < 0)
                                return w;
                        if (w > 0)
                                q = w;
                }

                if (r == 0 && q == 0)
                        break;
                if (r == 0 && saved_after == n) {
                        *ret = NULL; /* doesn't match */
                        return 0;
                }

                ln[r] = ls[q] = 0;

                if (r != q || strcasecmp(ln, ls)) {

                        /* Not the same, let's jump back, and try with the next label again */
                        s = old_suffix;
                        n = saved_after;
                        saved_after = saved_before = NULL;
                }
        }

        /* Found it! Now generate the new name */
        prefix = strndupa(name, saved_before - name);

        r = dns_name_concat(prefix, new_suffix, ret);
        if (r < 0)
                return r;

        return 1;
}

int dns_name_between(const char *a, const char *b, const char *c) {
        int n;

        /* Determine if b is strictly greater than a and strictly smaller than c.
           We consider the order of names to be circular, so that if a is
           strictly greater than c, we consider b to be between them if it is
           either greater than a or smaller than c. This is how the canonical
           DNS name order used in NSEC records work. */

        n = dns_name_compare_func(a, c);
        if (n == 0)
                return -EINVAL;
        else if (n < 0)
                /*       a<---b--->c       */
                return dns_name_compare_func(a, b) < 0 &&
                       dns_name_compare_func(b, c) < 0;
        else
                /* <--b--c         a--b--> */
                return dns_name_compare_func(b, c) < 0 ||
                       dns_name_compare_func(a, b) < 0;
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

int dns_name_address(const char *p, int *family, union in_addr_union *address) {
        int r;

        assert(p);
        assert(family);
        assert(address);

        r = dns_name_endswith(p, "in-addr.arpa");
        if (r < 0)
                return r;
        if (r > 0) {
                uint8_t a[4];
                unsigned i;

                for (i = 0; i < ELEMENTSOF(a); i++) {
                        char label[DNS_LABEL_MAX+1];

                        r = dns_label_unescape(&p, label, sizeof(label));
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EINVAL;
                        if (r > 3)
                                return -EINVAL;

                        r = safe_atou8(label, &a[i]);
                        if (r < 0)
                                return r;
                }

                r = dns_name_equal(p, "in-addr.arpa");
                if (r <= 0)
                        return r;

                *family = AF_INET;
                address->in.s_addr = htobe32(((uint32_t) a[3] << 24) |
                                             ((uint32_t) a[2] << 16) |
                                             ((uint32_t) a[1] << 8) |
                                              (uint32_t) a[0]);

                return 1;
        }

        r = dns_name_endswith(p, "ip6.arpa");
        if (r < 0)
                return r;
        if (r > 0) {
                struct in6_addr a;
                unsigned i;

                for (i = 0; i < ELEMENTSOF(a.s6_addr); i++) {
                        char label[DNS_LABEL_MAX+1];
                        int x, y;

                        r = dns_label_unescape(&p, label, sizeof(label));
                        if (r <= 0)
                                return r;
                        if (r != 1)
                                return -EINVAL;
                        x = unhexchar(label[0]);
                        if (x < 0)
                                return -EINVAL;

                        r = dns_label_unescape(&p, label, sizeof(label));
                        if (r <= 0)
                                return r;
                        if (r != 1)
                                return -EINVAL;
                        y = unhexchar(label[0]);
                        if (y < 0)
                                return -EINVAL;

                        a.s6_addr[ELEMENTSOF(a.s6_addr) - i - 1] = (uint8_t) y << 4 | (uint8_t) x;
                }

                r = dns_name_equal(p, "ip6.arpa");
                if (r <= 0)
                        return r;

                *family = AF_INET6;
                address->in6 = a;
                return 1;
        }

        return 0;
}

bool dns_name_is_root(const char *name) {

        assert(name);

        /* There are exactly two ways to encode the root domain name:
         * as empty string, or with a single dot. */

        return STR_IN_SET(name, "", ".");
}

bool dns_name_is_single_label(const char *name) {
        char label[DNS_LABEL_MAX+1];
        int r;

        assert(name);

        r = dns_label_unescape(&name, label, sizeof(label));
        if (r <= 0)
                return false;

        return dns_name_is_root(name);
}

/* Encode a domain name according to RFC 1035 Section 3.1 */
int dns_name_to_wire_format(const char *domain, uint8_t *buffer, size_t len) {
        uint8_t *label_length;
        uint8_t *out;
        int r;

        assert_return(buffer, -EINVAL);
        assert_return(domain, -EINVAL);
        assert_return(domain[0], -EINVAL);

        out = buffer;

        do {
                /* reserve a byte for label length */
                if (len == 0)
                        return -ENOBUFS;
                len--;
                label_length = out;
                out++;

                /* convert and copy a single label */
                r = dns_label_unescape(&domain, (char *) out, len);
                if (r < 0)
                        return r;

                /* fill label length, move forward */
                *label_length = r;
                out += r;
                len -= r;
        } while (r != 0);

        return out - buffer;
}

static bool srv_type_label_is_valid(const char *label, size_t n) {
        size_t k;

        assert(label);

        if (n < 2) /* Label needs to be at least 2 chars long */
                return false;

        if (label[0] != '_') /* First label char needs to be underscore */
                return false;

        /* Second char must be a letter */
        if (!(label[1] >= 'A' && label[1] <= 'Z') &&
            !(label[1] >= 'a' && label[1] <= 'z'))
                return false;

        /* Third and further chars must be alphanumeric or a hyphen */
        for (k = 2; k < n; k++) {
                if (!(label[k] >= 'A' && label[k] <= 'Z') &&
                    !(label[k] >= 'a' && label[k] <= 'z') &&
                    !(label[k] >= '0' && label[k] <= '9') &&
                    label[k] != '-')
                        return false;
        }

        return true;
}

bool dns_srv_type_is_valid(const char *name) {
        unsigned c = 0;
        int r;

        if (!name)
                return false;

        for (;;) {
                char label[DNS_LABEL_MAX];

                /* This more or less implements RFC 6335, Section 5.1 */

                r = dns_label_unescape(&name, label, sizeof(label));
                if (r < 0)
                        return false;
                if (r == 0)
                        break;

                if (c >= 2)
                        return false;

                if (!srv_type_label_is_valid(label, r))
                        return false;

                c++;
        }

        return c == 2; /* exactly two labels */
}

bool dns_service_name_is_valid(const char *name) {
        size_t l;

        /* This more or less implements RFC 6763, Section 4.1.1 */

        if (!name)
                return false;

        if (!utf8_is_valid(name))
                return false;

        if (string_has_cc(name, NULL))
                return false;

        l = strlen(name);
        if (l <= 0)
                return false;
        if (l > 63)
                return false;

        return true;
}

int dns_service_join(const char *name, const char *type, const char *domain, char **ret) {
        char escaped[DNS_LABEL_ESCAPED_MAX];
        _cleanup_free_ char *n = NULL;
        int r;

        assert(type);
        assert(domain);
        assert(ret);

        if (!dns_srv_type_is_valid(type))
                return -EINVAL;

        if (!name)
                return dns_name_concat(type, domain, ret);

        if (!dns_service_name_is_valid(name))
                return -EINVAL;

        r = dns_label_escape(name, strlen(name), escaped, sizeof(escaped));
        if (r < 0)
                return r;

        r = dns_name_concat(type, domain, &n);
        if (r < 0)
                return r;

        return dns_name_concat(escaped, n, ret);
}

static bool dns_service_name_label_is_valid(const char *label, size_t n) {
        char *s;

        assert(label);

        if (memchr(label, 0, n))
                return false;

        s = strndupa(label, n);
        return dns_service_name_is_valid(s);
}

int dns_service_split(const char *joined, char **_name, char **_type, char **_domain) {
        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        const char *p = joined, *q = NULL, *d = NULL;
        char a[DNS_LABEL_MAX], b[DNS_LABEL_MAX], c[DNS_LABEL_MAX];
        int an, bn, cn, r;
        unsigned x = 0;

        assert(joined);

        /* Get first label from the full name */
        an = dns_label_unescape(&p, a, sizeof(a));
        if (an < 0)
                return an;

        if (an > 0) {
                x++;

                /* If there was a first label, try to get the second one */
                bn = dns_label_unescape(&p, b, sizeof(b));
                if (bn < 0)
                        return bn;

                if (bn > 0) {
                        x++;

                        /* If there was a second label, try to get the third one */
                        q = p;
                        cn = dns_label_unescape(&p, c, sizeof(c));
                        if (cn < 0)
                                return cn;

                        if (cn > 0)
                                x++;
                } else
                        cn = 0;
        } else
                an = 0;

        if (x >= 2 && srv_type_label_is_valid(b, bn)) {

                if (x >= 3 && srv_type_label_is_valid(c, cn)) {

                        if (dns_service_name_label_is_valid(a, an)) {

                                /* OK, got <name> . <type> . <type2> . <domain> */

                                name = strndup(a, an);
                                if (!name)
                                        return -ENOMEM;

                                type = new(char, bn+1+cn+1);
                                if (!type)
                                        return -ENOMEM;
                                strcpy(stpcpy(stpcpy(type, b), "."), c);

                                d = p;
                                goto finish;
                        }

                } else if (srv_type_label_is_valid(a, an)) {

                        /* OK, got <type> . <type2> . <domain> */

                        name = NULL;

                        type = new(char, an+1+bn+1);
                        if (!type)
                                return -ENOMEM;
                        strcpy(stpcpy(stpcpy(type, a), "."), b);

                        d = q;
                        goto finish;
                }
        }

        name = NULL;
        type = NULL;
        d = joined;

finish:
        r = dns_name_normalize(d, &domain);
        if (r < 0)
                return r;

        if (_domain) {
                *_domain = domain;
                domain = NULL;
        }

        if (_type) {
                *_type = type;
                type = NULL;
        }

        if (_name) {
                *_name = name;
                name = NULL;
        }

        return 0;
}
