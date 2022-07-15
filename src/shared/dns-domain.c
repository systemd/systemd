/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "idn-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

int dns_label_unescape(const char **name, char *dest, size_t sz, DNSLabelFlags flags) {
        const char *n;
        char *d, last_char = 0;
        int r = 0;

        assert(name);
        assert(*name);

        n = *name;
        d = dest;

        for (;;) {
                if (IN_SET(*n, 0, '.')) {
                        if (FLAGS_SET(flags, DNS_LABEL_LDH) && last_char == '-')
                                /* Trailing dash */
                                return -EINVAL;

                        if (n[0] == '.' && (n[1] != 0 || !FLAGS_SET(flags, DNS_LABEL_LEAVE_TRAILING_DOT)))
                                n++;

                        break;
                }

                if (r >= DNS_LABEL_MAX)
                        return -EINVAL;

                if (sz <= 0)
                        return -ENOBUFS;

                if (*n == '\\') {
                        /* Escaped character */
                        if (FLAGS_SET(flags, DNS_LABEL_NO_ESCAPES))
                                return -EINVAL;

                        n++;

                        if (*n == 0)
                                /* Ending NUL */
                                return -EINVAL;

                        else if (IN_SET(*n, '\\', '.')) {
                                /* Escaped backslash or dot */

                                if (FLAGS_SET(flags, DNS_LABEL_LDH))
                                        return -EINVAL;

                                last_char = *n;
                                if (d)
                                        *(d++) = *n;
                                sz--;
                                r++;
                                n++;

                        } else if (n[0] >= '0' && n[0] <= '9') {
                                unsigned k;

                                /* Escaped literal ASCII character */

                                if (!(n[1] >= '0' && n[1] <= '9') ||
                                    !(n[2] >= '0' && n[2] <= '9'))
                                        return -EINVAL;

                                k = ((unsigned) (n[0] - '0') * 100) +
                                        ((unsigned) (n[1] - '0') * 10) +
                                        ((unsigned) (n[2] - '0'));

                                /* Don't allow anything that doesn't
                                 * fit in 8bit. Note that we do allow
                                 * control characters, as some servers
                                 * (e.g. cloudflare) are happy to
                                 * generate labels with them
                                 * inside. */
                                if (k > 255)
                                        return -EINVAL;

                                if (FLAGS_SET(flags, DNS_LABEL_LDH) &&
                                    !valid_ldh_char((char) k))
                                        return -EINVAL;

                                last_char = (char) k;
                                if (d)
                                        *(d++) = (char) k;
                                sz--;
                                r++;

                                n += 3;
                        } else
                                return -EINVAL;

                } else if ((uint8_t) *n >= (uint8_t) ' ' && *n != 127) {

                        /* Normal character */

                        if (FLAGS_SET(flags, DNS_LABEL_LDH)) {
                                if (!valid_ldh_char(*n))
                                        return -EINVAL;
                                if (r == 0 && *n == '-')
                                        /* Leading dash */
                                        return -EINVAL;
                        }

                        last_char = *n;
                        if (d)
                                *(d++) = *n;
                        sz--;
                        r++;
                        n++;
                } else
                        return -EINVAL;
        }

        /* Empty label that is not at the end? */
        if (r == 0 && *n)
                return -EINVAL;

        /* More than one trailing dot? */
        if (n[0] == '.' && !FLAGS_SET(flags, DNS_LABEL_LEAVE_TRAILING_DOT))
                return -EINVAL;

        if (sz >= 1 && d)
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

        terminal = *label_terminal;
        assert(IN_SET(*terminal, 0, '.'));

        /* Skip current terminal character (and accept domain names ending it ".") */
        if (*terminal == 0)
                terminal = PTR_SUB1(terminal, name);
        if (terminal >= name && *terminal == '.')
                terminal = PTR_SUB1(terminal, name);

        /* Point name to the last label, and terminal to the preceding terminal symbol (or make it a NULL pointer) */
        while (terminal) {
                /* Find the start of the last label */
                if (*terminal == '.') {
                        const char *y;
                        unsigned slashes = 0;

                        for (y = PTR_SUB1(terminal, name); y && *y == '\\'; y = PTR_SUB1(y, name))
                                slashes++;

                        if (slashes % 2 == 0) {
                                /* The '.' was not escaped */
                                name = terminal + 1;
                                break;
                        } else {
                                terminal = y;
                                continue;
                        }
                }

                terminal = PTR_SUB1(terminal, name);
        }

        r = dns_label_unescape(&name, dest, sz, 0);
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
                return -ENOBUFS;

        assert(p);
        assert(dest);

        q = dest;
        while (l > 0) {

                if (IN_SET(*p, '.', '\\')) {

                        /* Dot or backslash */

                        if (sz < 3)
                                return -ENOBUFS;

                        *(q++) = '\\';
                        *(q++) = *p;

                        sz -= 2;

                } else if (IN_SET(*p, '_', '-') ||
                           ascii_isdigit(*p) ||
                           ascii_isalpha(*p)) {

                        /* Proper character */

                        if (sz < 2)
                                return -ENOBUFS;

                        *(q++) = *p;
                        sz -= 1;

                } else {

                        /* Everything else */

                        if (sz < 5)
                                return -ENOBUFS;

                        *(q++) = '\\';
                        *(q++) = '0' + (char) ((uint8_t) *p / 100);
                        *(q++) = '0' + (char) (((uint8_t) *p / 10) % 10);
                        *(q++) = '0' + (char) ((uint8_t) *p % 10);

                        sz -= 4;
                }

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

        *ret = TAKE_PTR(s);

        return r;
}

#if HAVE_LIBIDN
int dns_label_apply_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max) {
        _cleanup_free_ uint32_t *input = NULL;
        size_t input_size, l;
        const char *p;
        bool contains_8bit = false;
        char buffer[DNS_LABEL_MAX+1];
        int r;

        assert(encoded);
        assert(decoded);

        /* Converts an U-label into an A-label */

        r = dlopen_idn();
        if (r < 0)
                return r;

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

        input = sym_stringprep_utf8_to_ucs4(encoded, encoded_size, &input_size);
        if (!input)
                return -ENOMEM;

        if (sym_idna_to_ascii_4i(input, input_size, buffer, 0) != 0)
                return -EINVAL;

        l = strlen(buffer);

        /* Verify that the result is not longer than one DNS label. */
        if (l <= 0 || l > DNS_LABEL_MAX)
                return -EINVAL;
        if (l > decoded_max)
                return -ENOBUFS;

        memcpy(decoded, buffer, l);

        /* If there's room, append a trailing NUL byte, but only then */
        if (decoded_max > l)
                decoded[l] = 0;

        return (int) l;
}

int dns_label_undo_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max) {
        size_t input_size, output_size;
        _cleanup_free_ uint32_t *input = NULL;
        _cleanup_free_ char *result = NULL;
        uint32_t *output = NULL;
        size_t w;
        int r;

        /* To be invoked after unescaping. Converts an A-label into an U-label. */

        assert(encoded);
        assert(decoded);

        r = dlopen_idn();
        if (r < 0)
                return r;

        if (encoded_size <= 0 || encoded_size > DNS_LABEL_MAX)
                return -EINVAL;

        if (!memory_startswith(encoded, encoded_size, IDNA_ACE_PREFIX))
                return 0;

        input = sym_stringprep_utf8_to_ucs4(encoded, encoded_size, &input_size);
        if (!input)
                return -ENOMEM;

        output_size = input_size;
        output = newa(uint32_t, output_size);

        sym_idna_to_unicode_44i(input, input_size, output, &output_size, 0);

        result = sym_stringprep_ucs4_to_utf8(output, output_size, NULL, &w);
        if (!result)
                return -ENOMEM;
        if (w <= 0)
                return -EINVAL;
        if (w > decoded_max)
                return -ENOBUFS;

        memcpy(decoded, result, w);

        /* Append trailing NUL byte if there's space, but only then. */
        if (decoded_max > w)
                decoded[w] = 0;

        return w;
}
#endif

int dns_name_concat(const char *a, const char *b, DNSLabelFlags flags, char **_ret) {
        _cleanup_free_ char *ret = NULL;
        size_t n = 0;
        const char *p;
        bool first = true;
        int r;

        if (a)
                p = a;
        else if (b)
                p = TAKE_PTR(b);
        else
                goto finish;

        for (;;) {
                char label[DNS_LABEL_MAX];

                r = dns_label_unescape(&p, label, sizeof label, flags);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (*p != 0)
                                return -EINVAL;

                        if (b) {
                                /* Now continue with the second string, if there is one */
                                p = TAKE_PTR(b);
                                continue;
                        }

                        break;
                }

                if (_ret) {
                        if (!GREEDY_REALLOC(ret, n + !first + DNS_LABEL_ESCAPED_MAX))
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

                n += r + !first;
                first = false;
        }

finish:
        if (n > DNS_HOSTNAME_MAX)
                return -EINVAL;

        if (_ret) {
                if (n == 0) {
                        /* Nothing appended? If so, generate at least a single dot, to indicate the DNS root domain */
                        if (!GREEDY_REALLOC(ret, 2))
                                return -ENOMEM;

                        ret[n++] = '.';
                } else {
                        if (!GREEDY_REALLOC(ret, n + 1))
                                return -ENOMEM;
                }

                ret[n] = 0;
                *_ret = TAKE_PTR(ret);
        }

        return 0;
}

void dns_name_hash_func(const char *p, struct siphash *state) {
        int r;

        assert(p);

        for (;;) {
                char label[DNS_LABEL_MAX+1];

                r = dns_label_unescape(&p, label, sizeof label, 0);
                if (r < 0)
                        break;
                if (r == 0)
                        break;

                ascii_strlower_n(label, r);
                siphash24_compress(label, r, state);
                siphash24_compress_byte(0, state); /* make sure foobar and foo.bar result in different hashes */
        }

        /* enforce that all names are terminated by the empty label */
        string_hash_func("", state);
}

int dns_name_compare_func(const char *a, const char *b) {
        const char *x, *y;
        int r, q;

        assert(a);
        assert(b);

        x = a + strlen(a);
        y = b + strlen(b);

        for (;;) {
                char la[DNS_LABEL_MAX], lb[DNS_LABEL_MAX];

                if (x == NULL && y == NULL)
                        return 0;

                r = dns_label_unescape_suffix(a, &x, la, sizeof(la));
                q = dns_label_unescape_suffix(b, &y, lb, sizeof(lb));
                if (r < 0 || q < 0)
                        return CMP(r, q);

                r = ascii_strcasecmp_nn(la, r, lb, q);
                if (r != 0)
                        return r;
        }
}

DEFINE_HASH_OPS(dns_name_hash_ops, char, dns_name_hash_func, dns_name_compare_func);

int dns_name_equal(const char *x, const char *y) {
        int r, q;

        assert(x);
        assert(y);

        for (;;) {
                char la[DNS_LABEL_MAX], lb[DNS_LABEL_MAX];

                r = dns_label_unescape(&x, la, sizeof la, 0);
                if (r < 0)
                        return r;

                q = dns_label_unescape(&y, lb, sizeof lb, 0);
                if (q < 0)
                        return q;

                if (r != q)
                        return false;
                if (r == 0)
                        return true;

                if (ascii_strcasecmp_n(la, lb, r) != 0)
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
                char ln[DNS_LABEL_MAX], ls[DNS_LABEL_MAX];

                r = dns_label_unescape(&n, ln, sizeof ln, 0);
                if (r < 0)
                        return r;

                if (!saved_n)
                        saved_n = n;

                q = dns_label_unescape(&s, ls, sizeof ls, 0);
                if (q < 0)
                        return q;

                if (r == 0 && q == 0)
                        return true;
                if (r == 0 && saved_n == n)
                        return false;

                if (r != q || ascii_strcasecmp_n(ln, ls, r) != 0) {

                        /* Not the same, let's jump back, and try with the next label again */
                        s = suffix;
                        n = TAKE_PTR(saved_n);
                }
        }
}

int dns_name_startswith(const char *name, const char *prefix) {
        const char *n, *p;
        int r, q;

        assert(name);
        assert(prefix);

        n = name;
        p = prefix;

        for (;;) {
                char ln[DNS_LABEL_MAX], lp[DNS_LABEL_MAX];

                r = dns_label_unescape(&p, lp, sizeof lp, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return true;

                q = dns_label_unescape(&n, ln, sizeof ln, 0);
                if (q < 0)
                        return q;

                if (r != q)
                        return false;
                if (ascii_strcasecmp_n(ln, lp, r) != 0)
                        return false;
        }
}

int dns_name_change_suffix(const char *name, const char *old_suffix, const char *new_suffix, char **ret) {
        const char *n, *s, *saved_before = NULL, *saved_after = NULL, *prefix;
        int r, q;

        assert(name);
        assert(old_suffix);
        assert(new_suffix);
        assert(ret);

        n = name;
        s = old_suffix;

        for (;;) {
                char ln[DNS_LABEL_MAX], ls[DNS_LABEL_MAX];

                if (!saved_before)
                        saved_before = n;

                r = dns_label_unescape(&n, ln, sizeof ln, 0);
                if (r < 0)
                        return r;

                if (!saved_after)
                        saved_after = n;

                q = dns_label_unescape(&s, ls, sizeof ls, 0);
                if (q < 0)
                        return q;

                if (r == 0 && q == 0)
                        break;
                if (r == 0 && saved_after == n) {
                        *ret = NULL; /* doesn't match */
                        return 0;
                }

                if (r != q || ascii_strcasecmp_n(ln, ls, r) != 0) {

                        /* Not the same, let's jump back, and try with the next label again */
                        s = old_suffix;
                        n = TAKE_PTR(saved_after);
                        saved_before = NULL;
                }
        }

        /* Found it! Now generate the new name */
        prefix = strndupa_safe(name, saved_before - name);

        r = dns_name_concat(prefix, new_suffix, 0, ret);
        if (r < 0)
                return r;

        return 1;
}

int dns_name_between(const char *a, const char *b, const char *c) {
        /* Determine if b is strictly greater than a and strictly smaller than c.
           We consider the order of names to be circular, so that if a is
           strictly greater than c, we consider b to be between them if it is
           either greater than a or smaller than c. This is how the canonical
           DNS name order used in NSEC records work. */

        if (dns_name_compare_func(a, c) < 0)
                /*
                   a and c are properly ordered:
                   a<---b--->c
                */
                return dns_name_compare_func(a, b) < 0 &&
                       dns_name_compare_func(b, c) < 0;
        else
                /*
                   a and c are equal or 'reversed':
                   <--b--c         a----->
                   or:
                   <-----c         a--b-->
                */
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

int dns_name_address(const char *p, int *ret_family, union in_addr_union *ret_address) {
        int r;

        assert(p);
        assert(ret_family);
        assert(ret_address);

        r = dns_name_endswith(p, "in-addr.arpa");
        if (r < 0)
                return r;
        if (r > 0) {
                uint8_t a[4];
                unsigned i;

                for (i = 0; i < ELEMENTSOF(a); i++) {
                        char label[DNS_LABEL_MAX+1];

                        r = dns_label_unescape(&p, label, sizeof label, 0);
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

                *ret_family = AF_INET;
                ret_address->in.s_addr = htobe32(((uint32_t) a[3] << 24) |
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

                        r = dns_label_unescape(&p, label, sizeof label, 0);
                        if (r <= 0)
                                return r;
                        if (r != 1)
                                return -EINVAL;
                        x = unhexchar(label[0]);
                        if (x < 0)
                                return -EINVAL;

                        r = dns_label_unescape(&p, label, sizeof label, 0);
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

                *ret_family = AF_INET6;
                ret_address->in6 = a;
                return 1;
        }

        *ret_family = AF_UNSPEC;
        *ret_address = IN_ADDR_NULL;

        return 0;
}

bool dns_name_is_root(const char *name) {

        assert(name);

        /* There are exactly two ways to encode the root domain name:
         * as empty string, or with a single dot. */

        return STR_IN_SET(name, "", ".");
}

bool dns_name_is_single_label(const char *name) {
        int r;

        assert(name);

        r = dns_name_parent(&name);
        if (r <= 0)
                return false;

        return dns_name_is_root(name);
}

/* Encode a domain name according to RFC 1035 Section 3.1, without compression */
int dns_name_to_wire_format(const char *domain, uint8_t *buffer, size_t len, bool canonical) {
        uint8_t *label_length, *out;
        int r;

        assert(domain);
        assert(buffer);

        out = buffer;

        do {
                /* Reserve a byte for label length */
                if (len <= 0)
                        return -ENOBUFS;
                len--;
                label_length = out;
                out++;

                /* Convert and copy a single label. Note that
                 * dns_label_unescape() returns 0 when it hits the end
                 * of the domain name, which we rely on here to encode
                 * the trailing NUL byte. */
                r = dns_label_unescape(&domain, (char *) out, len, 0);
                if (r < 0)
                        return r;

                /* Optionally, output the name in DNSSEC canonical
                 * format, as described in RFC 4034, section 6.2. Or
                 * in other words: in lower-case. */
                if (canonical)
                        ascii_strlower_n((char*) out, (size_t) r);

                /* Fill label length, move forward */
                *label_length = r;
                out += r;
                len -= r;

        } while (r != 0);

        /* Verify the maximum size of the encoded name. The trailing
         * dot + NUL byte account are included this time, hence
         * compare against DNS_HOSTNAME_MAX + 2 (which is 255) this
         * time. */
        if (out - buffer > DNS_HOSTNAME_MAX + 2)
                return -EINVAL;

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
        if (!ascii_isalpha(label[1]))
                return false;

        /* Third and further chars must be alphanumeric or a hyphen */
        for (k = 2; k < n; k++) {
                if (!ascii_isalpha(label[k]) &&
                    !ascii_isdigit(label[k]) &&
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

                r = dns_label_unescape(&name, label, sizeof label, 0);
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

bool dnssd_srv_type_is_valid(const char *name) {
        return dns_srv_type_is_valid(name) &&
                ((dns_name_endswith(name, "_tcp") > 0) ||
                 (dns_name_endswith(name, "_udp") > 0)); /* Specific to DNS-SD. RFC 6763, Section 7 */
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
        if (l > DNS_LABEL_MAX)
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
                return dns_name_concat(type, domain, 0, ret);

        if (!dns_service_name_is_valid(name))
                return -EINVAL;

        r = dns_label_escape(name, strlen(name), escaped, sizeof(escaped));
        if (r < 0)
                return r;

        r = dns_name_concat(type, domain, 0, &n);
        if (r < 0)
                return r;

        return dns_name_concat(escaped, n, 0, ret);
}

static bool dns_service_name_label_is_valid(const char *label, size_t n) {
        char *s;

        assert(label);

        if (memchr(label, 0, n))
                return false;

        s = strndupa_safe(label, n);
        return dns_service_name_is_valid(s);
}

int dns_service_split(const char *joined, char **ret_name, char **ret_type, char **ret_domain) {
        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        const char *p = joined, *q = NULL, *d = joined;
        char a[DNS_LABEL_MAX+1], b[DNS_LABEL_MAX+1], c[DNS_LABEL_MAX+1];
        int an, bn, cn, r;
        unsigned x = 0;

        assert(joined);

        /* Get first label from the full name */
        an = dns_label_unescape(&p, a, sizeof(a), 0);
        if (an < 0)
                return an;

        if (an > 0) {
                x++;

                /* If there was a first label, try to get the second one */
                bn = dns_label_unescape(&p, b, sizeof(b), 0);
                if (bn < 0)
                        return bn;

                if (bn > 0) {
                        if (!srv_type_label_is_valid(b, bn))
                                goto finish;

                        x++;

                        /* If there was a second label, try to get the third one */
                        q = p;
                        cn = dns_label_unescape(&p, c, sizeof(c), 0);
                        if (cn < 0)
                                return cn;

                        if (cn > 0 && srv_type_label_is_valid(c, cn))
                                x++;
                }
        }

        switch (x) {
        case 2:
                if (!srv_type_label_is_valid(a, an))
                        break;

                /* OK, got <type> . <type2> . <domain> */

                name = NULL;

                type = strjoin(a, ".", b);
                if (!type)
                        return -ENOMEM;

                d = q;
                break;

        case 3:
                if (!dns_service_name_label_is_valid(a, an))
                        break;

                /* OK, got <name> . <type> . <type2> . <domain> */

                name = strndup(a, an);
                if (!name)
                        return -ENOMEM;

                type = strjoin(b, ".", c);
                if (!type)
                        return -ENOMEM;

                d = p;
                break;
        }

finish:
        r = dns_name_normalize(d, 0, &domain);
        if (r < 0)
                return r;

        if (ret_domain)
                *ret_domain = TAKE_PTR(domain);

        if (ret_type)
                *ret_type = TAKE_PTR(type);

        if (ret_name)
                *ret_name = TAKE_PTR(name);

        return 0;
}

static int dns_name_build_suffix_table(const char *name, const char *table[]) {
        const char *p;
        unsigned n = 0;
        int r;

        assert(name);
        assert(table);

        p = name;
        for (;;) {
                if (n > DNS_N_LABELS_MAX)
                        return -EINVAL;

                table[n] = p;
                r = dns_name_parent(&p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                n++;
        }

        return (int) n;
}

int dns_name_suffix(const char *name, unsigned n_labels, const char **ret) {
        const char* labels[DNS_N_LABELS_MAX+1];
        int n;

        assert(name);
        assert(ret);

        n = dns_name_build_suffix_table(name, labels);
        if (n < 0)
                return n;

        if ((unsigned) n < n_labels)
                return -EINVAL;

        *ret = labels[n - n_labels];
        return (int) (n - n_labels);
}

int dns_name_skip(const char *a, unsigned n_labels, const char **ret) {
        int r;

        assert(a);
        assert(ret);

        for (; n_labels > 0; n_labels--) {
                r = dns_name_parent(&a);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *ret = "";
                        return 0;
                }
        }

        *ret = a;
        return 1;
}

int dns_name_count_labels(const char *name) {
        unsigned n = 0;
        int r;

        assert(name);

        for (const char *p = name;;) {
                r = dns_name_parent(&p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (n >= DNS_N_LABELS_MAX)
                        return -EINVAL;

                n++;
        }

        return n;
}

int dns_name_equal_skip(const char *a, unsigned n_labels, const char *b) {
        int r;

        assert(a);
        assert(b);

        r = dns_name_skip(a, n_labels, &a);
        if (r <= 0)
                return r;

        return dns_name_equal(a, b);
}

int dns_name_common_suffix(const char *a, const char *b, const char **ret) {
        const char *a_labels[DNS_N_LABELS_MAX+1], *b_labels[DNS_N_LABELS_MAX+1];
        int n = 0, m = 0, k = 0, r, q;

        assert(a);
        assert(b);
        assert(ret);

        /* Determines the common suffix of domain names a and b */

        n = dns_name_build_suffix_table(a, a_labels);
        if (n < 0)
                return n;

        m = dns_name_build_suffix_table(b, b_labels);
        if (m < 0)
                return m;

        for (;;) {
                char la[DNS_LABEL_MAX], lb[DNS_LABEL_MAX];
                const char *x, *y;

                if (k >= n || k >= m) {
                        *ret = a_labels[n - k];
                        return 0;
                }

                x = a_labels[n - 1 - k];
                r = dns_label_unescape(&x, la, sizeof la, 0);
                if (r < 0)
                        return r;

                y = b_labels[m - 1 - k];
                q = dns_label_unescape(&y, lb, sizeof lb, 0);
                if (q < 0)
                        return q;

                if (r != q || ascii_strcasecmp_n(la, lb, r) != 0) {
                        *ret = a_labels[n - k];
                        return 0;
                }

                k++;
        }
}

int dns_name_apply_idna(const char *name, char **ret) {

        /* Return negative on error, 0 if not implemented, positive on success. */

#if HAVE_LIBIDN2 || HAVE_LIBIDN2
        int r;

        r = dlopen_idn();
        if (r == -EOPNOTSUPP) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;
#endif

#if HAVE_LIBIDN2
        _cleanup_free_ char *t = NULL;

        assert(name);
        assert(ret);

        /* First, try non-transitional mode (i.e. IDN2008 rules) */
        r = sym_idn2_lookup_u8((uint8_t*) name, (uint8_t**) &t,
                               IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
        if (r == IDN2_DISALLOWED) /* If that failed, because of disallowed characters, try transitional mode.
                                   * (i.e. IDN2003 rules which supports some unicode chars IDN2008 doesn't allow). */
                r = sym_idn2_lookup_u8((uint8_t*) name, (uint8_t**) &t,
                                       IDN2_NFC_INPUT | IDN2_TRANSITIONAL);

        log_debug("idn2_lookup_u8: %s %s %s", name, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), t);
        if (r == IDN2_OK) {
                if (!startswith(name, "xn--")) {
                        _cleanup_free_ char *s = NULL;

                        r = sym_idn2_to_unicode_8z8z(t, &s, 0);
                        if (r != IDN2_OK) {
                                log_debug("idn2_to_unicode_8z8z(\"%s\") failed: %d/%s",
                                          t, r, sym_idn2_strerror(r));
                                *ret = NULL;
                                return 0;
                        }

                        if (!streq_ptr(name, s)) {
                                log_debug("idn2 roundtrip failed: \"%s\" %s \"%s\" %s \"%s\", ignoring.",
                                          name, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), t,
                                          special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), s);
                                *ret = NULL;
                                return 0;
                        }
                }

                *ret = TAKE_PTR(t);
                return 1; /* *ret has been written */
        }

        log_debug("idn2_lookup_u8(\"%s\") failed: %d/%s", name, r, sym_idn2_strerror(r));
        if (r == IDN2_2HYPHEN)
                /* The name has two hyphens — forbidden by IDNA2008 in some cases */
                return 0;
        if (IN_SET(r, IDN2_TOO_BIG_DOMAIN, IDN2_TOO_BIG_LABEL))
                return -ENOSPC;

        return -EINVAL;
#elif HAVE_LIBIDN
        _cleanup_free_ char *buf = NULL;
        size_t n = 0;
        bool first = true;
        int r, q;

        assert(name);
        assert(ret);

        for (;;) {
                char label[DNS_LABEL_MAX];

                r = dns_label_unescape(&name, label, sizeof label, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                q = dns_label_apply_idna(label, r, label, sizeof label);
                if (q < 0)
                        return q;
                if (q > 0)
                        r = q;

                if (!GREEDY_REALLOC(buf, n + !first + DNS_LABEL_ESCAPED_MAX))
                        return -ENOMEM;

                r = dns_label_escape(label, r, buf + n + !first, DNS_LABEL_ESCAPED_MAX);
                if (r < 0)
                        return r;

                if (first)
                        first = false;
                else
                        buf[n++] = '.';

                n += r;
        }

        if (n > DNS_HOSTNAME_MAX)
                return -EINVAL;

        if (!GREEDY_REALLOC(buf, n + 1))
                return -ENOMEM;

        buf[n] = 0;
        *ret = TAKE_PTR(buf);

        return 1;
#else
        *ret = NULL;
        return 0;
#endif
}

int dns_name_is_valid_or_address(const char *name) {
        /* Returns > 0 if the specified name is either a valid IP address formatted as string or a valid DNS name */

        if (isempty(name))
                return 0;

        if (in_addr_from_string_auto(name, NULL, NULL) >= 0)
                return 1;

        return dns_name_is_valid(name);
}

int dns_name_dot_suffixed(const char *name) {
        const char *p = name;
        int r;

        for (;;) {
                if (streq(p, "."))
                        return true;

                r = dns_label_unescape(&p, NULL, DNS_LABEL_MAX, DNS_LABEL_LEAVE_TRAILING_DOT);
                if (r < 0)
                        return r;
                if (r == 0)
                        return false;
        }
}

bool dns_name_dont_resolve(const char *name) {

        /* Never respond to some of the domains listed in RFC6303 */
        if (dns_name_endswith(name, "0.in-addr.arpa") > 0 ||
            dns_name_equal(name, "255.255.255.255.in-addr.arpa") > 0 ||
            dns_name_equal(name, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") > 0)
                return true;

        /* Never respond to some of the domains listed in RFC6761 */
        if (dns_name_endswith(name, "invalid") > 0)
                return true;

        return false;
}
