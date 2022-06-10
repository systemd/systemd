/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

#include "efi-string.h"

#ifdef SD_BOOT
#  include "util.h"
#else
#  include <stdlib.h>
#  include "alloc-util.h"
#  define xmalloc(n) ASSERT_SE_PTR(malloc(n))
#  define xnew(type, n) ASSERT_SE_PTR(new(type, (n)))
#endif

/* String functions for both char and char16_t that should behave the same way as their respective
 * counterpart in userspace. Where it makes sense, these accept NULL and do something sensible whereas
 * userspace does not allow for this (strlen8(NULL) returns 0 like strlen_ptr(NULL) for example). To make it
 * easier to tell in code which kind of string they work on, we use 8/16 suffixes. This also makes is easier
 * to unit test them. */

#define DEFINE_STRNLEN(type, name)             \
        size_t name(const type *s, size_t n) { \
                if (!s)                        \
                        return 0;              \
                                               \
                size_t len = 0;                \
                while (len < n && *s) {        \
                        s++;                   \
                        len++;                 \
                }                              \
                                               \
                return len;                    \
        }

DEFINE_STRNLEN(char, strnlen8);
DEFINE_STRNLEN(char16_t, strnlen16);

#define TOLOWER(c)                                                \
        ({                                                        \
                typeof(c) _c = (c);                               \
                (_c >= 'A' && _c <= 'Z') ? _c + ('a' - 'A') : _c; \
        })

#define DEFINE_STRTOLOWER(type, name)     \
        void name(type *s) {              \
                if (!s)                   \
                        return;           \
                for (; *s; s++)           \
                        *s = TOLOWER(*s); \
        }

DEFINE_STRTOLOWER(char, strtolower8);
DEFINE_STRTOLOWER(char16_t, strtolower16);

#define DEFINE_STRNCASECMP(type, name, tolower)              \
        int name(const type *s1, const type *s2, size_t n) { \
                if (!s1 || !s2)                              \
                        return CMP(s1, s2);                  \
                                                             \
                while (n > 0) {                              \
                        type c1 = *s1, c2 = *s2;             \
                        if (tolower) {                       \
                                c1 = TOLOWER(c1);            \
                                c2 = TOLOWER(c2);            \
                        }                                    \
                        if (!c1 || c1 != c2)                 \
                                return CMP(c1, c2);          \
                                                             \
                        s1++;                                \
                        s2++;                                \
                        n--;                                 \
                }                                            \
                                                             \
                return 0;                                    \
        }

DEFINE_STRNCASECMP(char, strncmp8, false);
DEFINE_STRNCASECMP(char16_t, strncmp16, false);
DEFINE_STRNCASECMP(char, strncasecmp8, true);
DEFINE_STRNCASECMP(char16_t, strncasecmp16, true);

#define DEFINE_STRCPY(type, name)                                     \
        type *name(type * restrict dest, const type * restrict src) { \
                assert(dest);                                         \
                type *ret = dest;                                     \
                                                                      \
                if (!src) {                                           \
                        *dest = '\0';                                 \
                        return ret;                                   \
                }                                                     \
                                                                      \
                while (*src) {                                        \
                        *dest = *src;                                 \
                        dest++;                                       \
                        src++;                                        \
                }                                                     \
                                                                      \
                *dest = '\0';                                         \
                return ret;                                           \
        }

DEFINE_STRCPY(char, strcpy8);
DEFINE_STRCPY(char16_t, strcpy16);

#define DEFINE_STRCHR(type, name)                  \
        type *name(const type *s, type c) {        \
                if (!s)                            \
                        return NULL;               \
                                                   \
                while (*s) {                       \
                        if (*s == c)               \
                                return (type *) s; \
                        s++;                       \
                }                                  \
                                                   \
                return NULL;                       \
        }

DEFINE_STRCHR(char, strchr8);
DEFINE_STRCHR(char16_t, strchr16);

#define DEFINE_STRNDUP(type, name, len_func)              \
        type *name(const type *s, size_t n) {             \
                if (!s)                                   \
                        return NULL;                      \
                                                          \
                size_t len = len_func(s, n);              \
                size_t size = len * sizeof(type);         \
                                                          \
                type *dup = xmalloc(size + sizeof(type)); \
                efi_memcpy(dup, s, size);                 \
                dup[len] = '\0';                          \
                                                          \
                return dup;                               \
        }

DEFINE_STRNDUP(char, xstrndup8, strnlen8);
DEFINE_STRNDUP(char16_t, xstrndup16, strnlen16);

/* Patterns are fnmatch-compatible (with reduced feature support). */
static bool efi_fnmatch_internal(const char16_t *p, const char16_t *h, int max_depth) {
        assert(p);
        assert(h);

        if (max_depth == 0)
                return false;

        for (;; p++, h++)
                switch (*p) {
                case '\0':
                        /* End of pattern. Check that haystack is now empty. */
                        return *h == '\0';

                case '\\':
                        p++;
                        if (*p == '\0' || *p != *h)
                                /* Trailing escape or no match. */
                                return false;
                        break;

                case '?':
                        if (*h == '\0')
                                /* Early end of haystack. */
                                return false;
                        break;

                case '*':
                        /* No need to recurse for consecutive '*'. */
                        while (*p == '*')
                                p++;

                        for (; *h != '\0'; h++)
                                /* Try matching haystack with remaining pattern. */
                                if (efi_fnmatch_internal(p, h, max_depth - 1))
                                        return true;

                        /* End of haystack. Pattern needs to be empty too for a match. */
                        return *p == '\0';

                case '[':
                        if (*h == '\0')
                                /* Early end of haystack. */
                                return false;

                        bool first = true, can_range = true, match = false;
                        for (;; first = false) {
                                p++;
                                if (*p == '\0')
                                        return false;

                                if (*p == '\\') {
                                        p++;
                                        if (*p == '\0')
                                                return false;
                                        if (*p == *h)
                                                match = true;
                                        can_range = true;
                                        continue;
                                }

                                /* End of set unless it's the first char. */
                                if (*p == ']' && !first)
                                        break;

                                /* Range pattern if '-' is not first or last in set. */
                                if (*p == '-' && can_range && !first && *(p + 1) != ']') {
                                        char16_t low = *(p - 1);
                                        p++;
                                        if (*p == '\\')
                                                p++;
                                        if (*p == '\0')
                                                return false;

                                        if (low <= *h && *h <= *p)
                                                match = true;

                                        /* Ranges cannot be chained: [a-c-f] == [-abcf] */
                                        can_range = false;
                                        continue;
                                }

                                if (*p == *h)
                                        match = true;
                                can_range = true;
                        }

                        if (!match)
                                return false;
                        break;

                default:
                        if (*p != *h)
                                /* Single char mismatch. */
                                return false;
                }
}

bool efi_fnmatch(const char16_t *pattern, const char16_t *haystack) {
        return efi_fnmatch_internal(pattern, haystack, 32);
}

#define DEFINE_PARSE_NUMBER(type, name)                                    \
        bool name(const type *s, uint64_t *ret_u, const type **ret_tail) { \
                assert(ret_u);                                             \
                                                                           \
                if (!s)                                                    \
                        return false;                                      \
                                                                           \
                /* Need at least one digit. */                             \
                if (*s < '0' || *s > '9')                                  \
                        return false;                                      \
                                                                           \
                uint64_t u = 0;                                            \
                while (*s >= '0' && *s <= '9') {                           \
                        if (__builtin_mul_overflow(u, 10, &u))             \
                                return false;                              \
                        if (__builtin_add_overflow(u, *s - '0', &u))       \
                                return false;                              \
                        s++;                                               \
                }                                                          \
                                                                           \
                if (!ret_tail && *s != '\0')                               \
                        return false;                                      \
                                                                           \
                *ret_u = u;                                                \
                if (ret_tail)                                              \
                        *ret_tail = s;                                     \
                return true;                                               \
        }

DEFINE_PARSE_NUMBER(char, parse_number8);
DEFINE_PARSE_NUMBER(char16_t, parse_number16);

static void format_number(
                char16_t buf[static SCRATCH_BUF_SIZE],
                size_t min_digits,
                bool hex,
                bool hex_prefix,
                bool lower,
                bool is_signed,
                uint64_t u) {

        size_t n = 0;
        int base = hex ? 16 : 10;
        char16_t tmp[SCRATCH_BUF_SIZE];
        const char16_t * const digits = lower ? u"0123456789abcdef" : u"0123456789ABCDEF";

        if (is_signed && (int64_t) u < 0) {
                buf[0] = '-';
                buf++;

                int rem = -((int64_t) u % base);
                u = (int64_t) u / -base;
                tmp[n++] = digits[rem];
        }

        while (u > 0 || n == 0) {
                int rem = u % base;
                u /= base;
                tmp[n++] = digits[rem];
        }

        assert(n + min_digits + 5 < SCRATCH_BUF_SIZE);

        if (hex_prefix) {
                buf[0] = '0';
                buf[1] = lower ? 'x' : 'X';
                buf += 2;
        }

        while (min_digits > n) {
                buf[0] = '0';
                buf++;
                min_digits--;
        }

        while (n > 0) {
                *buf = tmp[--n];
                buf++;
        }

        *buf = '\0';
}

static const char *parse_format_specifier(
                EFI_STATUS status,
                const char *format,
                va_list *ap,
                char16_t tmp[SCRATCH_BUF_SIZE],
                bool *ret_pad_zero,
                int *ret_precision,
                int *ret_field_width,
                const char **ret_str8,
                const char16_t **ret_str16,
                const wchar_t **ret_wstr) {

        assert(ap);
        assert(ret_pad_zero);
        assert(ret_precision);
        assert(ret_field_width);
        assert(ret_str8);
        assert(ret_str16);
        assert(ret_wstr);

        bool alternative_form = false, have_field_width = false, long_arg = false;
        size_t field_length = sizeof(int);

        for (;; format++)
                switch (*format) {
                case '0':
                        *ret_pad_zero = true;
                        break;
                case '.':
                        have_field_width = true;
                        break;
                case '#':
                        alternative_form = true;
                        break;

                case '*':
                case '1' ... '9': {
                        uint64_t u;

                        if (*format == '*')
                                u = va_arg(*ap, int);
                        else {
                                if (!parse_number8(format, &u, &format) || u > INT_MAX)
                                        assert_not_reached();
                                format--; /* Point it back to the last digit. */
                        }

                        if (have_field_width && *ret_precision < 0)
                                *ret_precision = u;
                        else if (!have_field_width && *ret_field_width < 0)
                                *ret_field_width = u;
                        else
                                assert_not_reached();
                        break;
                }

                case '%':
                        *ret_str16 = u"%";
                        return format;

                case 'c':
                        /* char/char16_t/wchat_t get promoted to int/wint_t. */
                        assert(field_length == sizeof(int) || long_arg);
                        assert_cc(sizeof(int) == sizeof(wint_t));

                        tmp[0] = va_arg(*ap, int);
                        tmp[1] = '\0';
                        *ret_str16 = tmp;
                        return format;

                case 's':
                        assert(field_length == sizeof(int) || long_arg);

                        if (long_arg)
                                *ret_wstr = va_arg(*ap, const wchar_t *);
                        else
                                *ret_str8 = va_arg(*ap, const char *);

                        return format;

                case 'm':
                        format_number(tmp,
                                      6,
                                      /* hex= */ true,
                                      /* has_prefix= */ true,
                                      /* lower= */ true,
                                      /* is_signed= */ false,
                                      status);
                        *ret_str16 = tmp;
                        return format;

                case 'h':
                        if (*(format + 1) == 'h')
                                format++;

                        /* Types smaller than int are promoted to int and would even elicit a warning when
                         * fetched with va_arg. */
                        field_length = sizeof(int);
                        break;

                case 'l':
                        if (*(format + 1) == 'l') {
                                format++;
                                field_length = sizeof(long long);
                        } else {
                                long_arg = true;
                                field_length = sizeof(long);
                        }
                        break;

                case 'z':
                        field_length = sizeof(size_t);
                        break;

                case 'd':
                case 'i':
                case 'u':
                case 'x':
                case 'X': {
                        union {
                                int64_t i;
                                uint64_t u;
                        } n = {};
                        bool is_signed = IN_SET(*format, 'd', 'i'), hex = IN_SET(*format, 'x', 'X'),
                             lower = *format == 'x';

                        switch (field_length) {
                        case sizeof(int32_t):
                                if (is_signed)
                                        n.i = va_arg(*ap, int32_t);
                                else
                                        n.u = va_arg(*ap, uint32_t);
                                break;
                        case sizeof(int64_t):
                                if (is_signed)
                                        n.i = va_arg(*ap, int64_t);
                                else
                                        n.u = va_arg(*ap, uint64_t);
                                break;
                        default:
                                assert_not_reached();
                        }

                        *ret_precision = MAX(0, *ret_precision);

                        /* Make sure that 0-padding goes after the "0x". */
                        if (hex && alternative_form && *ret_pad_zero) {
                                *ret_pad_zero = false;
                                *ret_precision = MAX(*ret_field_width, *ret_precision) - 2;
                        }

                        format_number(tmp, *ret_precision, hex, alternative_form, lower, is_signed, n.u);
                        *ret_str16 = tmp;
                        *ret_precision = -1; /* Numbers never get truncated. */
                        return format;
                }

                case 'p': {
                        const void *ptr = va_arg(*ap, const void *);

                        if (ptr) {
                                format_number(tmp,
                                              /* min_digits= */ 8,
                                              /* hex= */ true,
                                              /* has_prefix= */ true,
                                              /* lower= */ true,
                                              /* is_signed= */ false,
                                              (uintptr_t) ptr);
                                *ret_str16 = tmp;
                        }

                        *ret_precision = -1; /* Numbers never get truncated. */
                        return format;
                }

                default:
                        assert_not_reached();
                }
}

/* efi_vsnprintf is largely compatible to userspace vsnprintf. Any features omitted should trigger asserts.
 * Notable differences:
 *  - Passing NULL to %s is permitted and will print "(nil)".
 *  - If buf is too small, -1 is returned instead of needed buf size (printf/xasprintf will do a allocation
 *    loop if necessary).
 *  - The provided EFI_STATUS is used for %m instead of errno.
 *  - \n is translated to \r\n. */
int vsnprintf_status(
                EFI_STATUS status,
                char16_t * restrict buf,
                size_t n_buf,
                const char * restrict format,
                va_list ap) {

        assert(buf);
        assert(n_buf > 0);
        assert(format);

        n_buf--; /* For NUL-termination. */
        size_t n = 0;

        /* Make a copy so we can pass a pointer to the va_list for parse_format_specifier(). */
        va_list ap_copy;
        va_copy(ap_copy, ap);

        for (; *format != '\0'; format++) {
                if (n >= n_buf)
                        goto buf_too_small;

                if (*format != '%') {
                        /* EFI uses CR+LF for new lines. */
                        if (*format == '\n' && (n == 0 || *(format - 1) != '\r')) {
                                if (n + 1 >= n_buf)
                                        goto buf_too_small;
                                buf[n++] = '\r';
                        }

                        buf[n++] = *format;
                        continue;
                }

                bool pad_zero = false;
                int precision = -1, field_width = -1;
                const char *str8 = NULL;
                const char16_t *str16 = NULL;
                char16_t tmp[SCRATCH_BUF_SIZE];

                /* For unit tests we have to make do with wchar_t as char16_t has no defined length modifier
                 * for printf. In sd-boot we build with -fshort-wchar, making the two identical. */
                const wchar_t *wstr = NULL;

                format++;
                format = parse_format_specifier(
                                status, format, &ap_copy, tmp,
                                &pad_zero, &precision, &field_width,
                                &str8, &str16, &wstr);

                /* As extension, we support NULL for strings too. */
                if (!str8 && !str16 && !wstr)
                        str16 = u"(nil)";

                size_t padding = 0, len = strlen8(str8) + strlen16(str16);
#ifdef SD_BOOT
                len += strlen16(wstr);
#else
                len += wstr ? wcslen(wstr) : 0;
#endif

                if (precision >= 0)
                        len = MIN(len, (size_t) precision);

                if (field_width > 0 && (size_t) field_width > len)
                        padding = (size_t) field_width - len;

                if (n + padding + len > n_buf)
                        goto buf_too_small;

                while (padding > 0) {
                        buf[n++] = pad_zero ? '0' : ' ';
                        padding--;
                }

                for (size_t i = 0; i < len; i++)
                        buf[n++] = str16 ? str16[i] : (str8 ? str8[i] : wstr[i]);
        }

        assert(n <= n_buf && n <= INT_MAX);
        buf[n] = '\0';
        va_end(ap_copy);
        return n;

buf_too_small:
        va_end(ap_copy);
        return -1;
}

/* Uses buf and returns NULL if large enough, otherwise returns newly allocated buffer. */
_printf_(3, 0) static char16_t *xvasprintf_internal(
                char16_t buf[static PRINTF_BUF_SIZE],
                EFI_STATUS status,
                const char *format,
                va_list ap,
                size_t *ret_size) {

        char16_t *buf_dyn = NULL;
        size_t n_buf = PRINTF_BUF_SIZE;

        for (;;) {
                va_list ap_copy;
                va_copy(ap_copy, ap);
                int r = vsnprintf_status(status, buf_dyn ?: buf, n_buf, format, ap_copy);
                va_end(ap_copy);

                if (r == -1) {
                        free(buf_dyn);
                        n_buf += PRINTF_BUF_SIZE;
                        buf_dyn = xnew(char16_t, n_buf);
                        continue;
                }

                assert(r >= 0);
                if (ret_size)
                        *ret_size = (r + 1) * sizeof(*buf);
                return buf_dyn;
        }
}

int snprintf_status(
                EFI_STATUS status,
                char16_t * restrict buf,
                size_t n_buf,
                const char * restrict format, ...) {

        va_list ap;
        va_start(ap, format);
        int r = vsnprintf_status(status, buf, n_buf, format, ap);
        va_end(ap);
        return r;
}

#ifdef SD_BOOT
EFI_STATUS printf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        EFI_STATUS err = vprintf_status(status, format, ap);
        va_end(ap);
        return err;
}

EFI_STATUS vprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        char16_t buf[PRINTF_BUF_SIZE];
        _cleanup_free_ char16_t *buf_dyn = NULL;
        EFI_STATUS err;

        buf_dyn = xvasprintf_internal(buf, status, format, ap, NULL);
        err = ST->ConOut->OutputString(ST->ConOut, buf_dyn ?: buf);

        return err;
}
#endif

char16_t *xasprintf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        char16_t *s = xvasprintf_status(status, format, ap);
        va_end(ap);
        return s;
}

char16_t *xvasprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        char16_t buf[PRINTF_BUF_SIZE], *buf_dyn;
        size_t size;

        buf_dyn = xvasprintf_internal(buf, status, format, ap, &size);
        if (!buf_dyn) {
                buf_dyn = xmalloc(size);
                memcpy(buf_dyn, buf, size);
        }

        return buf_dyn;
}

int efi_memcmp(const void *p1, const void *p2, size_t n) {
        const uint8_t *up1 = p1, *up2 = p2;
        int r;

        if (!p1 || !p2)
                return CMP(p1, p2);

        while (n > 0) {
                r = CMP(*up1, *up2);
                if (r != 0)
                        return r;

                up1++;
                up2++;
                n--;
        }

        return 0;
}

void *efi_memcpy(void * restrict dest, const void * restrict src, size_t n) {
        if (!dest || !src || n == 0)
                return dest;

#ifdef SD_BOOT
        /* The firmware-provided memcpy is likely optimized, so use that. The function is guaranteed to be
         * available by the UEFI spec. We still make it depend on the boot services pointer being set just in
         * case the compiler emits a call before it is available. */
        if (_likely_(BS)) {
                BS->CopyMem(dest, (void *) src, n);
                return dest;
        }
#endif

        uint8_t *d = dest;
        const uint8_t *s = src;

        while (n > 0) {
                *d = *s;
                d++;
                s++;
                n--;
        }

        return dest;
}

void *efi_memset(void *p, int c, size_t n) {
        if (!p || n == 0)
                return p;

#ifdef SD_BOOT
        /* See comment in efi_memcpy. Note that the signature has c and n swapped! */
        if (_likely_(BS)) {
                BS->SetMem(p, n, c);
                return p;
        }
#endif

        uint8_t *q = p;
        while (n > 0) {
                *q = c;
                q++;
                n--;
        }

        return p;
}

#ifdef SD_BOOT
#  undef memcmp
#  undef memcpy
#  undef memset
/* Provide the actual implementation for the builtins by providing aliases. These need to be marked as used,
 * as otherwise the compiler might remove them but still emit calls, which would break when linking.
 * To prevent a different linker error, we mark memcpy/memset as weak, because gnu-efi is currently
 * providing them. */
__attribute__((used, alias("efi_memcmp"))) int memcmp(const void *p1, const void *p2, size_t n);
__attribute__((used, weak, alias("efi_memcpy"))) void *memcpy(void * restrict dest, const void * restrict src, size_t n);
__attribute__((used, weak, alias("efi_memset"))) void *memset(void *p, int c, size_t n);
#endif
