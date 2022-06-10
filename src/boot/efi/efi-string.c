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

enum {
        SCRATCH_BUF_SIZE = 64,
};

typedef enum FormatFlags {
        NUMBER_DEFAULT    = 1 << 0, /* Print as decimal. */
        NUMBER_HEX        = 1 << 1, /* Print as hex. */
        NUMBER_HEX_PREFIX = 1 << 2, /* Print as hex with 0x prefix. */
        NUMBER_LOWER      = 1 << 3, /* Print hex numbers and prefix in lowercase letters. */
        NUMBER_SIGNED     = 1 << 4, /* Value is signed. */
} NumberFormatFlags;

static void format_number(
                char16_t buf[static SCRATCH_BUF_SIZE],
                size_t min_digits,
                NumberFormatFlags flags,
                uint64_t u) {

        size_t n = 0;
        int base = FLAGS_SET(flags, NUMBER_HEX) ? 16 : 10;
        char16_t tmp[SCRATCH_BUF_SIZE];
        const char *digits = FLAGS_SET(flags, NUMBER_LOWER) ? "0123456789abcdef" : "0123456789ABCDEF";

        if (FLAGS_SET(flags, NUMBER_SIGNED) && (int64_t) u < 0) {
                *(buf++) = '-';

                /* We cannot just do "u = -(int64_t)u" here because -INT64_MIN overflows. */

                uint64_t rem = -((int64_t) u % base);
                u = (int64_t) u / -base;
                tmp[n++] = digits[rem];
        }

        while (u > 0 || n == 0) {
                uint64_t rem = u % base;
                u /= base;
                tmp[n++] = digits[rem];
        }

        assert(MAX(n, min_digits) + STRLEN("-0x") + 1 <= SCRATCH_BUF_SIZE);

        if (FLAGS_SET(flags, NUMBER_HEX_PREFIX)) {
                *(buf++) = '0';
                *(buf++) = FLAGS_SET(flags, NUMBER_LOWER) ? 'x' : 'X';
        }

        while (min_digits > n) {
                *(buf++) = '0';
                min_digits--;
        }

        while (n > 0)
                *(buf++) = tmp[--n];

        *buf = '\0';
}

static const char * const warn_table[] = {
        [EFI_SUCCESS]               = "Success",
#ifdef SD_BOOT
        [EFI_WARN_UNKOWN_GLYPH]     = "Unknown glyph",
        [EFI_WARN_DELETE_FAILURE]   = "Delete failure",
        [EFI_WARN_WRITE_FAILURE]    = "Write failure",
        [EFI_WARN_BUFFER_TOO_SMALL] = "Buffer too small",
#  ifdef EFI_WARN_RESET_REQUIRED
        [EFI_WARN_STALE_DATA]       = "Stale data",
        [EFI_WARN_FILE_SYSTEM]      = "File system",
        [EFI_WARN_RESET_REQUIRED]   = "Reset required",
#  endif
#endif
};

/* Errors have MSB set, remove it to keep the table compact. */
#define NOERR(err) ((err) & ~EFI_ERROR_MASK)

static const char * const err_table[] = {
        [NOERR(EFI_ERROR_MASK)]           = "Error",
        [NOERR(EFI_LOAD_ERROR)]           = "Load error",
#ifdef SD_BOOT
        [NOERR(EFI_INVALID_PARAMETER)]    = "Invalid parameter",
        [NOERR(EFI_UNSUPPORTED)]          = "Unsupported",
        [NOERR(EFI_BAD_BUFFER_SIZE)]      = "Bad buffer size",
        [NOERR(EFI_BUFFER_TOO_SMALL)]     = "Buffer too small",
        [NOERR(EFI_NOT_READY)]            = "Not ready",
        [NOERR(EFI_DEVICE_ERROR)]         = "Device error",
        [NOERR(EFI_WRITE_PROTECTED)]      = "Write protected",
        [NOERR(EFI_OUT_OF_RESOURCES)]     = "Out of resources",
        [NOERR(EFI_VOLUME_CORRUPTED)]     = "Volume corrupt",
        [NOERR(EFI_VOLUME_FULL)]          = "Volume full",
        [NOERR(EFI_NO_MEDIA)]             = "No media",
        [NOERR(EFI_MEDIA_CHANGED)]        = "Media changed",
        [NOERR(EFI_NOT_FOUND)]            = "Not found",
        [NOERR(EFI_ACCESS_DENIED)]        = "Access denied",
        [NOERR(EFI_NO_RESPONSE)]          = "No response",
        [NOERR(EFI_NO_MAPPING)]           = "No mapping",
        [NOERR(EFI_TIMEOUT)]              = "Time out",
        [NOERR(EFI_NOT_STARTED)]          = "Not started",
        [NOERR(EFI_ALREADY_STARTED)]      = "Already started",
        [NOERR(EFI_ABORTED)]              = "Aborted",
        [NOERR(EFI_ICMP_ERROR)]           = "ICMP error",
        [NOERR(EFI_TFTP_ERROR)]           = "TFTP error",
        [NOERR(EFI_PROTOCOL_ERROR)]       = "Protocol error",
        [NOERR(EFI_INCOMPATIBLE_VERSION)] = "Incompatible version",
        [NOERR(EFI_SECURITY_VIOLATION)]   = "Security violation",
        [NOERR(EFI_CRC_ERROR)]            = "CRC error",
        [NOERR(EFI_END_OF_MEDIA)]         = "End of media",
        [29]                              = "Reserved (29)",
        [30]                              = "Reserved (30)",
        [NOERR(EFI_END_OF_FILE)]          = "End of file",
        [NOERR(EFI_INVALID_LANGUAGE)]     = "Invalid language",
        [NOERR(EFI_COMPROMISED_DATA)]     = "Compromised data",
#  ifdef EFI_HTTP_ERROR
        [NOERR(EFI_IP_ADDRESS_CONFLICT)]  = "IP address conflict",
        [NOERR(EFI_HTTP_ERROR)]           = "HTTP error",
#  endif
#endif
};

static const char *process_format_specifier(
                EFI_STATUS status,
                const char *format,
                va_list *ap,
                char16_t tmp[static SCRATCH_BUF_SIZE],
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
        int precision = -1, field_width = -1;

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
                        int i;

                        if (*format == '*')
                                i = va_arg(*ap, int);
                        else {
                                uint64_t u;
                                if (!parse_number8(format, &u, &format) || u > INT_MAX)
                                        assert_not_reached();
                                format--; /* Point it back to the last digit. */
                                i = u;
                        }

                        if (have_field_width)
                                precision = i;
                        else
                                field_width = i;
                        break;
                }

                case '%':
                        *ret_str16 = u"%";
                        return format;

                case 'c':
                        /* char/char16_t/wchat_t get promoted to int/wint_t. */
                        assert(field_length == sizeof(int) || long_arg);
                        assert_cc(sizeof(int) >= sizeof(wint_t));

                        tmp[0] = va_arg(*ap, int);
                        tmp[1] = '\0';
                        *ret_str16 = tmp;
                        *ret_field_width = field_width;
                        return format;

                case 's':
                        assert(field_length == sizeof(int) || long_arg);

                        if (long_arg)
                                *ret_wstr = va_arg(*ap, const wchar_t *);
                        else
                                *ret_str8 = va_arg(*ap, const char *);

                        *ret_precision = precision;
                        *ret_field_width = field_width;
                        return format;

                case 'm':
                        if (status <= ELEMENTSOF(warn_table) - 1) {
                                *ret_str8 = warn_table[status];
                                return format;
                        }

                        if (status >= EFI_ERROR_MASK &&
                            status <= ((ELEMENTSOF(err_table) - 1) | EFI_ERROR_MASK)) {
                                *ret_str8 = err_table[NOERR(status)];
                                return format;
                        }

                        format_number(tmp,
                                      /*min_digits=*/8,
                                      NUMBER_HEX | NUMBER_HEX_PREFIX | NUMBER_LOWER,
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
                        uint64_t v;
                        NumberFormatFlags flags = NUMBER_DEFAULT;
                        SET_FLAG(flags, NUMBER_HEX, IN_SET(*format, 'x', 'X'));
                        SET_FLAG(flags, NUMBER_HEX_PREFIX, alternative_form);
                        SET_FLAG(flags, NUMBER_SIGNED, IN_SET(*format, 'd', 'i'));
                        SET_FLAG(flags, NUMBER_LOWER, IN_SET(*format, 'x'));

                        switch (field_length) {
                        case sizeof(int32_t):
                                v = FLAGS_SET(flags, NUMBER_SIGNED) ? (uint64_t) va_arg(*ap, int32_t) :
                                                                      va_arg(*ap, uint32_t);
                                break;
                        case sizeof(int64_t):
                                v = FLAGS_SET(flags, NUMBER_SIGNED) ? va_arg(*ap, int64_t) :
                                                                      va_arg(*ap, uint64_t);
                                break;
                        default:
                                assert_not_reached();
                        }

                        precision = MAX(0, precision);

                        /* Make sure that 0-padding goes after the "0x". */
                        if (FLAGS_SET(flags, NUMBER_HEX | NUMBER_HEX_PREFIX) && *ret_pad_zero) {
                                *ret_pad_zero = false;
                                precision = MAX(field_width, precision) - 2;
                        }

                        format_number(tmp, precision, flags, v);
                        *ret_str16 = tmp;
                        *ret_field_width = field_width;
                        return format;
                }

                case 'p': {
                        const void *ptr = va_arg(*ap, const void *);

                        if (ptr) {
                                format_number(tmp,
                                              /*min_digits=*/8,
                                              NUMBER_HEX | NUMBER_HEX_PREFIX | NUMBER_LOWER,
                                              (uintptr_t) ptr);
                                *ret_str16 = tmp;
                        }

                        *ret_field_width = field_width;
                        return format;
                }

                default:
                        assert_not_reached();
                }
}

/* printf_internal is largely compatible to userspace vasprintf. Any features omitted should trigger asserts.
 *
 * Supported:
 *  - Flags: #, 0
 *  - Lengths: h, hh, l, ll, z
 *  - Specifiers: %, c, s, u, i, d, x, X, p, m
 *  - Precision and width (inline or as int arg using *)
 *
 * Notable differences:
 *  - Passing NULL to %s is permitted and will print "(null)"
 *  - %p will also use "(null)"
 *  - The provided EFI_STATUS is used for %m instead of errno
 *  - "\n" is translated to "\r\n" */
_printf_(2, 0) static void printf_internal(
                EFI_STATUS status,
                const char *format,
                va_list ap,
                char16_t **ret_buf) {

        char16_t stack_buf[256], *buf = stack_buf;
        _cleanup_free_ char16_t *dyn_buf = NULL;
        size_t n = 0, n_buf = ELEMENTSOF(stack_buf);

        assert(format);

        /* Make a copy so we can pass a pointer to the va_list for parse_format_specifier(). */
        va_list ap_copy;
        va_copy(ap_copy, ap);

        while (*format != '\0') {
                bool pad_zero = false;
                size_t padding = 0, len;

                const char *str8 = NULL;
                const char16_t *str16 = NULL;
                /* For unit tests we have to make do with wchar_t as char16_t has no defined length modifier
                 * for printf. In sd-boot we build with -fshort-wchar, making the two identical. */
                const wchar_t *wstr = NULL;
                char16_t tmp[SCRATCH_BUF_SIZE];

                switch (*format) {
                case '%': {
                        int precision = -1, field_width = -1;

                        format++;
                        format = process_format_specifier(
                                        status, format, &ap_copy, tmp,
                                        &pad_zero, &precision, &field_width,
                                        &str8, &str16, &wstr);
                        format++;

                        /* As extension, we support NULL for strings too. */
                        if (!str8 && !str16 && !wstr)
                                str16 = u"(null)";

                        len = strlen8(str8) + strlen16(str16);
#ifdef SD_BOOT
                        len += strlen16(wstr);
#else
                        len += wstr ? wcslen(wstr) : 0;
#endif

                        if (precision >= 0)
                                len = MIN(len, (size_t) precision);

                        if (field_width > 0 && (size_t) field_width > len)
                                padding = (size_t) field_width - len;

                        break;
                }
                case '\n':
                        format++;
                        str16 = u"\r\n";
                        len = 2;
                        break;
                default:
                        str8 = format++;
                        while (!IN_SET(*format, '%', '\n', '\0'))
                                format++;
                        len = format - str8;
                }

               /* Grow buf. */
                if (n + len + padding >= n_buf) {
                        n_buf = 2 * (n + len + padding);

                        char16_t *new_buf = xnew(char16_t, n_buf);
                        memcpy(new_buf, buf, n * sizeof(*buf));

                        free(dyn_buf);
                        buf = dyn_buf = new_buf;
                }

                while (padding > 0) {
                        buf[n++] = pad_zero ? '0' : ' ';
                        padding--;
                }

                for (size_t i = 0; i < len; i++)
                        buf[n++] = str16 ? str16[i] : (str8 ? str8[i] : wstr[i]);
        }

        buf[n++] = '\0';

        if (ret_buf) {
                if (buf == stack_buf) {
                        *ret_buf = xnew(char16_t, n);
                        memcpy(*ret_buf, buf, n * sizeof(*buf));
                } else
                        *ret_buf = TAKE_PTR(dyn_buf);
        } else {
#ifdef SD_BOOT
                ST->ConOut->OutputString(ST->ConOut, buf);
#endif
        }

        va_end(ap_copy);
}

void printf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        vprintf_status(status, format, ap);
        va_end(ap);
}

void vprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        printf_internal(status, format, ap, NULL);
}

char16_t *xasprintf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        char16_t *ret = xvasprintf_status(status, format, ap);
        va_end(ap);
        return ret;
}

char16_t *xvasprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        char16_t *ret = NULL;
        printf_internal(status, format, ap, &ret);
        return ret;
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
