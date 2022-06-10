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

static const char *status_to_string(EFI_STATUS status) {
        if (status <= ELEMENTSOF(warn_table) - 1)
                return warn_table[status];
        if (status >= EFI_ERROR_MASK && status <= ((ELEMENTSOF(err_table) - 1) | EFI_ERROR_MASK))
                return err_table[NOERR(status)];
        return NULL;
}

typedef struct {
        size_t field_width;
        size_t precision;
        bool pad_zero:1;
        bool align_left:1;
        bool alternative_form:1;
        bool long_arg:1;
        bool longlong_arg:1;
        bool have_field_width:1;

        /* For numbers. */
        bool is_signed:1;
        bool lowercase:1;
        int8_t base;
        char sign_pad; /* For + and (space) flags. */
} SpecifierContext;

typedef struct {
        char16_t stack_buf[128]; /* We use stack_buf first to avoid allocations in most cases. */
        char16_t *dyn_buf;       /* Allocated buf or NULL if stack_buf is used. */
        char16_t *buf;           /* Points to the current active buf. */
        size_t n_buf;
        size_t n;

        EFI_STATUS status;
        const char *format;
        va_list ap;
} FormatContext;

static void grow_buf(FormatContext *ctx, size_t need) {
        assert(ctx);

        if (ctx->n + need < ctx->n_buf)
                return;

        ctx->n_buf = 2 * (ctx->n + need);

        char16_t *new_buf = xnew(char16_t, ctx->n_buf);
        memcpy(new_buf, ctx->buf, ctx->n * sizeof(*ctx->buf));

        free(ctx->dyn_buf);
        ctx->buf = ctx->dyn_buf = new_buf;
}

static void push_padding(FormatContext *ctx, char pad, size_t len) {
        assert(ctx);
        while (len >= 1) {
                len--;
                ctx->buf[ctx->n++] = pad;
        }
}

static bool push_str(
                FormatContext *ctx,
                const char *str8,
                const char16_t *str16,
                const wchar_t *wstr,
                size_t len,
                size_t padding,
                bool align_left) {

        assert(ctx);
        assert(str8 || str16 || wstr);

        grow_buf(ctx, padding + len);

        if (!align_left)
                push_padding(ctx, ' ', padding);

        if (str16 || (wstr && sizeof(wchar_t) == sizeof(char16_t))) {
                memcpy(ctx->buf + ctx->n, str16 ?: (void *) wstr, len * sizeof(*str16));
                ctx->n += len;
        } else
                for (size_t i = 0; i < len; i++)
                        ctx->buf[ctx->n++] = str8 ? str8[i] : wstr[i];

        if (align_left)
                push_padding(ctx, ' ', padding);

        assert(ctx->n < ctx->n_buf);
        return true;
}

static bool push_num(FormatContext *ctx, SpecifierContext *sp, uint64_t u) {
        const char *digits = sp->lowercase ? "0123456789abcdef" : "0123456789ABCDEF";
        char16_t tmp[32];
        size_t n = 0;

        assert(ctx);
        assert(sp);
        assert(IN_SET(sp->base, 10, 16));

        /* "%.0u" prints nothing if value is 0. */
        if (u == 0 && sp->precision == 0)
                return true;

        if (sp->is_signed && (int64_t) u < 0) {
                /* We cannot just do "u = -(int64_t)u" here because -INT64_MIN overflows. */

                uint64_t rem = -((int64_t) u % sp->base);
                u = (int64_t) u / -sp->base;
                tmp[n++] = digits[rem];
                sp->sign_pad = '-';
        }

        while (u > 0 || n == 0) {
                uint64_t rem = u % sp->base;
                u /= sp->base;
                tmp[n++] = digits[rem];
        }

        size_t prefix = (sp->sign_pad != 0 ? 1 : 0) + (sp->alternative_form ? 2 : 0);
        size_t number_len = prefix + MAX(n, sp->precision);

        grow_buf(ctx, MAX(sp->field_width, number_len));

        size_t padding = 0;
        if (sp->pad_zero)
                /* Leading zeroes go after the 0x prefix. */
                number_len = MAX(number_len, sp->field_width);
        else
                padding = LESS_BY(sp->field_width, number_len);

        if (!sp->align_left)
                push_padding(ctx, ' ', padding);

        if (sp->sign_pad != 0)
                ctx->buf[ctx->n++] = sp->sign_pad;
        if (sp->alternative_form) {
                ctx->buf[ctx->n++] = '0';
                ctx->buf[ctx->n++] = sp->lowercase ? 'x' : 'X';
        }

        if (number_len > n + prefix)
                push_padding(ctx, '0', number_len - n - prefix);

        while (n > 0)
                ctx->buf[ctx->n++] = tmp[--n];

        if (sp->align_left)
                push_padding(ctx, ' ', padding);

        assert(ctx->n < ctx->n_buf);
        return true;
}

/* This helps unit testing. */
#ifdef SD_BOOT
#  define NULLSTR "(null)"
#else
#  define NULLSTR "(nil)"
#endif

static bool handle_format_specifier(FormatContext *ctx, SpecifierContext *sp) {
        /* Parses one item from the format specifier in ctx and put the info into sp. If we are done with
         * this specifier returns true, otherwise this function should be called again. */

        /* This implementation assumes 32bit ints. Also note that all types smaller than int are promoted to
         * int in vararg functions, which is why we fetch only ints for any such types. The compiler would
         * otherwise warn about fetching smaller types. */
        assert_cc(sizeof(int) == 4);

        assert(ctx);
        assert(sp);

        switch (*ctx->format) {
        case '#':
                sp->alternative_form = true;
                return false;
        case '.':
                sp->have_field_width = true;
                return false;
        case '-':
                sp->align_left = true;
                return false;
        case '+':
        case ' ':
                sp->sign_pad = *ctx->format;
                return false;

        case '0':
                if (!sp->have_field_width) {
                        sp->pad_zero = true;
                        return false;
                }

                /* If field width has already been provided then 0 is part of precision (%.0s). */
                _fallthrough_;

        case '*':
        case '1' ... '9': {
                int64_t i;

                if (*ctx->format == '*')
                        i = va_arg(ctx->ap, int);
                else {
                        uint64_t u;
                        if (!parse_number8(ctx->format, &u, &ctx->format) || u > INT_MAX)
                                assert_not_reached();
                        ctx->format--; /* Point it back to the last digit. */
                        i = u;
                }

                if (sp->have_field_width)
                        /* Negative precision is ignored. */
                        sp->precision = i < 0 ? SIZE_MAX : (size_t) i;
                else {
                        /* Negative field width is treated as positive field width with - flag. */
                        if (i < 0) {
                                i *= -1;
                                sp->align_left = true;
                        }
                        sp->field_width = i;
                }

                return false;
        }

        case 'h':
                if (*(ctx->format + 1) == 'h')
                        ctx->format++;
                /* char/short gets promoted to int, nothing to do here. */
                return false;

        case 'l':
                if (*(ctx->format + 1) == 'l') {
                        ctx->format++;
                        sp->longlong_arg = true;
                } else
                        sp->long_arg = true;
                return false;

        case 'z':
                sp->long_arg = sizeof(size_t) == sizeof(long);
                sp->longlong_arg = !sp->long_arg && sizeof(size_t) == sizeof(long long);
                return false;

        case '%':
                return push_str(ctx, NULL, u"%", NULL, 1, 0, /*align_left=*/false);

        case 'c':
                /* Unlike with "%.0s", a field width of 0 is ignored. */
                sp->field_width = LESS_BY(sp->field_width, 1u);

                char16_t c = va_arg(ctx->ap, int);
                return push_str(ctx, NULL, &c, NULL, 1, sp->field_width, sp->align_left);

        case 's': {
                const char *str8 = NULL;
                const wchar_t *wstr = NULL;

                if (sp->long_arg) {
                        wstr = va_arg(ctx->ap, const wchar_t *) ?: L"(null)";
#ifdef SD_BOOT
                        sp->precision = strnlen16(wstr, sp->precision);
#else
                        sp->precision = wcsnlen(wstr, sp->precision);
#endif
                } else {
                        str8 = va_arg(ctx->ap, const char *) ?: "(null)";
                        sp->precision = strnlen8(str8, sp->precision);
                }

                sp->field_width = LESS_BY(sp->field_width, sp->precision);
                return push_str(ctx, str8, NULL, wstr, sp->precision, sp->field_width, sp->align_left);
        }

        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'X':
                sp->lowercase = IN_SET(*ctx->format, 'x');
                sp->is_signed = IN_SET(*ctx->format, 'd', 'i');
                sp->base = IN_SET(*ctx->format, 'x', 'X') ? 16 : 10;
                if (sp->precision == SIZE_MAX)
                        sp->precision = 1;

                uint64_t v;
                if (sp->longlong_arg)
                        v = sp->is_signed ? (uint64_t) va_arg(ctx->ap, long long) :
                                            va_arg(ctx->ap, unsigned long long);
                else if (sp->long_arg)
                        v = sp->is_signed ? (uint64_t) va_arg(ctx->ap, long) : va_arg(ctx->ap, unsigned long);
                else
                        v = sp->is_signed ? (uint64_t) va_arg(ctx->ap, int) : va_arg(ctx->ap, unsigned);

                return push_num(ctx, sp, v);

        case 'p': {
                const void *ptr = va_arg(ctx->ap, const void *);
                if (ptr) {
                        sp->base = 16;
                        sp->lowercase = true;
                        sp->alternative_form = true;
                        sp->precision = 0; /* Precision is ignored for %p. */
                        return push_num(ctx, sp, (uintptr_t) ptr);
                }

                sp->field_width = LESS_BY(sp->field_width, STRLEN(NULLSTR));
                return push_str(ctx, NULLSTR, NULL, NULL, STRLEN(NULLSTR), sp->field_width, sp->align_left);
        }

        case 'm': {
                const char *str8 = status_to_string(ctx->status);
                if (str8) {
                        sp->precision = strlen8(str8);
                        sp->field_width = LESS_BY(sp->field_width, sp->precision);
                        return push_str(ctx, str8, NULL, NULL, sp->precision, sp->field_width, sp->align_left);
                }

                sp->base = 16;
                sp->lowercase = true;
                sp->alternative_form = true;
                sp->precision = 0;
                return push_num(ctx, sp, ctx->status);
        }

        default:
                assert_not_reached();
        }
}

/* printf_internal is largely compatible to userspace vasprintf. Any features omitted should trigger asserts.
 *
 * Supported:
 *  - Flags: #, 0, +, -, space
 *  - Lengths: h, hh, l, ll, z
 *  - Specifiers: %, c, s, u, i, d, x, X, p, m
 *  - Precision and width (inline or as int arg using *)
 *
 * Notable differences:
 *  - Passing NULL to %s is permitted and will print "(null)"
 *  - %p will also use "(null)"
 *  - The provided EFI_STATUS is used for %m instead of errno
 *  - "\n" is translated to "\r\n" */
_printf_(2, 0) static char16_t *printf_internal(EFI_STATUS status, const char *format, va_list ap, bool ret) {
        assert(format);

        FormatContext ctx = {
                .buf = ctx.stack_buf,
                .n_buf = ELEMENTSOF(ctx.stack_buf),
                .format = format,
                .status = status,
        };

        /* We cannot put this into the struct without making a copy. */
        va_copy(ctx.ap, ap);

        while (*ctx.format != '\0') {
                switch (*ctx.format) {
                case '%':
                        ctx.format++;
                        SpecifierContext sp = { .precision = SIZE_MAX };
                        while (!handle_format_specifier(&ctx, &sp))
                                ctx.format++;
                        ctx.format++;
                        break;
                case '\n':
                        ctx.format++;
                        push_str(&ctx, NULL, u"\r\n", NULL, 2, 0, /*align_left=*/false);
                        break;
                default: {
                        const char *start = ctx.format++;
                        while (!IN_SET(*ctx.format, '%', '\n', '\0'))
                                ctx.format++;
                        push_str(&ctx, start, NULL, NULL, ctx.format - start, 0, /*align_left=*/false);
                }
                }
        }

        va_end(ctx.ap);

        assert(ctx.n < ctx.n_buf);
        ctx.buf[ctx.n++] = '\0';

        if (ret) {
                if (ctx.buf == ctx.stack_buf) {
                        char16_t *ret_buf = xnew(char16_t, ctx.n);
                        memcpy(ret_buf, ctx.buf, ctx.n * sizeof(*ctx.buf));
                        return ret_buf;
                }

                return TAKE_PTR(ctx.dyn_buf);
        }

#ifdef SD_BOOT
        ST->ConOut->OutputString(ST->ConOut, ctx.buf);
#endif
        return mfree(ctx.dyn_buf);
}

void printf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        printf_internal(status, format, ap, false);
        va_end(ap);
}

void vprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        printf_internal(status, format, ap, false);
}

char16_t *xasprintf_status(EFI_STATUS status, const char *format, ...) {
        va_list ap;
        va_start(ap, format);
        char16_t *ret = printf_internal(status, format, ap, true);
        va_end(ap);
        return ret;
}

char16_t *xvasprintf_status(EFI_STATUS status, const char *format, va_list ap) {
        return printf_internal(status, format, ap, true);
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
