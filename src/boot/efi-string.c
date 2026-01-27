/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"

#if SD_BOOT
#  include "proto/simple-text-io.h"
#  include "util.h"
#else
#  include <stdlib.h>

#  include "alloc-util.h"
#  define xnew(t, n) ASSERT_SE_PTR(new(t, n))
#  define xmalloc(n) ASSERT_SE_PTR(malloc(n))
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

#define DEFINE_STRTOLOWER(type, name)                \
        type* name(type *s) {                        \
                if (!s)                              \
                        return NULL;                 \
                for (type *p = s; *p; p++)           \
                        *p = TOLOWER(*p);            \
                return s;                            \
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
                type *ret = ASSERT_PTR(dest);                         \
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
                return c ? NULL : (type *) s;      \
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
                if (size > 0)                             \
                        memcpy(dup, s, size);             \
                dup[len] = '\0';                          \
                                                          \
                return dup;                               \
        }

DEFINE_STRNDUP(char, xstrndup8, strnlen8);
DEFINE_STRNDUP(char16_t, xstrndup16, strnlen16);

static unsigned utf8_to_unichar(const char *utf8, size_t n, char32_t *c) {
        char32_t unichar;
        unsigned len;

        assert(utf8);
        assert(c);

        if (!(utf8[0] & 0x80)) {
                *c = utf8[0];
                return 1;
        } else if ((utf8[0] & 0xe0) == 0xc0) {
                len = 2;
                unichar = utf8[0] & 0x1f;
        } else if ((utf8[0] & 0xf0) == 0xe0) {
                len = 3;
                unichar = utf8[0] & 0x0f;
        } else if ((utf8[0] & 0xf8) == 0xf0) {
                len = 4;
                unichar = utf8[0] & 0x07;
        } else if ((utf8[0] & 0xfc) == 0xf8) {
                len = 5;
                unichar = utf8[0] & 0x03;
        } else if ((utf8[0] & 0xfe) == 0xfc) {
                len = 6;
                unichar = utf8[0] & 0x01;
        } else {
                *c = UINT32_MAX;
                return 1;
        }

        if (len > n) {
                *c = UINT32_MAX;
                return len;
        }

        for (unsigned i = 1; i < len; i++) {
                if ((utf8[i] & 0xc0) != 0x80) {
                        *c = UINT32_MAX;
                        return len;
                }
                unichar <<= 6;
                unichar |= utf8[i] & 0x3f;
        }

        *c = unichar;
        return len;
}

/* Convert UTF-8 to UCS-2, skipping any invalid or short byte sequences. */
char16_t *xstrn8_to_16(const char *str8, size_t n) {
        assert(str8 || n == 0);

        if (n == SIZE_MAX)
                n = strlen8(str8);

        size_t i = 0;
        char16_t *str16 = xnew(char16_t, n + 1);

        while (n > 0 && *str8 != '\0') {
                char32_t unichar;

                size_t utf8len = utf8_to_unichar(str8, n, &unichar);
                str8 += utf8len;
                n = LESS_BY(n, utf8len);

                switch (unichar) {
                case 0 ... 0xd7ffU:
                case 0xe000U ... 0xffffU:
                        str16[i++] = unichar;
                        break;
                }
        }

        str16[i] = u'\0';
        return str16;
}

char *xstrn16_to_ascii(const char16_t *str16, size_t n) {
        assert(str16 || n == 0);

        if (n == SIZE_MAX)
                n = strlen16(str16);

        _cleanup_free_ char *str8 = xnew(char, n + 1);

        size_t i = 0;
        while (n > 0 && *str16 != u'\0') {

                if ((uint16_t) *str16 > 127U) /* Not ASCII? Fail! */
                        return NULL;

                str8[i++] = (char) (uint16_t) *str16;

                str16++;
                n--;
        }

        str8[i] = '\0';
        return TAKE_PTR(str8);
}

char* startswith8(const char *s, const char *prefix) {
        size_t l;

        assert(prefix);

        if (!s)
                return NULL;

        l = strlen8(prefix);
        if (!strneq8(s, prefix, l))
                return NULL;

        return (char*) s + l;
}

static bool efi_fnmatch_prefix(const char16_t *p, const char16_t *h, const char16_t **ret_p, const char16_t **ret_h) {
        assert(p);
        assert(h);
        assert(ret_p);
        assert(ret_h);

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
                        /* Point ret_p at the remainder of the pattern. */
                        while (*p == '*')
                                p++;
                        *ret_p = p;
                        *ret_h = h;
                        return true;

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

/* Patterns are fnmatch-compatible (with reduced feature support). */
bool efi_fnmatch(const char16_t *pattern, const char16_t *haystack) {
        /* Patterns can be considered as simple patterns (without '*') concatenated by '*'. By doing so we
         * simply have to make sure the very first simple pattern matches the start of haystack. Then we just
         * look for the remaining simple patterns *somewhere* within the haystack (in order) as any extra
         * characters in between would be matches by the '*'. We then only have to ensure that the very last
         * simple pattern matches at the actual end of the haystack.
         *
         * This means we do not need to use backtracking which could have catastrophic runtimes with the
         * right input data. */

        for (bool first = true;;) {
                const char16_t *pattern_tail = NULL, *haystack_tail = NULL;
                bool match = efi_fnmatch_prefix(pattern, haystack, &pattern_tail, &haystack_tail);
                if (first) {
                        if (!match)
                                /* Initial simple pattern must match. */
                                return false;
                        if (!pattern_tail)
                                /* No '*' was in pattern, we can return early. */
                                return true;
                        first = false;
                }

                if (pattern_tail) {
                        assert(match);
                        pattern = pattern_tail;
                        haystack = haystack_tail;
                } else {
                        /* If we have a match this must be at the end of the haystack. Note that
                         * efi_fnmatch_prefix compares the NUL-bytes at the end, so we cannot match the end
                         * of pattern in the middle of haystack). */
                        if (match || *haystack == '\0')
                                return match;

                        /* Match one character using '*'. */
                        haystack++;
                }
        }
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
                        if (!MUL_ASSIGN_SAFE(&u, 10))                      \
                                return false;                              \
                        if (!INC_SAFE(&u, *s - '0'))                       \
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

bool parse_boolean(const char *v, bool *ret) {
        assert(ret);

        if (!v)
                return false;

        if (streq8(v, "1") || streq8(v, "yes") || streq8(v, "y") || streq8(v, "true") || streq8(v, "t") ||
            streq8(v, "on")) {
                *ret = true;
                return true;
        }

        if (streq8(v, "0") || streq8(v, "no") || streq8(v, "n") || streq8(v, "false") || streq8(v, "f") ||
            streq8(v, "off")) {
                *ret = false;
                return true;
        }

        return false;
}

char* line_get_key_value(char *s, const char *sep, size_t *pos, char **ret_key, char **ret_value) {
        char *line, *value;
        size_t linelen;

        assert(s);
        assert(sep);
        assert(pos);
        assert(ret_key);
        assert(ret_value);

        for (;;) {
                line = s + *pos;
                if (*line == '\0')
                        return NULL;

                linelen = 0;
                while (line[linelen] && !strchr8("\n\r", line[linelen]))
                        linelen++;

                /* move pos to next line */
                *pos += linelen;
                if (s[*pos])
                        (*pos)++;

                /* empty line */
                if (linelen == 0)
                        continue;

                /* terminate line */
                line[linelen] = '\0';

                /* remove leading whitespace */
                while (linelen > 0 && strchr8(" \t", *line)) {
                        line++;
                        linelen--;
                }

                /* remove trailing whitespace */
                while (linelen > 0 && strchr8(" \t", line[linelen - 1]))
                        linelen--;
                line[linelen] = '\0';

                if (*line == '#')
                        continue;

                /* split key/value */
                value = line;
                while (*value && !strchr8(sep, *value))
                        value++;
                if (*value == '\0')
                        continue;
                *value = '\0';
                value++;
                while (*value && strchr8(sep, *value))
                        value++;

                /* unquote */
                if ((value[0] == '"' && line[linelen - 1] == '"') ||
                    (value[0] == '\'' && line[linelen - 1] == '\'')) {
                        value++;
                        line[linelen - 1] = '\0';
                }

                *ret_key = line;
                *ret_value = value;
                return line;
        }
}

char16_t *hexdump(const void *data, size_t size) {
        static const char hex[] = "0123456789abcdef";
        const uint8_t *d = data;

        assert(data || size == 0);

        char16_t *buf = xnew(char16_t, size * 2 + 1);

        for (size_t i = 0; i < size; i++) {
                buf[i * 2] = hex[d[i] >> 4];
                buf[i * 2 + 1] = hex[d[i] & 0x0F];
        }

        buf[size * 2] = 0;
        return buf;
}

static const char * const warn_table[] = {
        [EFI_SUCCESS]               = "Success",
        [EFI_WARN_UNKNOWN_GLYPH]    = "Unknown glyph",
        [EFI_WARN_DELETE_FAILURE]   = "Delete failure",
        [EFI_WARN_WRITE_FAILURE]    = "Write failure",
        [EFI_WARN_BUFFER_TOO_SMALL] = "Buffer too small",
        [EFI_WARN_STALE_DATA]       = "Stale data",
        [EFI_WARN_FILE_SYSTEM]      = "File system",
        [EFI_WARN_RESET_REQUIRED]   = "Reset required",
};

/* Errors have MSB set, remove it to keep the table compact. */
#define NOERR(err) ((err) & ~EFI_ERROR_MASK)

static const char * const err_table[] = {
        [NOERR(EFI_ERROR_MASK)]           = "Error",
        [NOERR(EFI_LOAD_ERROR)]           = "Load error",
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
        [NOERR(EFI_ERROR_RESERVED_29)]    = "Reserved (29)",
        [NOERR(EFI_ERROR_RESERVED_30)]    = "Reserved (30)",
        [NOERR(EFI_END_OF_FILE)]          = "End of file",
        [NOERR(EFI_INVALID_LANGUAGE)]     = "Invalid language",
        [NOERR(EFI_COMPROMISED_DATA)]     = "Compromised data",
        [NOERR(EFI_IP_ADDRESS_CONFLICT)]  = "IP address conflict",
        [NOERR(EFI_HTTP_ERROR)]           = "HTTP error",
};

static const char *status_to_string(EFI_STATUS status) {
        if (status <= ELEMENTSOF(warn_table) - 1)
                return warn_table[status];
        if (status >= EFI_ERROR_MASK && status <= ((ELEMENTSOF(err_table) - 1) | EFI_ERROR_MASK))
                return err_table[NOERR(status)];
        return NULL;
}

typedef struct {
        size_t padded_len; /* Field width in printf. */
        size_t len;        /* Precision in printf. */
        bool pad_zero;
        bool align_left;
        bool alternative_form;
        bool long_arg;
        bool longlong_arg;
        bool have_field_width;

        const char *str;
        const wchar_t *wstr;

        /* For numbers. */
        bool is_signed;
        bool lowercase;
        int8_t base;
        char sign_pad; /* For + and (space) flags. */
} SpecifierContext;

typedef struct {
        char16_t stack_buf[128]; /* We use stack_buf first to avoid allocations in most cases. */
        char16_t *dyn_buf;       /* Allocated buf or NULL if stack_buf is used. */
        char16_t *buf;           /* Points to the current active buf. */
        size_t n_buf;            /* Len of buf (in char16_t's, not bytes!). */
        size_t n;                /* Used len of buf (in char16_t's). This is always <n_buf. */

        EFI_STATUS status;
        const char *format;
        va_list ap;
} FormatContext;

static void grow_buf(FormatContext *ctx, size_t need) {
        assert(ctx);

        assert_se(INC_SAFE(&need, ctx->n));

        if (need < ctx->n_buf)
                return;

        /* Greedily allocate if we can. */
        if (!MUL_SAFE(&ctx->n_buf, need, 2))
                ctx->n_buf = need;

        /* We cannot use realloc here as ctx->buf may be ctx->stack_buf, which we cannot free. */
        char16_t *new_buf = xnew(char16_t, ctx->n_buf);
        memcpy(new_buf, ctx->buf, ctx->n * sizeof(*ctx->buf));

        free(ctx->dyn_buf);
        ctx->buf = ctx->dyn_buf = new_buf;
}

static void push_padding(FormatContext *ctx, char pad, size_t len) {
        assert(ctx);
        while (len > 0) {
                len--;
                ctx->buf[ctx->n++] = pad;
        }
}

static bool push_str(FormatContext *ctx, SpecifierContext *sp) {
        assert(ctx);
        assert(sp);

        sp->padded_len = LESS_BY(sp->padded_len, sp->len);

        grow_buf(ctx, sp->padded_len + sp->len);

        if (!sp->align_left)
                push_padding(ctx, ' ', sp->padded_len);

        /* In userspace unit tests we cannot just memcpy() the wide string. */
        if (sp->wstr && sizeof(wchar_t) == sizeof(char16_t)) {
                memcpy(ctx->buf + ctx->n, sp->wstr, sp->len * sizeof(*sp->wstr));
                ctx->n += sp->len;
        } else {
                assert(sp->str || sp->wstr);
                for (size_t i = 0; i < sp->len; i++)
                        ctx->buf[ctx->n++] = sp->str ? sp->str[i] : sp->wstr[i];
        }

        if (sp->align_left)
                push_padding(ctx, ' ', sp->padded_len);

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
        if (u == 0 && sp->len == 0)
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

        /* Note that numbers never get truncated! */
        size_t prefix = (sp->sign_pad != 0 ? 1 : 0) + (sp->alternative_form ? 2 : 0);
        size_t number_len = prefix + MAX(n, sp->len);
        grow_buf(ctx, MAX(sp->padded_len, number_len));

        size_t padding = 0;
        if (sp->pad_zero)
                /* Leading zeroes go after the sign or 0x prefix. */
                number_len = MAX(number_len, sp->padded_len);
        else
                padding = LESS_BY(sp->padded_len, number_len);

        if (!sp->align_left)
                push_padding(ctx, ' ', padding);

        if (sp->sign_pad != 0)
                ctx->buf[ctx->n++] = sp->sign_pad;
        if (sp->alternative_form) {
                ctx->buf[ctx->n++] = '0';
                ctx->buf[ctx->n++] = sp->lowercase ? 'x' : 'X';
        }

        push_padding(ctx, '0', LESS_BY(number_len, n + prefix));

        while (n > 0)
                ctx->buf[ctx->n++] = tmp[--n];

        if (sp->align_left)
                push_padding(ctx, ' ', padding);

        assert(ctx->n < ctx->n_buf);
        return true;
}

/* This helps unit testing. */
#if SD_BOOT
#  define NULLSTR "(null)"
#  define wcsnlen strnlen16
#else
#  define NULLSTR "(nil)"
#endif

static bool handle_format_specifier(FormatContext *ctx, SpecifierContext *sp) {
        /* Parses one item from the format specifier in ctx and put the info into sp. If we are done with
         * this specifier returns true, otherwise this function should be called again. */

        /* This implementation assumes 32-bit ints. Also note that all types smaller than int are promoted to
         * int in vararg functions, which is why we fetch only ints for any such types. The compiler would
         * otherwise warn about fetching smaller types. */
        assert_cc(sizeof(int) == 4);
        assert_cc(sizeof(wchar_t) <= sizeof(int));
        assert_cc(sizeof(long long) == sizeof(intmax_t));

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

                if (sp->have_field_width) {
                        /* Negative precision is ignored. */
                        if (i >= 0)
                                sp->len = (size_t) i;
                } else {
                        /* Negative field width is treated as positive field width with '-' flag. */
                        if (i < 0) {
                                i *= -1;
                                sp->align_left = true;
                        }
                        sp->padded_len = i;
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

        case 'j':
                sp->long_arg = sizeof(intmax_t) == sizeof(long);
                sp->longlong_arg = !sp->long_arg && sizeof(intmax_t) == sizeof(long long);
                return false;

        case 't':
                sp->long_arg = sizeof(ptrdiff_t) == sizeof(long);
                sp->longlong_arg = !sp->long_arg && sizeof(ptrdiff_t) == sizeof(long long);
                return false;

        case '%':
                sp->str = "%";
                sp->len = 1;
                return push_str(ctx, sp);

        case 'c':
                sp->wstr = &(wchar_t){ va_arg(ctx->ap, int) };
                sp->len = 1;
                return push_str(ctx, sp);

        case 's':
                if (sp->long_arg) {
                        sp->wstr = va_arg(ctx->ap, const wchar_t *) ?: L"(null)";
                        sp->len = wcsnlen(sp->wstr, sp->len);
                } else {
                        sp->str = va_arg(ctx->ap, const char *) ?: "(null)";
                        sp->len = strnlen8(sp->str, sp->len);
                }
                return push_str(ctx, sp);

        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'X':
                sp->lowercase = *ctx->format == 'x';
                sp->is_signed = IN_SET(*ctx->format, 'd', 'i');
                sp->base = IN_SET(*ctx->format, 'x', 'X') ? 16 : 10;
                if (sp->len == SIZE_MAX)
                        sp->len = 1;

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
                if (!ptr) {
                        sp->str = NULLSTR;
                        sp->len = STRLEN(NULLSTR);
                        return push_str(ctx, sp);
                }

                sp->base = 16;
                sp->lowercase = true;
                sp->alternative_form = true;
                sp->len = 0; /* Precision is ignored for %p. */
                return push_num(ctx, sp, (uintptr_t) ptr);
        }

        case 'm': {
                sp->str = status_to_string(ctx->status);
                if (sp->str) {
                        sp->len = strlen8(sp->str);
                        return push_str(ctx, sp);
                }

                sp->base = 16;
                sp->lowercase = true;
                sp->alternative_form = true;
                sp->len = 0;
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
 *  - Lengths: h, hh, l, ll, z, j, t
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
                SpecifierContext sp = { .len = SIZE_MAX };

                switch (*ctx.format) {
                case '%':
                        ctx.format++;
                        while (!handle_format_specifier(&ctx, &sp))
                                ctx.format++;
                        ctx.format++;
                        break;
                case '\n':
                        ctx.format++;
                        sp.str = "\r\n";
                        sp.len = 2;
                        push_str(&ctx, &sp);
                        break;
                default:
                        sp.str = ctx.format++;
                        while (!IN_SET(*ctx.format, '%', '\n', '\0'))
                                ctx.format++;
                        sp.len = ctx.format - sp.str;
                        push_str(&ctx, &sp);
                }
        }

        va_end(ctx.ap);

        assert(ctx.n < ctx.n_buf);
        ctx.buf[ctx.n++] = '\0';

        if (ret) {
                if (ctx.dyn_buf)
                        return TAKE_PTR(ctx.dyn_buf);

                char16_t *ret_buf = xnew(char16_t, ctx.n);
                memcpy(ret_buf, ctx.buf, ctx.n * sizeof(*ctx.buf));
                return ret_buf;
        }

#if SD_BOOT
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

#if SD_BOOT
/* To provide the actual implementation for these we need to remove the redirection to the builtins. */
#  undef memchr
#  undef memcmp
#  undef memcpy
#  undef memset
_used_ void *memchr(const void *p, int c, size_t n);
_used_ int memcmp(const void *p1, const void *p2, size_t n);
_used_ void *memcpy(void * restrict dest, const void * restrict src, size_t n);
_used_ void *memset(void *p, int c, size_t n);
#else
/* And for userspace unit testing we need to give them an efi_ prefix. */
#  undef memchr
#  define memchr efi_memchr
#  define memcmp efi_memcmp
#  define memcpy efi_memcpy
#  define memset efi_memset
#endif

void *memchr(const void *p, int c, size_t n) {
        if (!p || n == 0)
                return NULL;

        const uint8_t *q = p;
        for (size_t i = 0; i < n; i++)
                if (q[i] == (unsigned char) c)
                        return (void *) (q + i);

        return NULL;
}

int memcmp(const void *p1, const void *p2, size_t n) {
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

void *memcpy(void * restrict dest, const void * restrict src, size_t n) {
        if (!dest || !src || n == 0)
                return dest;

#if SD_BOOT
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

void *memset(void *p, int c, size_t n) {
        if (!p || n == 0)
                return p;

#if SD_BOOT
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

size_t strspn16(const char16_t *p, const char16_t *good) {
        assert(p);
        assert(good);

        const char16_t *i = p;
        for (; *i != 0; i++)
                if (!strchr16(good, *i))
                        break;

        return i - p;
}

size_t strcspn16(const char16_t *p, const char16_t *bad) {
        assert(p);
        assert(bad);

        const char16_t *i = p;
        for (; *i != 0; i++)
                if (strchr16(bad, *i))
                        break;

        return i - p;
}
