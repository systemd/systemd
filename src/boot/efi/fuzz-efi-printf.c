/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "efi-string.h"
#include "fuzz.h"
#include "utf8.h"

typedef struct {
        EFI_STATUS status;
        int16_t field_width;
        int16_t precision;
        const void *ptr;
        char c;
        unsigned char uchar;
        signed char schar;
        unsigned short ushort;
        signed short sshort;
        unsigned int uint;
        signed int sint;
        unsigned long ulong;
        signed long slong;
        unsigned long long ulonglong;
        signed long long slonglong;
        size_t size;
        ssize_t ssize;
        intmax_t intmax;
        uintmax_t uintmax;
        ptrdiff_t ptrdiff;
        char str[];
} Input;

#define PRINTF_ONE(...)                                                        \
        ({                                                                     \
                _cleanup_free_ char16_t *_ret = xasprintf_status(__VA_ARGS__); \
                DO_NOT_OPTIMIZE(_ret);                                         \
        })

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, sizeof(Input), 1024 * 1024))
                return 0;

        const Input *i = (const Input *) data;
        size_t len = size - offsetof(Input, str);

        fuzz_setup_logging();

        PRINTF_ONE(i->status, "%*.*s", i->field_width, (int) len, i->str);
        PRINTF_ONE(i->status, "%*.*ls", i->field_width, (int) (len / sizeof(wchar_t)), (const wchar_t *) i->str);

        PRINTF_ONE(i->status, "%% %*.*m", i->field_width, i->precision);
        PRINTF_ONE(i->status, "%*p", i->field_width, i->ptr);
        PRINTF_ONE(i->status, "%*c %12340c %56789c", i->field_width, i->c, i->c, i->c);

        PRINTF_ONE(i->status, "%*.*hhu", i->field_width, i->precision, i->uchar);
        PRINTF_ONE(i->status, "%*.*hhi", i->field_width, i->precision, i->schar);
        PRINTF_ONE(i->status, "%*.*hu", i->field_width, i->precision, i->ushort);
        PRINTF_ONE(i->status, "%*.*hi", i->field_width, i->precision, i->sshort);
        PRINTF_ONE(i->status, "%*.*u", i->field_width, i->precision, i->uint);
        PRINTF_ONE(i->status, "%*.*i", i->field_width, i->precision, i->sint);
        PRINTF_ONE(i->status, "%*.*lu", i->field_width, i->precision, i->ulong);
        PRINTF_ONE(i->status, "%*.*li", i->field_width, i->precision, i->slong);
        PRINTF_ONE(i->status, "%*.*llu", i->field_width, i->precision, i->ulonglong);
        PRINTF_ONE(i->status, "%*.*lli", i->field_width, i->precision, i->slonglong);

        PRINTF_ONE(i->status, "%+*.*hhi", i->field_width, i->precision, i->schar);
        PRINTF_ONE(i->status, "%-*.*hi", i->field_width, i->precision, i->sshort);
        PRINTF_ONE(i->status, "% *.*i", i->field_width, i->precision, i->sint);
        PRINTF_ONE(i->status, "%0*li", i->field_width, i->slong);
        PRINTF_ONE(i->status, "%#*.*llx", i->field_width, i->precision, i->ulonglong);

        PRINTF_ONE(i->status, "%-*.*zx", i->field_width, i->precision, i->size);
        PRINTF_ONE(i->status, "% *.*zi", i->field_width, i->precision, i->ssize);
        PRINTF_ONE(i->status, "%0*ji", i->field_width, i->intmax);
        PRINTF_ONE(i->status, "%#0*jX", i->field_width, i->uintmax);
        PRINTF_ONE(i->status, "%*.*ti", i->field_width, i->precision, i->ptrdiff);

        return 0;
}
