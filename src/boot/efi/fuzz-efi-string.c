/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "efi-string.h"
#include "fuzz.h"
#include "utf8.h"

static char16_t *memdup_str16(const uint8_t *data, size_t size) {
        char16_t *ret = memdup(data, size);
        assert_se(ret);
        ret[size / sizeof(char16_t) - 1] = '\0';
        return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, sizeof(size_t), 64 * 1024))
                return 0;

        fuzz_setup_logging();

        size_t len, len2;
        memcpy(&len, data, sizeof(len));
        data += sizeof(len);
        size -= sizeof(len);

        len2 = size - len;
        if (len > size || len < sizeof(char16_t) || len2 < sizeof(char16_t))
                return 0;

        const char *tail8 = NULL;
        _cleanup_free_ char *str8 = ASSERT_SE_PTR(memdup_suffix0(data, size));
        DO_NOT_OPTIMIZE(parse_number8(str8, &(uint64_t){ 0 }, size % 2 == 0 ? NULL : &tail8));

        const char16_t *tail16 = NULL;
        _cleanup_free_ char16_t *str16 = memdup_str16(data, size);
        DO_NOT_OPTIMIZE(parse_number16(str16, &(uint64_t){ 0 }, size % 2 == 0 ? NULL : &tail16));

        _cleanup_free_ char16_t *pattern = memdup_str16(data, len), *haystack = memdup_str16(data + len, len2);
        DO_NOT_OPTIMIZE(efi_fnmatch(pattern, haystack));

        return 0;
}
