/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-token-util.h"
#include "string-util.h"

int crypt_dump_buffer_to_hex_string(
                const char *buf,
                size_t buf_size,
                char **ret_dump_str) {

        int r;
        _cleanup_free_ char *dump_str = NULL;

        assert(buf || !buf_size);
        assert(ret_dump_str);

        for (size_t i = 0; i < buf_size; i++) {
                /* crypt_dump() breaks line after every
                 * 16th couple of chars in dumped hexstring */
                r = strextendf_with_separator(
                        &dump_str,
                        (i && !(i % 16)) ? CRYPT_DUMP_LINE_SEP : " ",
                        "%02hhx", buf[i]);
                if (r < 0)
                        return r;
        }

        *ret_dump_str = TAKE_PTR(dump_str);

        return 0;
}

int crypt_normalize_pin(const void *pin, size_t pin_size, char **ret_pin_string) {
        assert(pin || pin_size == 0);
        assert(ret_pin_string);

        if (pin_size == 0) {
                *ret_pin_string = NULL;
                return 0;
        }

        return make_cstring(pin, pin_size, MAKE_CSTRING_ALLOW_TRAILING_NUL, ret_pin_string);
}
