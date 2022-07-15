/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

int crypt_dump_hex_string(const char *hex_str, char **ret_dump_str) {

        int r;
        size_t len;
        _cleanup_free_ char *dump_str = NULL;

        assert(hex_str);
        assert(ret_dump_str);

        len = strlen(hex_str) >> 1;

        for (size_t i = 0; i < len; i++) {
                /* crypt_dump() breaks line after every
                 * 16th couple of chars in dumped hexstring */
                r = strextendf_with_separator(
                        &dump_str,
                        (i && !(i % 16)) ? CRYPT_DUMP_LINE_SEP : " ",
                        "%.2s", hex_str + (i<<1));
                if (r < 0)
                        return r;
        }

        *ret_dump_str = TAKE_PTR(dump_str);

        return 0;
}
