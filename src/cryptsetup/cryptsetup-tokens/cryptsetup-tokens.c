
#include "memory-util.h"

int crypt_dump_buffer_to_hex_string(
                const char *buf,
                size_t buf_size,
                char **ret_dump_str) {

        int r;

        assert(ret_dump_str);

        for (unsigned int i = 0; i < buf_size; i++) {
                /* crypt_dump() breaks line after every
                 * 16th couple of chars in dumped hexstring */
                r = strextendf_with_separator(
                        ret_dump_str,
                        (i && !(i % 16)) ? CRYPT_DUMP_LINE_SEP : " ",
                        "%02hhx", buf[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

int crypt_dump_hex_string(const char *hex_str, char **ret_dump_str) {

        int r;

        assert(ret_dump_str);

        for (unsigned int i = 0; i < strlen(hex_str) >> 1; i++) {
                /* crypt_dump() breaks line after every
                 * 16th couple of chars in dumped hexstring */
                r = strextendf_with_separator(
                        ret_dump_str,
                        (i && !(i % 16)) ? CRYPT_DUMP_LINE_SEP : " ",
                        "%.2s", hex_str + (i<<1));
                if (r < 0)
                        return r;
        }

        return 0;
}
