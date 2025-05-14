/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libudev.h"

#include "forward.h"
#include "device-nodes.h"

/**
 * SECTION:libudev-util
 * @short_description: utils
 *
 * Utilities useful when dealing with devices and device node names.
 */

/**
 * udev_util_encode_string:
 * @str: input string to be encoded
 * @str_enc: output string to store the encoded input string
 * @len: maximum size of the output string, which may be
 *       four times as long as the input string
 *
 * Encode all potentially unsafe characters of a string to the
 * corresponding 2 char hex value prefixed by '\x'.
 *
 * Returns: 0 if the entire string was copied, non-zero otherwise.
 **/
_public_ int udev_util_encode_string(const char *str, char *str_enc, size_t len) {
        return encode_devnode_name(str, str_enc, len);
}
