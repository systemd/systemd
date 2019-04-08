/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>

#include "sd-device.h"

#include "device-nodes.h"
#include "libudev-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "utf8.h"

/**
 * SECTION:libudev-util
 * @short_description: utils
 *
 * Utilities useful when dealing with devices and device node names.
 */

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
int util_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value) {
        char temp[UTIL_PATH_SIZE], *subsys, *sysname, *attr;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *val;
        int r;

        if (string[0] != '[')
                return -EINVAL;

        strscpy(temp, sizeof(temp), string);

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (!sysname)
                return -EINVAL;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (!attr)
                return -EINVAL;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] == '\0')
                attr = NULL;

        if (read_value && !attr)
                return -EINVAL;

        r = sd_device_new_from_subsystem_sysname(&dev, subsys, sysname);
        if (r < 0)
                return r;

        if (read_value) {
                r = sd_device_get_sysattr_value(dev, attr, &val);
                if (r < 0 && r != -ENOENT)
                        return r;
                if (r == -ENOENT)
                        result[0] = '\0';
                else
                        strscpy(result, maxsize, val);
                log_debug("value '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        } else {
                r = sd_device_get_syspath(dev, &val);
                if (r < 0)
                        return r;

                strscpyl(result, maxsize, val, attr ? "/" : NULL, attr ?: NULL, NULL);
                log_debug("path '[%s/%s]%s' is '%s'", subsys, sysname, strempty(attr), result);
        }
        return 0;
}

size_t util_path_encode(const char *src, char *dest, size_t size) {
        size_t i, j;

        assert(src);
        assert(dest);

        for (i = 0, j = 0; src[i] != '\0'; i++) {
                if (src[i] == '/') {
                        if (j+4 >= size) {
                                j = 0;
                                break;
                        }
                        memcpy(&dest[j], "\\x2f", 4);
                        j += 4;
                } else if (src[i] == '\\') {
                        if (j+4 >= size) {
                                j = 0;
                                break;
                        }
                        memcpy(&dest[j], "\\x5c", 4);
                        j += 4;
                } else {
                        if (j+1 >= size) {
                                j = 0;
                                break;
                        }
                        dest[j] = src[i];
                        j++;
                }
        }
        dest[j] = '\0';
        return j;
}

/*
 * Copy from 'str' to 'to', while removing all leading and trailing whitespace,
 * and replacing each run of consecutive whitespace with a single underscore.
 * The chars from 'str' are copied up to the \0 at the end of the string, or
 * at most 'len' chars.  This appends \0 to 'to', at the end of the copied
 * characters.
 *
 * If 'len' chars are copied into 'to', the final \0 is placed at len+1
 * (i.e. 'to[len] = \0'), so the 'to' buffer must have at least len+1
 * chars available.
 *
 * Note this may be called with 'str' == 'to', i.e. to replace whitespace
 * in-place in a buffer.  This function can handle that situation.
 *
 * Note that only 'len' characters are read from 'str'.
 */
size_t util_replace_whitespace(const char *str, char *to, size_t len) {
        bool is_space = false;
        size_t i, j;

        assert(str);
        assert(to);

        i = strspn(str, WHITESPACE);

        for (j = 0; j < len && i < len && str[i] != '\0'; i++) {
                if (isspace(str[i])) {
                        is_space = true;
                        continue;
                }

                if (is_space) {
                        if (j + 1 >= len)
                                break;

                        to[j++] = '_';
                        is_space = false;
                }
                to[j++] = str[i];
        }

        to[j] = '\0';
        return j;
}

/* allow chars in whitelist, plain ascii, hex-escaping and valid utf8 */
size_t util_replace_chars(char *str, const char *white) {
        size_t i = 0, replaced = 0;

        assert(str);

        while (str[i] != '\0') {
                int len;

                if (whitelisted_char_for_devnode(str[i], white)) {
                        i++;
                        continue;
                }

                /* accept hex encoding */
                if (str[i] == '\\' && str[i+1] == 'x') {
                        i += 2;
                        continue;
                }

                /* accept valid utf8 */
                len = utf8_encoded_valid_unichar(str + i, (size_t) -1);
                if (len > 1) {
                        i += len;
                        continue;
                }

                /* if space is allowed, replace whitespace with ordinary space */
                if (isspace(str[i]) && white && strchr(white, ' ')) {
                        str[i] = ' ';
                        i++;
                        replaced++;
                        continue;
                }

                /* everything else is replaced with '_' */
                str[i] = '_';
                i++;
                replaced++;
        }
        return replaced;
}

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
