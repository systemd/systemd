/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "device-nodes.h"
#include "libudev.h"
#include "libudev-private.h"
#include "utf8.h"
#include "MurmurHash2.h"

/**
 * SECTION:libudev-util
 * @short_description: utils
 *
 * Utilities useful when dealing with devices and device node names.
 */

/* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */
int util_resolve_subsys_kernel(struct udev *udev, const char *string,
                               char *result, size_t maxsize, int read_value)
{
        char temp[UTIL_PATH_SIZE];
        char *subsys;
        char *sysname;
        struct udev_device *dev;
        char *attr;

        if (string[0] != '[')
                return -1;

        strscpy(temp, sizeof(temp), string);

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (sysname == NULL)
                return -1;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (attr == NULL)
                return -1;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] == '\0')
                attr = NULL;

        if (read_value && attr == NULL)
                return -1;

        dev = udev_device_new_from_subsystem_sysname(udev, subsys, sysname);
        if (dev == NULL)
                return -1;

        if (read_value) {
                const char *val;

                val = udev_device_get_sysattr_value(dev, attr);
                if (val != NULL)
                        strscpy(result, maxsize, val);
                else
                        result[0] = '\0';
                log_debug("value '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        } else {
                size_t l;
                char *s;

                s = result;
                l = strpcpyl(&s, maxsize, udev_device_get_syspath(dev), NULL);
                if (attr != NULL)
                        strpcpyl(&s, l, "/", attr, NULL);
                log_debug("path '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        }
        udev_device_unref(dev);
        return 0;
}

ssize_t util_get_sys_core_link_value(struct udev *udev, const char *slink, const char *syspath, char *value, size_t size)
{
        char path[UTIL_PATH_SIZE];
        char target[UTIL_PATH_SIZE];
        ssize_t len;
        const char *pos;

        strscpyl(path, sizeof(path), syspath, "/", slink, NULL);
        len = readlink(path, target, sizeof(target));
        if (len <= 0 || len == (ssize_t)sizeof(target))
                return -1;
        target[len] = '\0';
        pos = strrchr(target, '/');
        if (pos == NULL)
                return -1;
        pos = &pos[1];
        return strscpy(value, size, pos);
}

int util_resolve_sys_link(struct udev *udev, char *syspath, size_t size)
{
        char link_target[UTIL_PATH_SIZE];

        ssize_t len;
        int i;
        int back;
        char *base = NULL;

        len = readlink(syspath, link_target, sizeof(link_target));
        if (len <= 0 || len == (ssize_t)sizeof(link_target))
                return -1;
        link_target[len] = '\0';

        for (back = 0; startswith(&link_target[back * 3], "../"); back++)
                ;
        for (i = 0; i <= back; i++) {
                base = strrchr(syspath, '/');
                if (base == NULL)
                        return -EINVAL;
                base[0] = '\0';
        }

        strscpyl(base, size - (base - syspath), "/", &link_target[back * 3], NULL);
        return 0;
}

int util_log_priority(const char *priority)
{
        char *endptr;
        int prio;

        prio = strtoul(priority, &endptr, 10);
        if (endptr[0] == '\0' || isspace(endptr[0])) {
                if (prio >= 0 && prio <= 7)
                        return prio;
                else
                        return -ERANGE;
        }

        return log_level_from_string(priority);
}

size_t util_path_encode(const char *src, char *dest, size_t size)
{
        size_t i, j;

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

void util_remove_trailing_chars(char *path, char c)
{
        size_t len;

        if (path == NULL)
                return;
        len = strlen(path);
        while (len > 0 && path[len-1] == c)
                path[--len] = '\0';
}

int util_replace_whitespace(const char *str, char *to, size_t len)
{
        size_t i, j;

        /* strip trailing whitespace */
        len = strnlen(str, len);
        while (len && isspace(str[len-1]))
                len--;

        /* strip leading whitespace */
        i = 0;
        while ((i < len) && isspace(str[i]))
                i++;

        j = 0;
        while (i < len) {
                /* substitute multiple whitespace with a single '_' */
                if (isspace(str[i])) {
                        while (isspace(str[i]))
                                i++;
                        to[j++] = '_';
                }
                to[j++] = str[i++];
        }
        to[j] = '\0';
        return 0;
}

/* allow chars in whitelist, plain ascii, hex-escaping and valid utf8 */
int util_replace_chars(char *str, const char *white)
{
        size_t i = 0;
        int replaced = 0;

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
                len = utf8_encoded_valid_unichar(&str[i]);
                if (len > 1) {
                        i += len;
                        continue;
                }

                /* if space is allowed, replace whitespace with ordinary space */
                if (isspace(str[i]) && white != NULL && strchr(white, ' ') != NULL) {
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
_public_ int udev_util_encode_string(const char *str, char *str_enc, size_t len)
{
        return encode_devnode_name(str, str_enc, len);
}

unsigned int util_string_hash32(const char *str)
{
        return MurmurHash2(str, strlen(str), 0);
}

/* get a bunch of bit numbers out of the hash, and set the bits in our bit field */
uint64_t util_string_bloom64(const char *str)
{
        uint64_t bits = 0;
        unsigned int hash = util_string_hash32(str);

        bits |= 1LLU << (hash & 63);
        bits |= 1LLU << ((hash >> 6) & 63);
        bits |= 1LLU << ((hash >> 12) & 63);
        bits |= 1LLU << ((hash >> 18) & 63);
        return bits;
}
