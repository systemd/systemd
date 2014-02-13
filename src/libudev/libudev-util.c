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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/param.h>

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

int util_delete_path(struct udev *udev, const char *path)
{
        char p[UTIL_PATH_SIZE];
        char *pos;
        int err = 0;

        if (path[0] == '/')
                while(path[1] == '/')
                        path++;
        strscpy(p, sizeof(p), path);
        pos = strrchr(p, '/');
        if (pos == p || pos == NULL)
                return 0;

        for (;;) {
                *pos = '\0';
                pos = strrchr(p, '/');

                /* don't remove the last one */
                if ((pos == p) || (pos == NULL))
                        break;

                err = rmdir(p);
                if (err < 0) {
                        if (errno == ENOENT)
                                err = 0;
                        break;
                }
        }
        return err;
}

uid_t util_lookup_user(struct udev *udev, const char *user)
{
        char *endptr;
        struct passwd pwbuf;
        struct passwd *pw;
        uid_t uid;
        size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        char *buf = alloca(buflen);

        if (streq(user, "root"))
                return 0;
        uid = strtoul(user, &endptr, 10);
        if (endptr[0] == '\0')
                return uid;

        errno = getpwnam_r(user, &pwbuf, buf, buflen, &pw);
        if (pw != NULL)
                return pw->pw_uid;
        if (errno == 0 || errno == ENOENT || errno == ESRCH)
                udev_err(udev, "specified user '%s' unknown\n", user);
        else
                udev_err(udev, "error resolving user '%s': %m\n", user);
        return 0;
}

gid_t util_lookup_group(struct udev *udev, const char *group)
{
        char *endptr;
        struct group grbuf;
        struct group *gr;
        gid_t gid = 0;
        size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        char *buf = NULL;

        if (streq(group, "root"))
                return 0;
        gid = strtoul(group, &endptr, 10);
        if (endptr[0] == '\0')
                return gid;
        gid = 0;
        for (;;) {
                char *newbuf;

                newbuf = realloc(buf, buflen);
                if (!newbuf)
                        break;
                buf = newbuf;
                errno = getgrnam_r(group, &grbuf, buf, buflen, &gr);
                if (gr != NULL) {
                        gid = gr->gr_gid;
                } else if (errno == ERANGE) {
                        buflen *= 2;
                        continue;
                } else if (errno == 0 || errno == ENOENT || errno == ESRCH) {
                        udev_err(udev, "specified group '%s' unknown\n", group);
                } else {
                        udev_err(udev, "error resolving group '%s': %m\n", group);
                }
                break;
        }
        free(buf);
        return gid;
}

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
                udev_dbg(udev, "value '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
        } else {
                size_t l;
                char *s;

                s = result;
                l = strpcpyl(&s, maxsize, udev_device_get_syspath(dev), NULL);
                if (attr != NULL)
                        strpcpyl(&s, l, "/", attr, NULL);
                udev_dbg(udev, "path '[%s/%s]%s' is '%s'\n", subsys, sysname, attr, result);
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

        prio = strtol(priority, &endptr, 10);
        if (endptr[0] == '\0' || isspace(endptr[0]))
                return prio;
        if (startswith(priority, "err"))
                return LOG_ERR;
        if (startswith(priority, "info"))
                return LOG_INFO;
        if (startswith(priority, "debug"))
                return LOG_DEBUG;
        return 0;
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
        while (isspace(str[i]) && (i < len))
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

ssize_t print_kmsg(const char *fmt, ...)
{
        _cleanup_close_ int fd = -1;
        va_list ap;
        char text[1024];
        ssize_t len;
        ssize_t ret;

        fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        len = snprintf(text, sizeof(text), "<30>systemd-udevd[%u]: ", getpid());

        va_start(ap, fmt);
        len += vsnprintf(text + len, sizeof(text) - len, fmt, ap);
        va_end(ap);

        ret = write(fd, text, len);
        if (ret < 0)
                return -errno;

        return ret;
}
