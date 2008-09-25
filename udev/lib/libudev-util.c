/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

static ssize_t get_sys_link(struct udev *udev, const char *slink, const char *syspath, char *subsystem, size_t size)
{
	char path[UTIL_PATH_SIZE];
	ssize_t len;
	const char *pos;

	util_strlcpy(path, syspath, sizeof(path));
	util_strlcat(path, "/", sizeof(path));
	util_strlcat(path, slink, sizeof(path));
	len = readlink(path, path, sizeof(path));
	if (len < 0 || len >= (ssize_t) sizeof(path))
		return -1;
	path[len] = '\0';
	pos = strrchr(path, '/');
	if (pos == NULL)
		return -1;
	pos = &pos[1];
	info(udev, "resolved link to: '%s'\n", pos);
	return util_strlcpy(subsystem, pos, size);
}

ssize_t util_get_sys_subsystem(struct udev *udev, const char *syspath, char *subsystem, size_t size)
{
	return get_sys_link(udev, "subsystem", syspath, subsystem, size);
}

ssize_t util_get_sys_driver(struct udev *udev, const char *syspath, char *driver, size_t size)
{
	return get_sys_link(udev, "driver", syspath, driver, size);
}

int util_resolve_sys_link(struct udev *udev, char *syspath, size_t size)
{
	struct stat statbuf;
	char link_target[UTIL_PATH_SIZE];

	int len;
	int i;
	int back;

	if (lstat(syspath, &statbuf) < 0)
		return -1;
	if (!S_ISLNK(statbuf.st_mode))
		return -1;
	len = readlink(syspath, link_target, sizeof(link_target));
	if (len <= 0)
		return -1;
	link_target[len] = '\0';
	dbg(udev, "path link '%s' points to '%s'\n", syspath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg(udev, "base '%s', tail '%s', back %i\n", syspath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		char *pos = strrchr(syspath, '/');

		if (pos == NULL)
			return -1;
		pos[0] = '\0';
	}
	dbg(udev, "after moving back '%s'\n", syspath);
	util_strlcat(syspath, "/", size);
	util_strlcat(syspath, &link_target[back * 3], size);
	return 0;
}

int util_log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0')
		return prio;
	if (strncasecmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strcasecmp(priority, "info") == 0)
		return LOG_INFO;
	if (strcasecmp(priority, "debug") == 0)
		return LOG_DEBUG;
	return 0;
}

size_t util_path_encode(char *s, size_t len)
{
	char t[(len * 3)+1];
	size_t i, j;

	t[0] = '\0';
	for (i = 0, j = 0; s[i] != '\0'; i++) {
		if (s[i] == '/') {
			memcpy(&t[j], "\\x2f", 4);
			j += 4;
		} else if (s[i] == '\\') {
			memcpy(&t[j], "\\x5c", 4);
			j += 4;
		} else {
			t[j] = s[i];
			j++;
		}
	}
	t[j] = '\0';
	strncpy(s, t, len);
	return j;
}

size_t util_path_decode(char *s)
{
	size_t i, j;

	for (i = 0, j = 0; s[i] != '\0'; j++) {
		if (memcmp(&s[i], "\\x2f", 4) == 0) {
			s[j] = '/';
			i += 4;
		}else if (memcmp(&s[i], "\\x5c", 4) == 0) {
			s[j] = '\\';
			i += 4;
		} else {
			s[j] = s[i];
			i++;
		}
	}
	s[j] = '\0';
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

size_t util_strlcpy(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while ((ch = *p++)) {
		if (bytes+1 < size)
			*q++ = ch;
		bytes++;
	}

	/* If size == 0 there is no space for a final null... */
	if (size)
		*q = '\0';
	return bytes;
}

size_t util_strlcat(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while (bytes < size && *q) {
		q++;
		bytes++;
	}
	if (bytes == size)
		return (bytes + strlen(src));

	while ((ch = *p++)) {
		if (bytes+1 < size)
		*q++ = ch;
		bytes++;
	}

	*q = '\0';
	return bytes;
}

/* count of characters used to encode one unicode char */
static int utf8_encoded_expected_len(const char *str)
{
	unsigned char c = (unsigned char)str[0];

	if (c < 0x80)
		return 1;
	if ((c & 0xe0) == 0xc0)
		return 2;
	if ((c & 0xf0) == 0xe0)
		return 3;
	if ((c & 0xf8) == 0xf0)
		return 4;
	if ((c & 0xfc) == 0xf8)
		return 5;
	if ((c & 0xfe) == 0xfc)
		return 6;
	return 0;
}

/* decode one unicode char */
static int utf8_encoded_to_unichar(const char *str)
{
	int unichar;
	int len;
	int i;

	len = utf8_encoded_expected_len(str);
	switch (len) {
	case 1:
		return (int)str[0];
	case 2:
		unichar = str[0] & 0x1f;
		break;
	case 3:
		unichar = (int)str[0] & 0x0f;
		break;
	case 4:
		unichar = (int)str[0] & 0x07;
		break;
	case 5:
		unichar = (int)str[0] & 0x03;
		break;
	case 6:
		unichar = (int)str[0] & 0x01;
		break;
	default:
		return -1;
	}

	for (i = 1; i < len; i++) {
		if (((int)str[i] & 0xc0) != 0x80)
			return -1;
		unichar <<= 6;
		unichar |= (int)str[i] & 0x3f;
	}

	return unichar;
}

/* expected size used to encode one unicode char */
static int utf8_unichar_to_encoded_len(int unichar)
{
	if (unichar < 0x80)
		return 1;
	if (unichar < 0x800)
		return 2;
	if (unichar < 0x10000)
		return 3;
	if (unichar < 0x200000)
		return 4;
	if (unichar < 0x4000000)
		return 5;
	return 6;
}

/* check if unicode char has a valid numeric range */
static int utf8_unichar_valid_range(int unichar)
{
	if (unichar > 0x10ffff)
		return 0;
	if ((unichar & 0xfffff800) == 0xd800)
		return 0;
	if ((unichar > 0xfdcf) && (unichar < 0xfdf0))
		return 0;
	if ((unichar & 0xffff) == 0xffff)
		return 0;
	return 1;
}

/* validate one encoded unicode char and return its length */
static int utf8_encoded_valid_unichar(const char *str)
{
	int len;
	int unichar;
	int i;

	len = utf8_encoded_expected_len(str);
	if (len == 0)
		return -1;

	/* ascii is valid */
	if (len == 1)
		return 1;

	/* check if expected encoded chars are available */
	for (i = 0; i < len; i++)
		if ((str[i] & 0x80) != 0x80)
			return -1;

	unichar = utf8_encoded_to_unichar(str);

	/* check if encoded length matches encoded value */
	if (utf8_unichar_to_encoded_len(unichar) != len)
		return -1;

	/* check if value has valid range */
	if (!utf8_unichar_valid_range(unichar))
		return -1;

	return len;
}

/* allow chars in whitelist, plain ascii, hex-escaping and valid utf8 */
int util_replace_chars(char *str, const char *white)
{
	size_t i = 0;
	int replaced = 0;

	while (str[i] != '\0') {
		int len;

		/* accept whitelist */
		if (white != NULL && strchr(white, str[i]) != NULL) {
			i++;
			continue;
		}

		/* accept plain ascii char */
		if ((str[i] >= '0' && str[i] <= '9') ||
		    (str[i] >= 'A' && str[i] <= 'Z') ||
		    (str[i] >= 'a' && str[i] <= 'z')) {
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
		if (isspace(str[i]) && strchr(white, ' ') != NULL) {
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
