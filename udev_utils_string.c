/*
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/utsname.h>

#include "udev.h"

int string_is_true(const char *str)
{
	if (strcasecmp(str, "true") == 0)
		return 1;
	if (strcasecmp(str, "yes") == 0)
		return 1;
	if (strcasecmp(str, "1") == 0)
		return 1;
	return 0;
}

void remove_trailing_chars(char *path, char c)
{
	size_t len;

	len = strlen(path);
	while (len > 0 && path[len-1] == c)
		path[--len] = '\0';
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
int utf8_encoded_valid_unichar(const char *str)
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

/* replace everything but whitelisted plain ascii and valid utf8 */
int replace_untrusted_chars(char *str)
{
	size_t i = 0;
	int replaced = 0;

	while (str[i] != '\0') {
		int len;

		/* valid printable ascii char */
		if ((str[i] >= '0' && str[i] <= '9') ||
		    (str[i] >= 'A' && str[i] <= 'Z') ||
		    (str[i] >= 'a' && str[i] <= 'z') ||
		    strchr(" #$%+-./:=?@_,", str[i])) {
			i++;
			continue;
		}
		/* valid utf8 is accepted */
		len = utf8_encoded_valid_unichar(&str[i]);
		if (len > 1) {
			i += len;
			continue;
		}

		/* everything else is garbage */
		str[i] = '_';
		i++;
		replaced++;
	}

	return replaced;
}
