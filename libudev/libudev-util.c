/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

static ssize_t get_sys_link(struct udev *udev, const char *slink, const char *syspath, char *value, size_t size)
{
	char path[UTIL_PATH_SIZE];
	ssize_t len;
	const char *pos;

	util_strscpyl(path, sizeof(path), syspath, "/", slink, NULL);
	len = readlink(path, path, sizeof(path));
	if (len <= 0 || len == (ssize_t)sizeof(path))
		return -1;
	path[len] = '\0';
	pos = strrchr(path, '/');
	if (pos == NULL)
		return -1;
	pos = &pos[1];
	dbg(udev, "resolved link to: '%s'\n", pos);
	return util_strscpy(value, size, pos);
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
	char link_target[UTIL_PATH_SIZE];

	ssize_t len;
	int i;
	int back;
	char *base;

	len = readlink(syspath, link_target, sizeof(link_target));
	if (len <= 0 || len == (ssize_t)sizeof(link_target))
		return -1;
	link_target[len] = '\0';
	dbg(udev, "path link '%s' points to '%s'\n", syspath, link_target);

	for (back = 0; strncmp(&link_target[back * 3], "../", 3) == 0; back++)
		;
	dbg(udev, "base '%s', tail '%s', back %i\n", syspath, &link_target[back * 3], back);
	for (i = 0; i <= back; i++) {
		base = strrchr(syspath, '/');
		if (base == NULL)
			return -1;
		base[0] = '\0';
	}
	dbg(udev, "after moving back '%s'\n", syspath);
	util_strscpyl(base, size - (base - syspath), "/", &link_target[back * 3], NULL);
	return 0;
}

int util_log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0' || isspace(endptr[0]))
		return prio;
	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;
	if (strncmp(priority, "debug", 5) == 0)
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

size_t util_path_decode(char *s)
{
	size_t i, j;

	for (i = 0, j = 0; s[i] != '\0'; j++) {
		if (memcmp(&s[i], "\\x2f", 4) == 0) {
			s[j] = '/';
			i += 4;
		} else if (memcmp(&s[i], "\\x5c", 4) == 0) {
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

/*
 * Concatenates strings. In any case, terminates in _all_ cases with '\0'
 * and moves the @dest pointer forward to the added '\0'. Returns the
 * remaining size, and 0 if the string was truncated.
 */
size_t util_strpcpy(char **dest, size_t size, const char *src)
{
	size_t len;

	len = strlen(src);
	if (len >= size) {
		if (size > 1)
			*dest = mempcpy(*dest, src, size-1);
		size = 0;
		*dest[0] = '\0';
	} else {
		if (len > 0) {
			*dest = mempcpy(*dest, src, len);
			size -= len;
		}
		*dest[0] = '\0';
	}
	return size;
}

/* concatenates list of strings, moves dest forward */
size_t util_strpcpyl(char **dest, size_t size, const char *src, ...)
{
	va_list va;

	va_start(va, src);
	do {
		size = util_strpcpy(dest, size, src);
		src = va_arg(va, char *);
	} while (src != NULL);
	va_end(va);

	return size;
}

/* copies string */
size_t util_strscpy(char *dest, size_t size, const char *src)
{
	char *s;

	s = dest;
	return util_strpcpy(&s, size, src);
}

/* concatenates list of strings */
size_t util_strscpyl(char *dest, size_t size, const char *src, ...)
{
	va_list va;
	char *s;

	va_start(va, src);
	s = dest;
	do {
		size = util_strpcpy(&s, size, src);
		src = va_arg(va, char *);
	} while (src != NULL);
	va_end(va);

	return size;
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

int udev_util_replace_whitespace(const char *str, char *to, size_t len)
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

static int is_whitelisted(char c, const char *white)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    strchr("#+-.:=@_", c) != NULL ||
	    (white != NULL && strchr(white, c) != NULL))
		return 1;
	return 0;
}

/* allow chars in whitelist, plain ascii, hex-escaping and valid utf8 */
int udev_util_replace_chars(char *str, const char *white)
{
	size_t i = 0;
	int replaced = 0;

	while (str[i] != '\0') {
		int len;

		if (is_whitelisted(str[i], white)) {
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
 * util_encode_string:
 * @str: input string to be encoded
 * @str_enc: output string to store the encoded input string
 * @len: maximum size of the output string, which may be
 *       four times as long as the input string
 *
 * Encode all potentially unsafe characters of a string to the
 * corresponding hex value prefixed by '\x'.
 *
 * Returns: 0 if the entire string was copied, non-zero otherwise.
 **/
int udev_util_encode_string(const char *str, char *str_enc, size_t len)
{
	size_t i, j;

	if (str == NULL || str_enc == NULL)
		return -1;

	for (i = 0, j = 0; str[i] != '\0'; i++) {
		int seqlen;

		seqlen = utf8_encoded_valid_unichar(&str[i]);
		if (seqlen > 1) {
			if (len-j < (size_t)seqlen)
				goto err;
			memcpy(&str_enc[j], &str[i], seqlen);
			j += seqlen;
			i += (seqlen-1);
		} else if (str[i] == '\\' || !is_whitelisted(str[i], NULL)) {
			if (len-j < 4)
				goto err;
			sprintf(&str_enc[j], "\\x%02x", (unsigned char) str[i]);
			j += 4;
		} else {
			if (len-j < 1)
				goto err;
			str_enc[j] = str[i];
			j++;
		}
	}
	if (len-j < 1)
		goto err;
	str_enc[j] = '\0';
	return 0;
err:
	return -1;
}

/*
 * http://sites.google.com/site/murmurhash/
 *
 * All code is released to the public domain. For business purposes,
 * Murmurhash is under the MIT license.
 *
 */
static unsigned int murmur_hash2(const char *key, int len, unsigned int seed)
{
	/*
	 *  'm' and 'r' are mixing constants generated offline.
	 *  They're not really 'magic', they just happen to work well.
	 */
	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	/* initialize the hash to a 'random' value */
	unsigned int h = seed ^ len;

	/* mix 4 bytes at a time into the hash */
	const unsigned char * data = (const unsigned char *)key;

	while(len >= 4) {
		unsigned int k = *(unsigned int *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		h *= m; 
		h ^= k;

		data += 4;
		len -= 4;
	}

	/* handle the last few bytes of the input array */
	switch(len) {
	case 3:
		h ^= data[2] << 16;
	case 2:
		h ^= data[1] << 8;
	case 1:
		h ^= data[0];
		h *= m;
	};

	/* do a few final mixes of the hash to ensure the last few bytes are well-incorporated */
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

unsigned int util_string_hash32(const char *str)
{
	return murmur_hash2(str, strlen(str), 0);
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
