/*
 * udev_libc_wrapper - wrapping of functions missing in a specific libc
 *		       or not working in a statically compiled binary
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2005 Kay Sievers <kay@vrfy.org>
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
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>

#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_utils.h"
#include "logging.h"

#ifdef __KLIBC__
#define __OWN_USERDB_PARSER__
#endif

#ifdef __GLIBC__
#define __OWN_STRLCPYCAT__
#endif

#ifdef USE_STATIC
#define __OWN_USERDB_PARSER__
#endif

#ifdef __OWN_STRLCPYCAT__
size_t strlcpy(char *dst, const char *src, size_t size)
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

	*q = '\0';
	return bytes;
}

size_t strlcat(char *dst, const char *src, size_t size)
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
#endif /* __OWN_STRLCPYCAT__ */

#ifndef __OWN_USERDB_PARSER__
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

uid_t lookup_user(const char *user)
{
	struct passwd *pw;
	uid_t uid = 0;

	pw = getpwnam(user);
	if (pw == NULL)
		dbg("specified user unknown '%s'", user);
	else
		uid = pw->pw_uid;

	return uid;
}

gid_t lookup_group(const char *group)
{
	struct group *gr;
	gid_t gid = 0;

	gr = getgrnam(group);
	if (gr == NULL)
		dbg("specified group unknown '%s'", group);
	else
		gid = gr->gr_gid;

	return gid;
}

#else /* __OWN_USERDB_PARSER__ */

#define PASSWD_FILE		"/etc/passwd"
#define GROUP_FILE		"/etc/group"

/* return the id of a passwd style line, selected by the users name */
static unsigned long get_id_by_name(const char *uname, const char *dbfile)
{
	unsigned long id = 0;
	char line[LINE_SIZE];
	char *buf;
	char *bufline;
	size_t bufsize;
	size_t cur;
	size_t count;
	char *pos;
	char *name;
	char *idstr;
	char *tail;

	if (file_map(dbfile, &buf, &bufsize) != 0) {
		dbg("can't open '%s' as db file", dbfile);
		return 0;
	}
	dbg("search '%s' in '%s'", uname, dbfile);

	/* loop through the whole file */
	cur = 0;
	while (cur < bufsize) {
		count = buf_get_line(buf, bufsize, cur);
		bufline = &buf[cur];
		cur += count+1;

		if (count >= sizeof(line))
			continue;

		strlcpy(line, bufline, count);
		pos = line;

		/* get name */
		name = strsep(&pos, ":");
		if (name == NULL)
			continue;

		/* skip pass */
		if (strsep(&pos, ":") == NULL)
			continue;

		/* get id */
		idstr = strsep(&pos, ":");
		if (idstr == NULL)
			continue;

		if (strcmp(uname, name) == 0) {
			id = strtoul(idstr, &tail, 10);
			if (tail[0] != '\0') {
				id = 0;
				dbg("no id found for '%s'",  name);
			} else
				dbg("id for '%s' is '%li'", name, id);
			break;
		}
	}

	file_unmap(buf, bufsize);
	return id;
}

uid_t lookup_user(const char *user)
{
	unsigned long id;

	id = get_id_by_name(user, PASSWD_FILE);
	return (uid_t) id;
}

gid_t lookup_group(const char *group)
{
	unsigned long id;

	id = get_id_by_name(group, GROUP_FILE);
	return (gid_t) id;
}
#endif /* __OWN_USERDB_PARSER__ */
