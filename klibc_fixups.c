/*
 * klibc_fixups.c - very simple implementation of stuff missing in klibc
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 Kay Sievers <kay@vrfy.org>
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

#ifdef __KLIBC__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>

#include "klibc_fixups.h"
#include "logging.h"

#define PW_FILE		"/etc/passwd"
#define GR_FILE		"/etc/group"
#define UTMP_FILE	"/var/run/utmp"


/* return the id of a passwd style line, selected by the users name */
static unsigned long get_id_by_name(const char *uname, const char *dbfile)
{
	unsigned long id = -1;
	FILE *file;
	char buf[255];
	char *pos;
	char *name;
	char *idstr;
	char *tail;

	file = fopen(dbfile, "r");
	if (file == NULL) {
		dbg("unable to open file '%s'", dbfile);
		return -1;
	}

	while (1) {
		pos = fgets(buf, sizeof(buf), file);
		if (pos == NULL)
			break;

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
			if (tail == NULL)
				id = -1;
			else
				dbg("id for '%s' is '%li'", name, id);
			break;
		}
	}

	fclose(file);
	return id;
}

struct passwd *getpwnam(const char *name)
{
	static struct passwd pw;

	memset(&pw, 0x00, sizeof(struct passwd));
	pw.pw_uid = (uid_t) get_id_by_name(name, PW_FILE);
	if (pw.pw_uid < 0)
		return NULL;
	else
		return &pw;
}

struct group *getgrnam(const char *name)
{
	static struct group gr;

	memset(&gr, 0x00, sizeof(struct group));
	gr.gr_gid = (gid_t) get_id_by_name(name, GR_FILE);
	if (gr.gr_gid < 0)
		return NULL;
	else
		return &gr;
}


int ufd = -1;

void setutent()
{
	if (ufd < 0)
		ufd = open(UTMP_FILE, O_RDONLY);
	fcntl(ufd, F_SETFD, FD_CLOEXEC);
	lseek(ufd, 0, SEEK_SET);
}

void endutent() {
	if (ufd < 0)
		return;
	close(ufd);
	ufd = -1;
}

struct utmp *getutent(void)
{
	static struct utmp utmp;
	int retval;

	if (ufd < 0) {
		setutent();
		if (ufd < 0)
			return NULL;
	}
	retval = read(ufd, &utmp, sizeof(struct utmp));
	if (retval < 1)
		return NULL;
	return &utmp;
}

#endif
