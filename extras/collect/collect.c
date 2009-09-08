/*
 * Collect variables across events.
 *
 * usage: collect [--add|--remove] <checkpoint> <id> <idlist>
 *
 * Adds ID <id> to the list governed by <checkpoint>.
 * <id> must be part of the ID list <idlist>.
 * If all IDs given by <idlist> are listed (ie collect has been
 * invoked for each ID in <idlist>) collect returns 0, the
 * number of missing IDs otherwise.
 * A negative number is returned on error.
 *
 * Copyright(C) 2007, Hannes Reinecke <hare@suse.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

#define TMPFILE			"/dev/.udev/collect"
#define BUFSIZE			16
#define UDEV_ALARM_TIMEOUT	180

enum collect_state {
	STATE_NONE,
	STATE_OLD,
	STATE_CONFIRMED,
};

struct _mate {
	struct udev_list_node node;
	char *name;
	enum collect_state state;
};

static struct udev_list_node bunch;
static int debug;

/* This can increase dynamically */
static size_t bufsize = BUFSIZE;

static struct _mate *node_to_mate(struct udev_list_node *node)
{
	char *mate;

	mate = (char *)node;
	mate -= offsetof(struct _mate, node);
	return (struct _mate *)mate;
}

static void sig_alrm(int signo)
{
	exit(4);
}

static void usage(void)
{
	printf("usage: collect [--add|--remove] [--debug] <checkpoint> <id> <idlist>\n"
	       "\n"
	       "  Adds ID <id> to the list governed by <checkpoint>.\n"
	       "  <id> must be part of the list <idlist>.\n"
	       "  If all IDs given by <idlist> are listed (ie collect has been\n"
	       "  invoked for each ID in <idlist>) collect returns 0, the\n"
	       "  number of missing IDs otherwise.\n"
	       "  On error a negative number is returned.\n"
	       "\n");
}

/*
 * prepare
 *
 * Prepares the database file
 */
static int prepare(char *dir, char *filename)
{
	struct stat statbuf;
	char buf[512];
	int fd;

	if (stat(dir, &statbuf) < 0)
		mkdir(dir, 0700);

	sprintf(buf, "%s/%s", dir, filename);

	fd = open(buf,O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0)
		fprintf(stderr, "Cannot open %s: %s\n", buf, strerror(errno));

	if (lockf(fd,F_TLOCK,0) < 0) {
		if (debug)
			fprintf(stderr, "Lock taken, wait for %d seconds\n", UDEV_ALARM_TIMEOUT);
		if (errno == EAGAIN || errno == EACCES) {
			alarm(UDEV_ALARM_TIMEOUT);
			lockf(fd, F_LOCK, 0);
			if (debug)
				fprintf(stderr, "Acquired lock on %s\n", buf);
		} else {
			if (debug)
				fprintf(stderr, "Could not get lock on %s: %s\n", buf, strerror(errno));
		}
	}

	return fd;
}

/*
 * Read checkpoint file
 *
 * Tricky reading this. We allocate a buffer twice as large
 * as we're going to read. Then we read into the upper half
 * of that buffer and start parsing.
 * Once we do _not_ find end-of-work terminator (whitespace
 * character) we move the upper half to the lower half,
 * adjust the read pointer and read the next bit.
 * Quite clever methinks :-)
 * I should become a programmer ...
 *
 * Yes, one could have used fgets() for this. But then we'd
 * have to use freopen etc which I found quite tedious.
 */
static int checkout(int fd)
{
	int len;
	char *buf, *ptr, *word = NULL;
	struct _mate *him;

 restart:
	len = bufsize >> 1;
	buf = calloc(1,bufsize + 1);
	if (!buf) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	memset(buf, ' ', bufsize);
	ptr = buf + len;
	while ((read(fd, buf + len, len)) > 0) {
		while (ptr && *ptr) {
			word = ptr;
			ptr = strpbrk(word," \n\t\r");
			if (!ptr && word < (buf + len)) {
				bufsize = bufsize << 1;
				if (debug)
					fprintf(stderr, "ID overflow, restarting with size %zi\n", bufsize);
				free(buf);
				lseek(fd, 0, SEEK_SET);
				goto restart;
			}
			if (ptr) {
				*ptr = '\0';
				ptr++;
				if (!strlen(word))
					continue;

				if (debug)
					fprintf(stderr, "Found word %s\n", word);
				him = malloc(sizeof (struct _mate));
				him->name = strdup(word);
				him->state = STATE_OLD;
				udev_list_node_append(&him->node, &bunch);
				word = NULL;
			}
		}
		memcpy(buf, buf + len, len);
		memset(buf + len, ' ', len);

		if (!ptr)
			ptr = word;
		if (!ptr)
			break;
		ptr -= len;
	}

	free(buf);
	return 0;
}

/*
 * invite
 *
 * Adds a new ID 'us' to the internal list,
 * marks it as confirmed.
 */
static void invite(char *us)
{
	struct udev_list_node *him_node;
	struct _mate *who = NULL;

	if (debug)
		fprintf(stderr, "Adding ID '%s'\n", us);

	udev_list_node_foreach(him_node, &bunch) {
		struct _mate *him = node_to_mate(him_node);

		if (!strcmp(him->name, us)) {
			him->state = STATE_CONFIRMED;
			who = him;
		}
	}
	if (debug && !who)
		fprintf(stderr, "ID '%s' not in database\n", us);

}

/*
 * reject
 *
 * Marks the ID 'us' as invalid,
 * causing it to be removed when the
 * list is written out.
 */
static void reject(char *us)
{
	struct udev_list_node *him_node;
	struct _mate *who = NULL;

	if (debug)
		fprintf(stderr, "Removing ID '%s'\n", us);

	udev_list_node_foreach(him_node, &bunch) {
		struct _mate *him = node_to_mate(him_node);

		if (!strcmp(him->name, us)) {
			him->state = STATE_NONE;
			who = him;
		}
	}
	if (debug && !who)
		fprintf(stderr, "ID '%s' not in database\n", us);
}

/*
 * kickout
 *
 * Remove all IDs in the internal list which are not part
 * of the list passed via the commandline.
 */
static void kickout(void)
{
	struct udev_list_node *him_node;
	struct udev_list_node *tmp;

	udev_list_node_foreach_safe(him_node, tmp, &bunch) {
		struct _mate *him = node_to_mate(him_node);

		if (him->state == STATE_OLD) {
			udev_list_node_remove(&him->node);
			free(him->name);
			free(him);
		}
	}
}

/*
 * missing
 *
 * Counts all missing IDs in the internal list.
 */
static int missing(int fd)
{
	char *buf;
	int ret = 0;
	struct udev_list_node *him_node;

	buf = malloc(bufsize);
	if (!buf)
		return -1;

	udev_list_node_foreach(him_node, &bunch) {
		struct _mate *him = node_to_mate(him_node);

		if (him->state == STATE_NONE) {
			ret++;
		} else {
			while (strlen(him->name)+1 >= bufsize) {
				char *tmpbuf;

				bufsize = bufsize << 1;
				tmpbuf = realloc(buf, bufsize);
				if (!tmpbuf) {
					free(buf);
					return -1;
				}
				buf = tmpbuf;
			}
			snprintf(buf, strlen(him->name)+2, "%s ", him->name);
			write(fd, buf, strlen(buf));
		}
	}

	free(buf);
	return ret;
}

/*
 * everybody
 *
 * Prints out the status of the internal list.
 */
static void everybody(void)
{
	struct udev_list_node *him_node;
	const char *state = "";

	udev_list_node_foreach(him_node, &bunch) {
		struct _mate *him = node_to_mate(him_node);

		switch (him->state) {
		case STATE_NONE:
			state = "none";
			break;
		case STATE_OLD:
			state = "old";
			break;
		case STATE_CONFIRMED:
			state = "confirmed";
			break;
		}
		fprintf(stderr, "ID: %s=%s\n", him->name, state);
	}
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "add", no_argument, NULL, 'a' },
		{ "remove", no_argument, NULL, 'r' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int argi;
	char *checkpoint, *us;
	int fd;
	int i;
	int ret = 0;
	int prune = 0;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "ardh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'a':
			prune = 0;
			break;
		case 'r':
			prune = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage();
			goto exit;
		default:
			ret = 1;
			goto exit;
		}
	}

	argi = optind;
	if (argi + 2 > argc) {
		printf("Missing parameter(s)\n");
		ret = 1;
		goto exit;
	}
	checkpoint = argv[argi++];
	us = argv[argi++];

	if (signal(SIGALRM, sig_alrm) == SIG_ERR) {
		fprintf(stderr, "Cannot set SIGALRM: %s\n", strerror(errno));
		ret = 2;
		goto exit;
	}

	udev_list_init(&bunch);

	if (debug)
		fprintf(stderr, "Using checkpoint '%s'\n", checkpoint);

	fd = prepare(TMPFILE, checkpoint);
	if (fd < 0) {
		ret = 3;
		goto out;
	}

	if (checkout(fd) < 0) {
		ret = 2;
		goto out;
	}

	for (i = argi; i < argc; i++) {
		struct udev_list_node *him_node;
		struct _mate *who;

		who = NULL;
		udev_list_node_foreach(him_node, &bunch) {
			struct _mate *him = node_to_mate(him_node);

			if (!strcmp(him->name, argv[i]))
				who = him;
		}
		if (!who) {
			struct _mate *him;

			if (debug)
				fprintf(stderr, "ID %s: not in database\n", argv[i]);
			him = malloc(sizeof (struct _mate));
			him->name = malloc(strlen(argv[i]) + 1);
			strcpy(him->name, argv[i]);
			him->state = STATE_NONE;
			udev_list_node_append(&him->node, &bunch);
		} else {
			if (debug)
				fprintf(stderr, "ID %s: found in database\n", argv[i]);
			who->state = STATE_CONFIRMED;
		}
	}

	if (prune)
		reject(us);
	else
		invite(us);

	if (debug) {
		everybody();
		fprintf(stderr, "Prune lists\n");
	}
	kickout();

	lseek(fd, 0, SEEK_SET);
	ftruncate(fd, 0);
	ret = missing(fd);

	lockf(fd, F_ULOCK, 0);
	close(fd);
 out:
	if (debug)
		everybody();
	if (ret >= 0)
		printf("COLLECT_%s=%d\n", checkpoint, ret);
 exit:
	return ret;
}
