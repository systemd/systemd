/*
 * udevd.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
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

#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include "list.h"
#include "udev.h"
#include "udevd.h"
#include "logging.h"

#define BUFFER_SIZE			1024

static int expect_seqnum = 0;
static int lock_file = -1;
static char *lock_filename = ".udevd_lock";

LIST_HEAD(msg_list);

static void sig_handler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
	case SIGALRM:
		dbg("event timeout reached");
		break;
	case SIGINT:
	case SIGTERM:
	case SIGKILL:
		if (lock_file >= 0) {
			close(lock_file);
			unlink(lock_filename);
		}
		exit(20 + signum);
		break;
	default:
		dbg("unhandled signal");
	}
}

static void dump_queue(void)
{
	struct hotplug_msg *msg;

	list_for_each_entry(msg, &msg_list, list)
		dbg("sequence %d in queue", msg->seqnum);
}

static void dump_msg(struct hotplug_msg *msg)
{
	dbg("sequence %d, '%s', '%s', '%s'",
	    msg->seqnum, msg->action, msg->devpath, msg->subsystem);
}

static int dispatch_msg(struct hotplug_msg *msg)
{
	pid_t pid;

	dump_msg(msg);

	setenv("ACTION", msg->action, 1);
	setenv("DEVPATH", msg->devpath, 1);

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execl(UDEV_EXEC, "udev", msg->subsystem, NULL);
		dbg("exec of child failed");
		exit(1);
		break;
	case -1:
		dbg("fork of child failed");
		return -1;
	default:
		wait(NULL);
	}
	return 0;
}

static void set_timeout(int seconds)
{
	alarm(seconds);
	dbg("set timeout in %d seconds", seconds);
}

static void check_queue(void)
{
	struct hotplug_msg *msg;
	struct hotplug_msg *tmp_msg;
	time_t msg_age;

recheck:
	/* dispatch events until one is missing */
	list_for_each_entry_safe(msg, tmp_msg, &msg_list, list) {
		if (msg->seqnum != expect_seqnum)
			break;
		dispatch_msg(msg);
		expect_seqnum++;
		list_del_init(&msg->list);
		free(msg);
	}

	/* recalculate timeout */
	if (list_empty(&msg_list) == 0) {
		msg_age = time(NULL) - msg->queue_time;
		if (msg_age > EVENT_TIMEOUT_SECONDS-1) {
			info("event %d, age %li seconds, skip event %d-%d",
			     msg->seqnum, msg_age, expect_seqnum, msg->seqnum-1);
			expect_seqnum = msg->seqnum;
			goto recheck;
		}
		set_timeout(EVENT_TIMEOUT_SECONDS - msg_age);
		return;
	}

	/* queue is empty */
	set_timeout(UDEVD_TIMEOUT_SECONDS);
}

static int queue_msg(struct hotplug_msg *msg)
{
	struct hotplug_msg *new_msg;
	struct hotplug_msg *tmp_msg;

	new_msg = malloc(sizeof(*new_msg));
	if (new_msg == NULL) {
		dbg("error malloc");
		return -ENOMEM;
	}
	memcpy(new_msg, msg, sizeof(*new_msg));

	/* store timestamp of queuing */
	new_msg->queue_time = time(NULL);

	/* sort message by sequence number into list*/
	list_for_each_entry(tmp_msg, &msg_list, list)
		if (tmp_msg->seqnum > new_msg->seqnum)
			break;
	list_add_tail(&new_msg->list, &tmp_msg->list);

	return 0;
}

static void work(void)
{
	struct hotplug_msg *msg;
	int msgid;
	key_t key;
	char buf[BUFFER_SIZE];
	int ret;

	key = ftok(UDEVD_EXEC, IPC_KEY_ID);
	msg = (struct hotplug_msg *) buf;
	msgid = msgget(key, IPC_CREAT);
	if (msgid == -1) {
		dbg("open message queue error");
		exit(1);
	}
	while (1) {
		ret = msgrcv(msgid, (struct msgbuf *) buf, BUFFER_SIZE-4, HOTPLUGMSGTYPE, 0);
		if (ret != -1) {
			/* init the expected sequence with value from first call */
			if (expect_seqnum == 0) {
				expect_seqnum = msg->seqnum;
				dbg("init next expected sequence number to %d", expect_seqnum);
			}
			dbg("current sequence %d, expected sequence %d", msg->seqnum, expect_seqnum);
			if (msg->seqnum == expect_seqnum) {
				/* execute expected event */
				dispatch_msg(msg);
				expect_seqnum++;
				check_queue();
				dump_queue();
				continue;
			}
			if (msg->seqnum > expect_seqnum) {
				/* something missing, queue event*/
				queue_msg(msg);
				check_queue();
				dump_queue();
				continue;
			}
			dbg("too late for event with sequence %d, even skipped ", msg->seqnum);
		} else {
			if (errno == EINTR) {
				/* timeout */
				if (list_empty(&msg_list)) {
					info("we have nothing to do, so daemon exits...");
					if (lock_file >= 0) {
						close(lock_file);
						unlink(lock_filename);
					}
					exit(0);
				}
				check_queue();
				dump_queue();
				continue;
			}
			dbg("ipc message receive error '%s'", strerror(errno));
		}
	}
}

static int one_and_only(void)
{
	char string[100];

	lock_file = open(lock_filename, O_RDWR | O_CREAT, 0x640);

	/* see if we can open */
	if (lock_file < 0)
		return -1;
	
	/* see if we can lock */
	if (lockf(lock_file, F_TLOCK, 0) < 0) {
		close(lock_file);
		unlink(lock_filename);
		return -1;
	}

	snprintf(string, sizeof(string), "%d\n", getpid());
	write(lock_file, string, strlen(string));

	return 0;
}

int main(int argc, char *argv[])
{
	/* only let one version of the daemon run at any one time */
	if (one_and_only() != 0)
		exit(0);

	/* set up signal handler */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGKILL, sig_handler);
	signal(SIGALRM, sig_handler);

	/* we exit if we have nothing to do, next event will start us again */
	set_timeout(UDEVD_TIMEOUT_SECONDS);

	work();
	exit(0);
}
