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
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"


#define BUFFER_SIZE			1024

static int running_remove_queue(pid_t pid);
static int msg_exec(struct hotplug_msg *msg);

static int expect_seqnum = 0;
static int lock_file = -1;
static char *lock_filename = ".udevd_lock";

LIST_HEAD(msg_list);
LIST_HEAD(running_list);
LIST_HEAD(delayed_list);

static void sig_handler(int signum)
{
	pid_t pid;

	dbg("caught signal %d", signum);
	switch (signum) {
	case SIGALRM:
		dbg("event timeout reached");
		break;
	case SIGCHLD:
		/* catch signals from exiting childs */
		while ( (pid = waitpid(-1, NULL, WNOHANG)) > 0) {
			dbg("exec finished, pid %d", pid);
			running_remove_queue(pid);
		}
		break;
	case SIGINT:
	case SIGTERM:
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

static void set_timeout(int seconds)
{
	alarm(seconds);
	dbg("set timeout in %d seconds", seconds);
}

static int running_moveto_queue(struct hotplug_msg *msg)
{
	dbg("move sequence %d [%d] to running queue '%s'",
	    msg->seqnum, msg->pid, msg->devpath);
	list_move_tail(&msg->list, &running_list);
	return 0;
}

static int running_remove_queue(pid_t  pid)
{
	struct hotplug_msg *child;
	struct hotplug_msg *tmp_child;

	list_for_each_entry_safe(child, tmp_child, &running_list, list)
		if (child->pid == pid) {
			list_del_init(&child->list);
			free(child);
			return 0;
		}
	return -EINVAL;
}

static pid_t running_getpid_by_devpath(struct hotplug_msg *msg)
{
	struct hotplug_msg *child;
	struct hotplug_msg *tmp_child;

	list_for_each_entry_safe(child, tmp_child, &running_list, list)
		if (strncmp(child->devpath, msg->devpath, sizeof(child->devpath)) == 0)
			return child->pid;
	return 0;
}

static void delayed_dump_queue(void)
{
	struct hotplug_msg *child;

	list_for_each_entry(child, &delayed_list, list)
		dbg("event for '%s' in queue", child->devpath);
}

static int delayed_moveto_queue(struct hotplug_msg *msg)
{
	dbg("move event to delayed queue '%s'", msg->devpath);
	list_move_tail(&msg->list, &delayed_list);
	return 0;
}

static void delayed_check_queue(void)
{
	struct hotplug_msg *delayed_child;
	struct hotplug_msg *running_child;
	struct hotplug_msg *tmp_child;

	/* see if we have delayed exec's that can run now */
	list_for_each_entry_safe(delayed_child, tmp_child, &delayed_list, list)
		list_for_each_entry_safe(running_child, tmp_child, &running_list, list)
			if (strncmp(delayed_child->devpath, running_child->devpath,
			    sizeof(running_child->devpath)) == 0) {
				dbg("delayed exec for '%s' can run now", delayed_child->devpath);
				msg_exec(delayed_child);
			}
}

static void msg_dump(struct hotplug_msg *msg)
{
	dbg("sequence %d, '%s', '%s', '%s'",
	    msg->seqnum, msg->action, msg->devpath, msg->subsystem);
}

static int msg_exec(struct hotplug_msg *msg)
{
	pid_t pid;

	msg_dump(msg);

	setenv("ACTION", msg->action, 1);
	setenv("DEVPATH", msg->devpath, 1);

	/* delay exec, if we already have a udev working on the same devpath */
	pid = running_getpid_by_devpath(msg);
	if (pid != 0) {
		dbg("delay exec of sequence %d, [%d] already working on '%s'",
		    msg->seqnum, pid, msg->devpath);
		delayed_moveto_queue(msg);
	}

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execl(UDEV_BIN, "udev", msg->subsystem, NULL);
		dbg("exec of child failed");
		exit(1);
		break;
	case -1:
		dbg("fork of child failed");
		return -1;
	default:
		/* exec in background, get the SIGCHLD with the sig handler */
		msg->pid = pid;
		running_moveto_queue(msg);
		break;
	}
	return 0;
}

static void msg_dump_queue(void)
{
	struct hotplug_msg *msg;

	list_for_each_entry(msg, &msg_list, list)
		dbg("sequence %d in queue", msg->seqnum);
}

static void msg_check_queue(void)
{
	struct hotplug_msg *msg;
	struct hotplug_msg *tmp_msg;
	time_t msg_age;

recheck:
	/* dispatch events until one is missing */
	list_for_each_entry_safe(msg, tmp_msg, &msg_list, list) {
		if (msg->seqnum != expect_seqnum)
			break;
		msg_exec(msg);
		expect_seqnum++;
	}

	/* recalculate next timeout */
	if (list_empty(&msg_list) == 0) {
		msg_age = time(NULL) - msg->queue_time;
		if (msg_age > EVENT_TIMEOUT_SEC-1) {
			info("event %d, age %li seconds, skip event %d-%d",
			     msg->seqnum, msg_age, expect_seqnum, msg->seqnum-1);
			expect_seqnum = msg->seqnum;
			goto recheck;
		}

		/* the first sequence gets its own timeout */
		if (expect_seqnum == 0) {
			msg_age = EVENT_TIMEOUT_SEC - FIRST_EVENT_TIMEOUT_SEC;
			expect_seqnum = 1;
		}

		set_timeout(EVENT_TIMEOUT_SEC - msg_age);
		return;
	}
}

static int msg_add_queue(struct hotplug_msg *msg)
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

	key = ftok(UDEVD_BIN, IPC_KEY_ID);
	msg = (struct hotplug_msg *) buf;
	msgid = msgget(key, IPC_CREAT);
	if (msgid == -1) {
		dbg("open message queue error");
		exit(1);
	}
	while (1) {
		ret = msgrcv(msgid, (struct msgbuf *) buf, BUFFER_SIZE-4, HOTPLUGMSGTYPE, 0);
		if (ret != -1) {
			dbg("received sequence %d, expected sequence %d", msg->seqnum, expect_seqnum);
			if (msg->seqnum >= expect_seqnum) {
				msg_add_queue(msg);
				msg_dump_queue();
				msg_check_queue();
				continue;
			}
			dbg("too late for event with sequence %d, event skipped ", msg->seqnum);
		} else {
			if (errno == EINTR) {
				msg_check_queue();
				msg_dump_queue();
				delayed_check_queue();
				delayed_dump_queue();
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
	signal(SIGALRM, sig_handler);
	signal(SIGCHLD, sig_handler);

	work();
	exit(0);
}
