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

#include "udev.h"
#include "udevd.h"
#include "logging.h"

#define BUFFER_SIZE			1024
#define EVENT_TIMEOUT_SECONDS		10
#define DAEMON_TIMEOUT_SECONDS		30


static int expect_seqnum = 0;
static struct hotplug_msg *head = NULL;


static void sig_alarmhandler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
	case SIGALRM:
		dbg("event timeout reached");
		break;

	default:
		dbg("unhandled signal");
	}
}

static void dump_queue(void)
{
	struct hotplug_msg *p;
	p = head;

	dbg("next expected sequence is %d", expect_seqnum);
	while(p != NULL) {
		dbg("sequence %d in queue", p->seqnum);
		p = p->next;
	}
}

static void dump_msg(struct hotplug_msg *pmsg)
{
	dbg("sequence %d, '%s', '%s', '%s'",
	    pmsg->seqnum, pmsg->action, pmsg->devpath, pmsg->subsystem);
}

static int dispatch_msg(struct hotplug_msg *pmsg)
{
	pid_t pid;
	char *argv[3];
	extern char **environ;

	dump_msg(pmsg);

	setenv("ACTION", pmsg->action, 1);
	setenv("DEVPATH", pmsg->devpath, 1);
	argv[0] = DEFAULT_UDEV_EXEC;
	argv[1] = pmsg->subsystem;
	argv[2] = NULL;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execve(argv[0], argv, environ);
		dbg("exec of child failed");
		exit(1);
		break;
	case -1:
		dbg("fork of child failed");
		return -1;
	default:
		wait(0);
	}
	return 0;
}

static void set_timer(int seconds)
{
	signal(SIGALRM, sig_alarmhandler);
	alarm(seconds);
}

static void check_queue(void)
{
	struct hotplug_msg *p;
	p = head;

	dump_queue();
	while(head != NULL && head->seqnum == expect_seqnum) {
		dispatch_msg(head);
		expect_seqnum++;
		p = head;
		head = head->next;
		free(p);
	}
	if (head != NULL)
		set_timer(EVENT_TIMEOUT_SECONDS);
	else
		set_timer(DAEMON_TIMEOUT_SECONDS);
}

static void add_queue(struct hotplug_msg *pmsg)
{
	struct hotplug_msg *pnewmsg;
	struct hotplug_msg *p;
	struct hotplug_msg *p1;

	p = head;
	p1 = NULL;
	pnewmsg = malloc(sizeof(struct hotplug_msg));
	*pnewmsg = *pmsg;
	pnewmsg->next = NULL;
	while(p != NULL && pmsg->seqnum > p->seqnum) {
		p1 = p;
		p = p->next;
	}
	pnewmsg->next = p;
	if (p1 == NULL) {
		head = pnewmsg;
	} else {
		p1->next = pnewmsg;
	}
	dump_queue();
}

static int process_queue(void)
{
	int msgid;
	key_t key;
	struct hotplug_msg *pmsg;
	char buf[BUFFER_SIZE];
	int ret;

	key = ftok(DEFAULT_UDEVD_EXEC, IPC_KEY_ID);
	pmsg = (struct hotplug_msg *) buf;
	msgid = msgget(key, IPC_CREAT);
	if (msgid == -1) {
		dbg("open message queue error");
		return -1;
	}
	while (1) {
		ret = msgrcv(msgid, (struct msgbuf *) buf, BUFFER_SIZE-4, HOTPLUGMSGTYPE, 0);
		if (ret != -1) {
			dbg("current sequence %d, expected sequence %d", pmsg->seqnum, expect_seqnum);

			/* init expected sequence with value from first call */
			if (expect_seqnum == 0) {
				expect_seqnum = pmsg->seqnum;
				dbg("init next expected sequence number to %d", expect_seqnum);
			}

			if (pmsg->seqnum > expect_seqnum) {
				add_queue(pmsg);
				set_timer(EVENT_TIMEOUT_SECONDS);
			} else {
				if (pmsg->seqnum == expect_seqnum) {
					dispatch_msg(pmsg);
					expect_seqnum++;
					check_queue();
				} else {
					dbg("timeout event for unexpected sequence number %d", pmsg->seqnum);
				}
			}
		} else {
			if (errno == EINTR) {
				if (head != NULL) {
					/* event timeout, skip all missing, proceed with next queued event */
					info("timeout reached, skip events %d - %d", expect_seqnum, head->seqnum-1);
					expect_seqnum = head->seqnum;
				} else {
					info("we have nothing to do, so daemon exits...");
					exit(0);
				}
				check_queue();
			} else {
				dbg("ipc message receive error '%s'", strerror(errno));
			}
		}
	}
	return 0;
}

static void sig_handler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
		case SIGINT:
		case SIGTERM:
		case SIGKILL:
			exit(20 + signum);
			break;

		default:
			dbg("unhandled signal");
	}
}

int main(int argc, char *argv[])
{
	/* set up signal handler */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGKILL, sig_handler);

	/* we exit if we have nothing to do, next event will start us again */
	set_timer(DAEMON_TIMEOUT_SECONDS);

	/* main loop */
	process_queue();
	return 0;
}
