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

#define BUFFER_SIZE		1024
#define TIMEOUT_SECONDS		10

static void reset_timer(void);
static void reset_queue(void);


static int expect_seqnum = 0;
static int timeout_value = TIMEOUT_SECONDS;
static int timeout = 0;
static struct hotplug_msg *head = NULL;
static char exec_program[100];


static void sig_handler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
		case SIGHUP:
			dbg("reset requested, all waiting events killed");
			reset_timer();
			reset_queue();
			timeout = 0;
			expect_seqnum = 0;
			break;

		case SIGINT:
		case SIGTERM:
		case SIGKILL:
			exit(20 + signum);
			break;

		default:
			dbg("unhandled signal");
	}
}

static void sig_alarmhandler(int signum)
{
	dbg("caught signal %d", signum);
	switch (signum) {
	case SIGALRM:
		timeout = 1;
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
	while(p) {
		dbg("sequence %d in queue", p->seqnum);
		p=p->next;
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
	int retval;
	extern char **environ;

	dump_msg(pmsg);
	dbg("exec '%s'", exec_program);

	setenv("ACTION", pmsg->action, 1);
	setenv("DEVPATH", pmsg->devpath, 1);

	argv[0] = exec_program;
	argv[1] = pmsg->subsystem;
	argv[2] = NULL;

	pid = fork();
	switch (pid) {
	case 0:
		retval = execve(argv[0], argv, environ);
		if (retval != 0) {
			dbg("child execve failed");
			exit(1);
		}
		break;
	case -1:
		dbg("fork failed");
		return -1;
	default:
		wait(0);
		break;
	}
	return 0;
}

static void reset_timer(void)
{
	alarm(0);
}

static void set_timer(void)
{
	signal(SIGALRM, sig_alarmhandler);
	alarm(timeout_value);
}

static void reset_queue(void)
{
	struct hotplug_msg *p;
	p = head;

	while(head) {
		p = head;
		head = head->next;
		free(p);
	}
}

static void check_queue(void)
{
	struct hotplug_msg *p;
	p = head;

	dump_queue();
	while(head && head->seqnum == expect_seqnum) {
		dispatch_msg(head);
		expect_seqnum++;
		p = head;
		head = head->next;
		free(p);
	}
	if (head != NULL)
		set_timer();
	else
		reset_timer();
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
	while(p && pmsg->seqnum > p->seqnum) {
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

	key = ftok(DEFAULT_EXEC_PROGRAM, IPC_KEY_ID);
	pmsg = (struct hotplug_msg *) buf;
	msgid = msgget(key, IPC_CREAT);
	if (msgid == -1) {
		dbg("open message queue error");
		goto exit;
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
				set_timer();
			} else {
				if (pmsg->seqnum == expect_seqnum) {
					dispatch_msg(pmsg);
					expect_seqnum++;
					check_queue();
				} else {
					dbg("timeout event for unexpected sequence number %d", pmsg->seqnum);
				}
			}
		} else
			if (errno == EINTR) {
				if (head != NULL) {
					/* timeout, skip all missing, proceed with next queued event */
					dbg("timeout reached, skip events %d - %d", expect_seqnum, head->seqnum-1);
					expect_seqnum = head->seqnum;
				}
				check_queue();
				timeout = 0;
			} else {
				dbg("ipc message receive error '%s'", strerror(errno));
			}
	}
	return 0;
exit:
	return -1;
}

int main(int argc, char *argv[])
{
	/* get program to exec on events */
	if (argc == 2)
		strncpy(exec_program, argv[1], sizeof(exec_program));
	else
		strcpy(exec_program, DEFAULT_EXEC_PROGRAM);

	/* set up signal handler */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGKILL, sig_handler);
	signal(SIGHUP, sig_handler);

	/* main loop */
	process_queue();
	return 0;
}
