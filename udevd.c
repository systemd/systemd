/*
 * udevd.c - hotplug event serializer
 *
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

#include <pthread.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "list.h"
#include "udev.h"
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"


unsigned char logname[42];
static pthread_mutex_t  msg_lock;
static pthread_mutex_t  msg_active_lock;
static pthread_cond_t msg_active;
static pthread_mutex_t  exec_lock;
static pthread_mutex_t  exec_active_lock;
static pthread_cond_t exec_active;
static pthread_mutex_t  running_lock;
static pthread_attr_t thr_attr;
static int expected_seqnum = 0;

LIST_HEAD(msg_list);
LIST_HEAD(exec_list);
LIST_HEAD(running_list);


static void msg_dump_queue(void)
{
	struct hotplug_msg *msg;

	list_for_each_entry(msg, &msg_list, list)
		dbg("sequence %d in queue", msg->seqnum);
}

static void msg_dump(struct hotplug_msg *msg)
{
	dbg("sequence %d, '%s', '%s', '%s'",
	    msg->seqnum, msg->action, msg->devpath, msg->subsystem);
}

static struct hotplug_msg *msg_create(void)
{
	struct hotplug_msg *new_msg;

	new_msg = malloc(sizeof(struct hotplug_msg));
	if (new_msg == NULL) {
		dbg("error malloc");
		return NULL;
	}
	return new_msg;
}

static void msg_delete(struct hotplug_msg *msg)
{
	if (msg != NULL)
		free(msg);
}

/* orders the message in the queue by sequence number */
static void msg_queue_insert(struct hotplug_msg *msg)
{
	struct hotplug_msg *loop_msg;

	/* sort message by sequence number into list*/
	list_for_each_entry(loop_msg, &msg_list, list)
		if (loop_msg->seqnum > msg->seqnum)
			break;
	list_add_tail(&msg->list, &loop_msg->list);
	dbg("queued message seq %d", msg->seqnum);

	/* store timestamp of queuing */
	msg->queue_time = time(NULL);

	/* signal queue activity to manager */
	pthread_mutex_lock(&msg_active_lock);
	pthread_cond_signal(&msg_active);
	pthread_mutex_unlock(&msg_active_lock);

	return ;
}

/* forks event and removes event from run queue when finished */
static void *run_threads(void * parm)
{
	pid_t pid;
	struct hotplug_msg *msg;

	msg = parm;
	setenv("ACTION", msg->action, 1);
	setenv("DEVPATH", msg->devpath, 1);

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
		goto exit;
	default:
		/* wait for exit of child */
		dbg("==> exec seq %d [%d] working at '%s'",
		    msg->seqnum, pid, msg->devpath);
		wait(NULL);
		dbg("<== exec seq %d came back", msg->seqnum);
	}

exit:
	/* remove event from run list */
	pthread_mutex_lock(&running_lock);
	list_del_init(&msg->list);
	pthread_mutex_unlock(&running_lock);

	msg_delete(msg);

	/* signal queue activity to exec manager */
	pthread_mutex_lock(&exec_active_lock);
	pthread_cond_signal(&exec_active);
	pthread_mutex_unlock(&exec_active_lock);

	pthread_exit(0);
}

/* returns already running task with devpath */
static struct hotplug_msg *running_with_devpath(struct hotplug_msg *msg)
{
	struct hotplug_msg *loop_msg;
	struct hotplug_msg *tmp_msg;

	list_for_each_entry_safe(loop_msg, tmp_msg, &running_list, list)
		if (strncmp(loop_msg->devpath, msg->devpath, sizeof(loop_msg->devpath)) == 0)
			return loop_msg;
	return NULL;
}

/* queue management executes the events and delays events for the same devpath */
static void *exec_queue_manager(void * parm)
{
	struct hotplug_msg *loop_msg;
	struct hotplug_msg *tmp_msg;
	struct hotplug_msg *msg;
	pthread_t run_tid;

	while (1) {
		pthread_mutex_lock(&exec_lock);
		list_for_each_entry_safe(loop_msg, tmp_msg, &exec_list, list) {
			msg = running_with_devpath(loop_msg);
			if (msg == NULL) {
				/* move event to run list */
				pthread_mutex_lock(&running_lock);
				list_move_tail(&loop_msg->list, &running_list);
				pthread_mutex_unlock(&running_lock);

				pthread_create(&run_tid, &thr_attr, run_threads, (void *) loop_msg);

				dbg("moved seq %d to running list", loop_msg->seqnum);
			} else {
				dbg("delay seq %d, cause seq %d already working on '%s'",
				    loop_msg->seqnum, msg->seqnum, msg->devpath);
			}
		}
		pthread_mutex_unlock(&exec_lock);

		/* wait for activation, new events or childs coming back */
		pthread_mutex_lock(&exec_active_lock);
		pthread_cond_wait(&exec_active, &exec_active_lock);
		pthread_mutex_unlock(&exec_active_lock);
	}
}

static void exec_queue_activate(void)
{
	pthread_mutex_lock(&exec_active_lock);
	pthread_cond_signal(&exec_active);
	pthread_mutex_unlock(&exec_active_lock);
}

/* move message from incoming to exec queue */
static void msg_move_exec(struct list_head *head)
{
	list_move_tail(head, &exec_list);
	exec_queue_activate();
}

/* queue management thread handles the timeouts and dispatches the events */
static void *msg_queue_manager(void * parm)
{
	struct hotplug_msg *loop_msg;
	struct hotplug_msg *tmp_msg;
	time_t msg_age = 0;
	struct timespec tv;

	while (1) {
		dbg("msg queue manager, next expected is %d", expected_seqnum);
		pthread_mutex_lock(&msg_lock);
		pthread_mutex_lock(&exec_lock);
recheck:
		list_for_each_entry_safe(loop_msg, tmp_msg, &msg_list, list) {
			/* move event with expected sequence to the exec list */
			if (loop_msg->seqnum == expected_seqnum) {
				msg_move_exec(&loop_msg->list);
				expected_seqnum++;
				dbg("moved seq %d to exec, next expected is %d",
				    loop_msg->seqnum, expected_seqnum);
				continue;
			}

			/* move event with expired timeout to the exec list */
			msg_age = time(NULL) - loop_msg->queue_time;
			if (msg_age > EVENT_TIMEOUT_SEC-1) {
				msg_move_exec(&loop_msg->list);
				expected_seqnum = loop_msg->seqnum+1;
				dbg("moved seq %d to exec, reset next expected to %d",
				    loop_msg->seqnum, expected_seqnum);
				goto recheck;
			} else {
				break;
			}
		}

		msg_dump_queue();
		pthread_mutex_unlock(&exec_lock);
		pthread_mutex_unlock(&msg_lock);

		/* wait until queue gets active or next message timeout expires */
		pthread_mutex_lock(&msg_active_lock);

		if (list_empty(&msg_list) == 0) {
			tv.tv_sec = time(NULL) + EVENT_TIMEOUT_SEC - msg_age;
			tv.tv_nsec = 0;
			dbg("next event expires in %li seconds",
			    EVENT_TIMEOUT_SEC - msg_age);
			pthread_cond_timedwait(&msg_active, &msg_active_lock, &tv);
		} else {
			pthread_cond_wait(&msg_active, &msg_active_lock);
		}
		pthread_mutex_unlock(&msg_active_lock);
	}
}

/* every connect creates a thread which gets the msg, queues it and exits */
static void *client_threads(void * parm)
{
	int sock;
	struct hotplug_msg *msg;
	int retval;

	sock = (int) parm;

	msg = msg_create();
	if (msg == NULL) {
		dbg("unable to store message");
		goto exit;
	}

	retval = recv(sock, msg, sizeof(struct hotplug_msg), 0);
	if (retval <  0) {
		dbg("unable to receive message");
		goto exit;
	}

	if (strncmp(msg->magic, UDEV_MAGIC, sizeof(UDEV_MAGIC)) != 0 ) {
		dbg("message magic '%s' doesn't match, ignore it", msg->magic);
		msg_delete(msg);
		goto exit;
	}

	/* if no seqnum is given, we move straight to exec queue */
	if (msg->seqnum == 0) {
		pthread_mutex_lock(&exec_lock);
		list_add(&msg->list, &exec_list);
		exec_queue_activate();
		pthread_mutex_unlock(&exec_lock);
	} else {
		pthread_mutex_lock(&msg_lock);
		msg_queue_insert(msg);
		pthread_mutex_unlock(&msg_lock);
	}

exit:
	close(sock);
	pthread_exit(0);
}

static void sig_handler(int signum)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			unlink(UDEVD_LOCK);
			exit(20 + signum);
			break;
		default:
			dbg("unhandled signal");
	}
}

static int one_and_only(void)
{
	char string[50];
	int lock_file;

	lock_file = open(UDEVD_LOCK, O_RDWR | O_CREAT, 0x640);
	if (lock_file < 0)
		return -1;

	/* see if we can lock */
	if (lockf(lock_file, F_TLOCK, 0) < 0) {
		dbg("file is already locked, exit");
		close(lock_file);
		return -1;
	}

	snprintf(string, sizeof(string), "%d\n", getpid());
	write(lock_file, string, strlen(string));

	return 0;
}

int main(int argc, char *argv[])
{
	int ssock;
	int csock;
	struct sockaddr_un saddr;
	struct sockaddr_un caddr;
	socklen_t addrlen;
	socklen_t clen;
	pthread_t cli_tid;
	pthread_t mgr_msg_tid;
	pthread_t mgr_exec_tid;
	int retval;

	init_logging("udevd");

	/* only let one version of the daemon run at any one time */
	if (one_and_only() != 0)
		exit(0);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	ssock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (ssock == -1) {
		dbg("error getting socket");
		exit(1);
	}

	retval = bind(ssock, &saddr, addrlen);
	if (retval < 0) {
		dbg("bind failed\n");
		goto exit;
	}

	retval = listen(ssock, SOMAXCONN);
	if (retval < 0) {
		dbg("listen failed\n");
		goto exit;
	}

	pthread_mutex_init(&msg_lock, NULL);
	pthread_mutex_init(&msg_active_lock, NULL);
	pthread_mutex_init(&exec_lock, NULL);
	pthread_mutex_init(&exec_active_lock, NULL);
	pthread_mutex_init(&running_lock, NULL);

	/* set default attributes for created threads */
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&thr_attr, 16 * 1024);

	/* init queue management */
	pthread_create(&mgr_msg_tid, &thr_attr, msg_queue_manager, NULL);
	pthread_create(&mgr_exec_tid, &thr_attr, exec_queue_manager, NULL);

	clen = sizeof(caddr);
	/* main loop */
	while (1) {
		csock = accept(ssock, &caddr, &clen);
		if (csock < 0) {
			dbg("client accept failed\n");
			continue;
		}
		pthread_create(&cli_tid, &thr_attr, client_threads, (void *) csock);
	}
exit:
	close(ssock);
	exit(1);
}
