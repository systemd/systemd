/*
 * udevd.c - hotplug event serializer
 *
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <linux/netlink.h>

#include "list.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_version.h"
#include "udev_utils.h"
#include "udevd.h"
#include "logging.h"

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

/* global variables*/
static int udevd_sock;
static int uevent_netlink_sock;
static pid_t sid;

static int pipefds[2];
static volatile int sigchilds_waiting;
static volatile int run_msg_q;
static volatile int sig_flag;
static int init_phase = 1;
static int run_exec_q;
static int stop_exec_q;

static LIST_HEAD(msg_list);
static LIST_HEAD(exec_list);
static LIST_HEAD(running_list);

static void exec_queue_manager(void);
static void msg_queue_manager(void);
static void user_sighandler(void);
static void reap_sigchilds(void);

static char *udev_bin;
static unsigned long long expected_seqnum;
static int event_timeout;
static int max_childs;
static int max_childs_running;


#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void msg_dump_queue(void)
{
#ifdef DEBUG
	struct uevent_msg *msg;

	list_for_each_entry(msg, &msg_list, node)
		dbg("sequence %llu in queue", msg->seqnum);
#endif
}

static void msg_queue_delete(struct uevent_msg *msg)
{
	list_del(&msg->node);
	free(msg);
}

/* orders the message in the queue by sequence number */
static void msg_queue_insert(struct uevent_msg *msg)
{
	struct uevent_msg *loop_msg;
	struct sysinfo info;

	if (msg->seqnum == 0) {
		dbg("no SEQNUM, move straight to the exec queue");
		list_add(&msg->node, &exec_list);
		run_exec_q = 1;
		return;
	}

	/* store timestamp of queuing */
	sysinfo(&info);
	msg->queue_time = info.uptime;

	/* with the first event we provide a phase of shorter timeout */
	if (init_phase) {
		static long init_time;

		if (init_time == 0)
			init_time = info.uptime;
		if (info.uptime - init_time >= UDEVD_INIT_TIME)
			init_phase = 0;
	}

	/* don't delay messages with timeout set */
	if (msg->timeout) {
		dbg("move seq %llu with timeout %u to exec queue", msg->seqnum, msg->timeout);
		list_add(&msg->node, &exec_list);
		run_exec_q = 1;
		return;
	}

	/* sort message by sequence number into list */
	list_for_each_entry_reverse(loop_msg, &msg_list, node) {
		if (loop_msg->seqnum < msg->seqnum)
			break;

		if (loop_msg->seqnum == msg->seqnum) {
			dbg("ignoring duplicate message seq %llu", msg->seqnum);
			free(msg);
			return;
		}
	}
	list_add(&msg->node, &loop_msg->node);
	info("seq %llu queued, devpath '%s'", msg->seqnum, msg->devpath);

	/* run msg queue manager */
	run_msg_q = 1;

	return;
}

/* forks event and removes event from run queue when finished */
static void udev_event_fork(struct uevent_msg *msg)
{
	char *const argv[] = { "udev", msg->subsystem, NULL };
	pid_t pid;
	struct sysinfo info;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		if (uevent_netlink_sock != -1)
			close(uevent_netlink_sock);
		close(udevd_sock);
		logging_close();
		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);
		execve(udev_bin, argv, msg->envp);
		err("exec of child failed");
		_exit(1);
	case -1:
		err("fork of child failed");
		msg_queue_delete(msg);
		break;
	default:
		/* get SIGCHLD in main loop */
		sysinfo(&info);
		info("seq %llu forked, pid %d, %ld seconds old",
		     msg->seqnum, pid, info.uptime - msg->queue_time);
		msg->pid = pid;
	}
}

static int running_processes(void)
{
	int f;
	static char buf[4096];
	int len;
	int running;
	const char *pos;

	f = open("/proc/stat", O_RDONLY);
	if (f == -1)
		return -1;

	len = read(f, buf, sizeof(buf));
	close(f);

	if (len <= 0)
		return -1;
	else
		buf[len] = '\0';

	pos = strstr(buf, "procs_running ");
	if (pos == NULL)
		return -1;

	if (sscanf(pos, "procs_running %u", &running) != 1)
		return -1;

	return running;
}

/* return the number of process es in our session, count only until limit */
static int running_processes_in_session(pid_t session, int limit)
{
	DIR *dir;
	struct dirent *dent;
	int running = 0;

	dir = opendir("/proc");
	if (!dir)
		return -1;

	/* read process info from /proc */
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		int f;
		char procdir[64];
		char line[256];
		const char *pos;
		char state;
		pid_t ppid, pgrp, sess;
		int len;

		if (!isdigit(dent->d_name[0]))
			continue;

		snprintf(procdir, sizeof(procdir), "/proc/%s/stat", dent->d_name);
		procdir[sizeof(procdir)-1] = '\0';

		f = open(procdir, O_RDONLY);
		if (f == -1)
			continue;

		len = read(f, line, sizeof(line));
		close(f);

		if (len <= 0)
			continue;
		else
			line[len] = '\0';

		/* skip ugly program name */
		pos = strrchr(line, ')') + 2;
		if (pos == NULL)
			continue;

		if (sscanf(pos, "%c %d %d %d ", &state, &ppid, &pgrp, &sess) != 4)
			continue;

		/* count only processes in our session */
		if (sess != session)
			continue;

		/* count only running, no sleeping processes */
		if (state != 'R')
			continue;

		running++;
		if (limit > 0 && running >= limit)
			break;
	}
	closedir(dir);

	return running;
}

static int compare_devpath(const char *running, const char *waiting)
{
	int i;

	for (i = 0; i < PATH_SIZE; i++) {
		/* identical device event found */
		if (running[i] == '\0' && waiting[i] == '\0')
			return 1;

		/* parent device event found */
		if (running[i] == '\0' && waiting[i] == '/')
			return 2;

		/* child device event found */
		if (running[i] == '/' && waiting[i] == '\0')
			return 3;

		/* no matching event */
		if (running[i] != waiting[i])
			break;
	}

	return 0;
}

/* returns still running task for the same device, its parent or its physical device */
static int running_with_devpath(struct uevent_msg *msg, int limit)
{
	struct uevent_msg *loop_msg;
	int childs_count = 0;

	if (msg->devpath == NULL)
		return 0;

	/* skip any events with a timeout set */
	if (msg->timeout != 0)
		return 0;

	list_for_each_entry(loop_msg, &running_list, node) {
		if (limit && childs_count++ > limit) {
			dbg("%llu, maximum number (%i) of child reached", msg->seqnum, childs_count);
			return 1;
		}
		if (loop_msg->devpath == NULL)
			continue;

		/* return running parent/child device event */
		if (compare_devpath(loop_msg->devpath, msg->devpath) != 0) {
			dbg("%llu, child device event still running %llu (%s)",
			    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
			return 2;
		}

		/* return running physical device event */
		if (msg->physdevpath && msg->action && strcmp(msg->action, "add") == 0)
			if (compare_devpath(loop_msg->devpath, msg->physdevpath) != 0) {
				dbg("%llu, physical device event still running %llu (%s)",
				    msg->seqnum, loop_msg->seqnum, loop_msg->devpath);
				return 3;
			}
	}

	return 0;
}

/* exec queue management routine executes the events and serializes events in the same sequence */
static void exec_queue_manager(void)
{
	struct uevent_msg *loop_msg;
	struct uevent_msg *tmp_msg;
	int running;

	if (list_empty(&exec_list))
		return;

	running = running_processes();
	dbg("%d processes runnning on system", running);
	if (running < 0)
		running = max_childs_running;

	list_for_each_entry_safe(loop_msg, tmp_msg, &exec_list, node) {
		/* check running processes in our session and possibly throttle */
		if (running >= max_childs_running) {
			running = running_processes_in_session(sid, max_childs_running+10);
			dbg("at least %d processes running in session", running);
			if (running >= max_childs_running) {
				dbg("delay seq %llu, cause too many processes already running",
				    loop_msg->seqnum);
				return;
			}
		}

		if (running_with_devpath(loop_msg, max_childs) == 0) {
			/* move event to run list */
			list_move_tail(&loop_msg->node, &running_list);
			udev_event_fork(loop_msg);
			running++;
			dbg("moved seq %llu to running list", loop_msg->seqnum);
		} else
			dbg("delay seq %llu (%s)", loop_msg->seqnum, loop_msg->devpath);
	}
}

static void msg_move_exec(struct uevent_msg *msg)
{
	list_move_tail(&msg->node, &exec_list);
	run_exec_q = 1;
	expected_seqnum = msg->seqnum+1;
	dbg("moved seq %llu to exec, next expected is %llu",
		msg->seqnum, expected_seqnum);
}

/* msg queue management routine handles the timeouts and dispatches the events */
static void msg_queue_manager(void)
{
	struct uevent_msg *loop_msg;
	struct uevent_msg *tmp_msg;
	struct sysinfo info;
	long msg_age = 0;
	int timeout = event_timeout;

	dbg("msg queue manager, next expected is %llu", expected_seqnum);
recheck:
	sysinfo(&info);
	list_for_each_entry_safe(loop_msg, tmp_msg, &msg_list, node) {
		/* move event with expected sequence to the exec list */
		if (loop_msg->seqnum == expected_seqnum) {
			msg_move_exec(loop_msg);
			continue;
		}

		/* limit timeout during initialization phase */
		if (init_phase) {
			timeout = UDEVD_INIT_EVENT_TIMEOUT;
			dbg("initialization phase, limit timeout to %i seconds", UDEVD_INIT_EVENT_TIMEOUT);
		}

		/* move event with expired timeout to the exec list */
		msg_age = info.uptime - loop_msg->queue_time;
		dbg("seq %llu is %li seconds old", loop_msg->seqnum, msg_age);
		if (msg_age >= timeout) {
			msg_move_exec(loop_msg);
			goto recheck;
		} else {
			break;
		}
	}

	msg_dump_queue();

	/* set timeout for remaining queued events */
	if (list_empty(&msg_list) == 0) {
		struct itimerval itv = {{0, 0}, {timeout - msg_age, 0}};
		dbg("next event expires in %li seconds", timeout - msg_age);
		setitimer(ITIMER_REAL, &itv, NULL);
	}
}

static struct uevent_msg *get_msg_from_envbuf(const char *buf, int buf_size)
{
	int bufpos;
	int i;
	struct uevent_msg *msg;
	int major = 0;
	int minor = 0;

	msg = malloc(sizeof(struct uevent_msg) + buf_size);
	if (msg == NULL)
		return NULL;
	memset(msg, 0x00, sizeof(struct uevent_msg) + buf_size);

	/* copy environment buffer and reconstruct envp */
	memcpy(msg->envbuf, buf, buf_size);
	bufpos = 0;
	for (i = 0; (bufpos < buf_size) && (i < UEVENT_NUM_ENVP-2); i++) {
		int keylen;
		char *key;

		key = &msg->envbuf[bufpos];
		keylen = strlen(key);
		msg->envp[i] = key;
		bufpos += keylen + 1;
		dbg("add '%s' to msg.envp[%i]", msg->envp[i], i);

		/* remember some keys for further processing */
		if (strncmp(key, "ACTION=", 7) == 0)
			msg->action = &key[7];
		else if (strncmp(key, "DEVPATH=", 8) == 0)
			msg->devpath = &key[8];
		else if (strncmp(key, "SUBSYSTEM=", 10) == 0)
			msg->subsystem = &key[10];
		else if (strncmp(key, "SEQNUM=", 7) == 0)
			msg->seqnum = strtoull(&key[7], NULL, 10);
		else if (strncmp(key, "PHYSDEVPATH=", 12) == 0)
			msg->physdevpath = &key[12];
		else if (strncmp(key, "MAJOR=", 6) == 0)
			major = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "MINOR=", 6) == 0)
			minor = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "TIMEOUT=", 8) == 0)
			msg->timeout = strtoull(&key[8], NULL, 10);
	}
	msg->devt = makedev(major, minor);
	msg->envp[i++] = "UDEVD_EVENT=1";
	msg->envp[i] = NULL;

	return msg;
}

/* receive the udevd message from userspace */
static struct uevent_msg *get_udevd_msg(void)
{
	static struct udevd_msg usend_msg;
	struct uevent_msg *msg;
	ssize_t size;
	struct msghdr smsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *cred;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	int envbuf_size;
	int *intval;

	memset(&usend_msg, 0x00, sizeof(struct udevd_msg));
	iov.iov_base = &usend_msg;
	iov.iov_len = sizeof(struct udevd_msg);

	memset(&smsg, 0x00, sizeof(struct msghdr));
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = sizeof(cred_msg);

	size = recvmsg(udevd_sock, &smsg, 0);
	if (size <  0) {
		if (errno != EINTR)
			dbg("unable to receive udevd message");
		return NULL;
	}
	cmsg = CMSG_FIRSTHDR(&smsg);
	cred = (struct ucred *) CMSG_DATA(cmsg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		info("no sender credentials received, message ignored");
		return NULL;
	}

	if (cred->uid != 0) {
		info("sender uid=%i, message ignored", cred->uid);
		return NULL;
	}

	if (strncmp(usend_msg.magic, UDEV_MAGIC, sizeof(UDEV_MAGIC)) != 0 ) {
		info("message magic '%s' doesn't match, ignore it", usend_msg.magic);
		return NULL;
	}

	switch (usend_msg.type) {
	case UDEVD_UEVENT_UDEVSEND:
	case UDEVD_UEVENT_INITSEND:
		info("udevd event message received");
		envbuf_size = size - offsetof(struct udevd_msg, envbuf);
		dbg("envbuf_size=%i", envbuf_size);
		msg = get_msg_from_envbuf(usend_msg.envbuf, envbuf_size);
		if (msg == NULL)
			return NULL;
		msg->type = usend_msg.type;
		return msg;
	case UDEVD_STOP_EXEC_QUEUE:
		info("udevd message (STOP_EXEC_QUEUE) received");
		stop_exec_q = 1;
		break;
	case UDEVD_START_EXEC_QUEUE:
		info("udevd message (START_EXEC_QUEUE) received");
		stop_exec_q = 0;
		exec_queue_manager();
		break;
	case UDEVD_SET_LOG_LEVEL:
		intval = (int *) usend_msg.envbuf;
		info("udevd message (SET_LOG_PRIORITY) received, udev_log_priority=%i", *intval);
		udev_log_priority = *intval;
		break;
	case UDEVD_SET_MAX_CHILDS:
		intval = (int *) usend_msg.envbuf;
		info("udevd message (UDEVD_SET_MAX_CHILDS) received, max_childs=%i", *intval);
		max_childs = *intval;
		break;
	default:
		dbg("unknown message type");
	}
	return NULL;
}

/* receive the kernel user event message and do some sanity checks */
static struct uevent_msg *get_netlink_msg(void)
{
	struct uevent_msg *msg;
	int bufpos;
	ssize_t size;
	static char buffer[UEVENT_BUFFER_SIZE + 512];
	char *pos;

	size = recv(uevent_netlink_sock, &buffer, sizeof(buffer), 0);
	if (size <  0) {
		if (errno != EINTR)
			dbg("unable to receive udevd message");
		return NULL;
	}

	if ((size_t)size > sizeof(buffer)-1)
		size = sizeof(buffer)-1;
	buffer[size] = '\0';
	dbg("uevent_size=%zi", size);

	/* start of event payload */
	bufpos = strlen(buffer)+1;
	msg = get_msg_from_envbuf(&buffer[bufpos], size-bufpos);
	if (msg == NULL)
		return NULL;
	msg->type = UDEVD_UEVENT_NETLINK;

	/* validate message */
	pos = strchr(buffer, '@');
	if (pos == NULL) {
		dbg("invalid uevent '%s'", buffer);
		free(msg);
		return NULL;
	}
	pos[0] = '\0';

	if (msg->action == NULL) {
		dbg("no ACTION in payload found, skip event '%s'", buffer);
		free(msg);
		return NULL;
	}

	if (strcmp(msg->action, buffer) != 0) {
		dbg("ACTION in payload does not match uevent, skip event '%s'", buffer);
		free(msg);
		return NULL;
	}

	return msg;
}

static void asmlinkage sig_handler(int signum)
{
	int rc;

	switch (signum) {
		case SIGINT:
		case SIGTERM:
			exit(20 + signum);
			break;
		case SIGALRM:
			/* set flag, then write to pipe if needed */
			run_msg_q = 1;
			goto do_write;
			break;
		case SIGCHLD:
			/* set flag, then write to pipe if needed */
			sigchilds_waiting = 1;
			goto do_write;
			break;
	}

do_write:
	/* if pipe is empty, write to pipe to force select to return
	 * immediately when it gets called
	 */
	if (!sig_flag) {
		rc = write(pipefds[1],&signum,sizeof(signum));
		if (rc >= 0)
			sig_flag = 1;
	}
}

static void udev_done(int pid)
{
	/* find msg associated with pid and delete it */
	struct uevent_msg *msg;
	struct sysinfo info;

	list_for_each_entry(msg, &running_list, node) {
		if (msg->pid == pid) {
			sysinfo(&info);
			info("seq %llu exit, %ld seconds old", msg->seqnum, info.uptime - msg->queue_time);
			msg_queue_delete(msg);

			/* we want to run the exec queue manager since there may
			 * be events waiting with the devpath of the one that
			 * just finished
			 */
			run_exec_q = 1;
			return;
		}
	}
}

static void reap_sigchilds(void)
{
	while(1) {
		int pid = waitpid(-1, NULL, WNOHANG);
		if ((pid == -1) || (pid == 0))
			break;
		udev_done(pid);
	}
}

/* just read everything from the pipe and clear the flag,
 * the flags was set in the signal handler
 */
static void user_sighandler(void)
{
	int sig;

	while(1) {
		int rc = read(pipefds[0], &sig, sizeof(sig));
		if (rc < 0)
			break;

		sig_flag = 0;
	}
}

static int init_udevd_socket(void)
{
	struct sockaddr_un saddr;
	const int buffersize = 1024 * 1024;
	socklen_t addrlen;
	const int feature_on = 1;
	int retval;

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	udevd_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (udevd_sock == -1) {
		err("error getting socket, %s", strerror(errno));
		return -1;
	}

	/* set receive buffersize */
	setsockopt(udevd_sock, SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(buffersize));

	/* the bind takes care of ensuring only one copy running */
	retval = bind(udevd_sock, (struct sockaddr *) &saddr, addrlen);
	if (retval < 0) {
		err("bind failed, %s", strerror(errno));
		close(udevd_sock);
		return -1;
	}

	/* enable receiving of the sender credentials */
	setsockopt(udevd_sock, SOL_SOCKET, SO_PASSCRED, &feature_on, sizeof(feature_on));

	return 0;
}

static int init_uevent_netlink_sock(void)
{
	struct sockaddr_nl snl;
	const int buffersize = 1024 * 1024;
	int retval;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 0xffffffff;

	uevent_netlink_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_netlink_sock == -1) {
		dbg("error getting socket, %s", strerror(errno));
		return -1;
	}

	/* set receive buffersize */
	setsockopt(uevent_netlink_sock, SOL_SOCKET, SO_RCVBUF, &buffersize, sizeof(buffersize));

	retval = bind(uevent_netlink_sock, (struct sockaddr *) &snl,
		      sizeof(struct sockaddr_nl));
	if (retval < 0) {
		dbg("bind failed, %s", strerror(errno));
		close(uevent_netlink_sock);
		uevent_netlink_sock = -1;
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	int maxsockplus;
	int retval;
	int fd;
	struct sigaction act;
	fd_set readfds;
	const char *value;
	int uevent_netlink_active = 0;
	int daemonize = 0;
	int i;

	logging_init("udevd");
	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	if (getuid() != 0) {
		err("need to be root, exit");
		goto exit;
	}

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];
		if (strcmp(arg, "--daemon") == 0 || strcmp(arg, "-d") == 0) {
			info("will daemonize");
			daemonize = 1;
		}
		if (strcmp(arg, "--stop-exec-queue") == 0) {
			info("will not execute events until START_EXEC_QUEUE is received");
			stop_exec_q = 1;
		}
	}
	if (daemonize) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			dbg("damonized fork running");
			break;
		case -1:
			err("fork of daemon failed");
			goto exit;
		default:
			logging_close();
			exit(0);
		}
	}

	/* become session leader */
	sid = setsid();
	dbg("our session is %d", sid);

	chdir("/");
	umask(umask(077) | 022);

	/*set a reasonable scheduling priority for the daemon */
	setpriority(PRIO_PROCESS, 0, UDEVD_PRIORITY);

	/* Set fds to dev/null */
	fd = open( "/dev/null", O_RDWR );
	if (fd >= 0)  {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	} else
		err("error opening /dev/null %s", strerror(errno));

	/* setup signal handler pipe */
	retval = pipe(pipefds);
	if (retval < 0) {
		err("error getting pipes: %s", strerror(errno));
		goto exit;
	}

	retval = fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(pipefds[0], F_SETFD, FD_CLOEXEC);
	if (retval < 0)
		err("error fcntl on read pipe: %s", strerror(errno));

	retval = fcntl(pipefds[1], F_SETFL, O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(pipefds[1], F_SETFD, FD_CLOEXEC);
	if (retval < 0)
		err("error fcntl on write pipe: %s", strerror(errno));

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

	if (init_uevent_netlink_sock() < 0) {
		dbg("uevent socket not available");
 	}

	if (init_udevd_socket() < 0) {
		if (errno == EADDRINUSE)
			dbg("another udevd running, exit");
		else
			dbg("error initialising udevd socket: %s", strerror(errno));

		goto exit;
	}

	/* override of forked udev binary, used for testing */
	udev_bin = getenv("UDEV_BIN");
	if (udev_bin != NULL)
		info("udev binary is set to '%s'", udev_bin);
	else
		udev_bin = UDEV_BIN;

	/* init of expected_seqnum value */
	value = getenv("UDEVD_EXPECTED_SEQNUM");
	if (value) {
		expected_seqnum = strtoull(value, NULL, 10);
		info("initialize expected_seqnum to %llu", expected_seqnum);
	}

	/* timeout to wait for missing events */
	value = getenv("UDEVD_EVENT_TIMEOUT");
	if (value)
		event_timeout = strtoul(value, NULL, 10);
	else
		event_timeout = UDEVD_EVENT_TIMEOUT;
	info("initialize event_timeout to %u", event_timeout);

	/* maximum limit of forked childs */
	value = getenv("UDEVD_MAX_CHILDS");
	if (value)
		max_childs = strtoul(value, NULL, 10);
	else
		max_childs = UDEVD_MAX_CHILDS;
	info("initialize max_childs to %u", max_childs);

	/* start to throttle forking if maximum number of _running_ childs is reached */
	value = getenv("UDEVD_MAX_CHILDS_RUNNING");
	if (value)
		max_childs_running = strtoull(value, NULL, 10);
	else
		max_childs_running = UDEVD_MAX_CHILDS_RUNNING;
	info("initialize max_childs_running to %u", max_childs_running);

	FD_ZERO(&readfds);
	FD_SET(udevd_sock, &readfds);
	if (uevent_netlink_sock != -1)
		FD_SET(uevent_netlink_sock, &readfds);
	FD_SET(pipefds[0], &readfds);
	maxsockplus = udevd_sock+1;
	while (1) {
		struct uevent_msg *msg;

		fd_set workreadfds = readfds;
		retval = select(maxsockplus, &workreadfds, NULL, NULL, NULL);

		if (retval < 0) {
			if (errno != EINTR)
				dbg("error in select: %s", strerror(errno));
			continue;
		}

		if (FD_ISSET(udevd_sock, &workreadfds)) {
			msg = get_udevd_msg();
			if (msg) {
				/* discard kernel messages if netlink is active */
				if (uevent_netlink_active && msg->type == UDEVD_UEVENT_UDEVSEND && msg->seqnum != 0) {
					dbg("skip uevent_helper message, netlink is active");
					free(msg);
					continue;
				}
				msg_queue_insert(msg);
			}
		}

		if (FD_ISSET(uevent_netlink_sock, &workreadfds)) {
			msg = get_netlink_msg();
			if (msg) {
				msg_queue_insert(msg);
				/* disable udevsend with first netlink message */
				if (!uevent_netlink_active) {
					info("uevent_nl message received, disable udevsend messages");
					uevent_netlink_active = 1;
				}
			}
		}

		if (FD_ISSET(pipefds[0], &workreadfds))
			user_sighandler();

		if (sigchilds_waiting) {
			sigchilds_waiting = 0;
			reap_sigchilds();
		}

		if (run_msg_q) {
			run_msg_q = 0;
			msg_queue_manager();
		}

		if (run_exec_q) {
			 /* clean up running_list before calling exec_queue_manager() */
			if (sigchilds_waiting) {
				sigchilds_waiting = 0;
				reap_sigchilds();
			}

			run_exec_q = 0;
			if (!stop_exec_q)
				exec_queue_manager();
		}
	}

exit:
	logging_close();
	return 1;
}
