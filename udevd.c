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

#include "list.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_version.h"
#include "udev_utils.h"
#include "udevd.h"
#include "logging.h"

/* global variables*/
static int udevsendsock;
static pid_t sid;

static int pipefds[2];
static long startup_time;
static unsigned long long expected_seqnum = 0;
static volatile int sigchilds_waiting;
static volatile int run_msg_q;
static volatile int sig_flag;
static int run_exec_q;

static LIST_HEAD(msg_list);
static LIST_HEAD(exec_list);
static LIST_HEAD(running_list);

static void exec_queue_manager(void);
static void msg_queue_manager(void);
static void user_sighandler(void);
static void reap_sigchilds(void);
char *udev_bin;

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
	struct hotplug_msg *msg;

	list_for_each_entry(msg, &msg_list, node)
		dbg("sequence %llu in queue", msg->seqnum);
#endif
}

static void run_queue_delete(struct hotplug_msg *msg)
{
	list_del(&msg->node);
	free(msg);
}

/* orders the message in the queue by sequence number */
static void msg_queue_insert(struct hotplug_msg *msg)
{
	struct hotplug_msg *loop_msg;
	struct sysinfo info;

	if (msg->seqnum == 0) {
		dbg("no SEQNUM, move straight to the exec queue");
		list_add(&msg->node, &exec_list);
		run_exec_q = 1;
		return;
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
			info("ignoring duplicate message seq %llu", msg->seqnum);
			return;
		}
	}

	/* store timestamp of queuing */
	sysinfo(&info);
	msg->queue_time = info.uptime;

	list_add(&msg->node, &loop_msg->node);
	dbg("queued message seq %llu", msg->seqnum);

	/* run msg queue manager */
	run_msg_q = 1;

	return;
}

/* forks event and removes event from run queue when finished */
static void execute_udev(struct hotplug_msg *msg)
{
	char *const argv[] = { "udev", msg->subsystem, NULL };
	pid_t pid;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		close(udevsendsock);
		logging_close();

		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);
		execve(udev_bin, argv, msg->envp);
		err("exec of child failed");
		_exit(1);
		break;
	case -1:
		err("fork of child failed");
		run_queue_delete(msg);
		break;
	default:
		/* get SIGCHLD in main loop */
		dbg("==> exec seq %llu [%d] working at '%s'", msg->seqnum, pid, msg->devpath);
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
static struct hotplug_msg *running_with_devpath(struct hotplug_msg *msg)
{
	struct hotplug_msg *loop_msg;

	if (msg->devpath == NULL)
		return NULL;

	/* skip any events with a timeout set */
	if (msg->timeout)
		return NULL;

	list_for_each_entry(loop_msg, &running_list, node) {
		if (loop_msg->devpath == NULL)
			continue;

		/* return running parent/child device event */
		if (compare_devpath(loop_msg->devpath, msg->devpath) != 0)
			return loop_msg;

		/* return running physical device event */
		if (msg->physdevpath && msg->action && strcmp(msg->action, "add") == 0)
			if (compare_devpath(loop_msg->devpath, msg->physdevpath) != 0)
				return loop_msg;
	}

	return NULL;
}

/* exec queue management routine executes the events and serializes events in the same sequence */
static void exec_queue_manager(void)
{
	struct hotplug_msg *loop_msg;
	struct hotplug_msg *tmp_msg;
	struct hotplug_msg *msg;
	int running;

	running = running_processes();
	dbg("%d processes runnning on system", running);
	if (running < 0)
		running = THROTTLE_MAX_RUNNING_CHILDS;

	list_for_each_entry_safe(loop_msg, tmp_msg, &exec_list, node) {
		/* check running processes in our session and possibly throttle */
		if (running >= THROTTLE_MAX_RUNNING_CHILDS) {
			running = running_processes_in_session(sid, THROTTLE_MAX_RUNNING_CHILDS+10);
			dbg("%d processes running in session", running);
			if (running >= THROTTLE_MAX_RUNNING_CHILDS) {
				dbg("delay seq %llu, cause too many processes already running", loop_msg->seqnum);
				return;
			}
		}

		msg = running_with_devpath(loop_msg);
		if (!msg) {
			/* move event to run list */
			list_move_tail(&loop_msg->node, &running_list);
			execute_udev(loop_msg);
			running++;
			dbg("moved seq %llu to running list", loop_msg->seqnum);
		} else {
			dbg("delay seq %llu (%s), cause seq %llu (%s) is still running",
			    loop_msg->seqnum, loop_msg->devpath, msg->seqnum, msg->devpath);
		}
	}
}

static void msg_move_exec(struct hotplug_msg *msg)
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
	struct hotplug_msg *loop_msg;
	struct hotplug_msg *tmp_msg;
	struct sysinfo info;
	long msg_age = 0;
	static int timeout = EVENT_INIT_TIMEOUT_SEC;
	static int init = 1;

	dbg("msg queue manager, next expected is %llu", expected_seqnum);
recheck:
	list_for_each_entry_safe(loop_msg, tmp_msg, &msg_list, node) {
		/* move event with expected sequence to the exec list */
		if (loop_msg->seqnum == expected_seqnum) {
			msg_move_exec(loop_msg);
			continue;
		}

		/* see if we are in the initialization phase and wait for the very first events */
		if (init && (info.uptime - startup_time >= INIT_TIME_SEC)) {
			init = 0;
			timeout = EVENT_TIMEOUT_SEC;
			dbg("initialization phase passed, set timeout to %i seconds", EVENT_TIMEOUT_SEC);
		}

		/* move event with expired timeout to the exec list */
		sysinfo(&info);
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

/* receive the udevsend message and do some sanity checks */
static struct hotplug_msg *get_udevsend_msg(void)
{
	static struct udevsend_msg usend_msg;
	struct hotplug_msg *msg;
	int bufpos;
	int i;
	ssize_t size;
	struct msghdr smsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *cred;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	int envbuf_size;

	memset(&usend_msg, 0x00, sizeof(struct udevsend_msg));
	iov.iov_base = &usend_msg;
	iov.iov_len = sizeof(struct udevsend_msg);

	memset(&smsg, 0x00, sizeof(struct msghdr));
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = sizeof(cred_msg);

	size = recvmsg(udevsendsock, &smsg, 0);
	if (size <  0) {
		if (errno != EINTR)
			dbg("unable to receive udevsend message");
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

	envbuf_size = size - offsetof(struct udevsend_msg, envbuf);
	dbg("envbuf_size=%i", envbuf_size);
	msg = malloc(sizeof(struct hotplug_msg) + envbuf_size);
	if (msg == NULL)
		return NULL;

	memset(msg, 0x00, sizeof(struct hotplug_msg) + envbuf_size);

	/* copy environment buffer and reconstruct envp */
	memcpy(msg->envbuf, usend_msg.envbuf, envbuf_size);
	bufpos = 0;
	for (i = 0; (bufpos < envbuf_size) && (i < HOTPLUG_NUM_ENVP-2); i++) {
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

		if (strncmp(key, "DEVPATH=", 8) == 0)
			msg->devpath = &key[8];

		if (strncmp(key, "SUBSYSTEM=", 10) == 0)
			msg->subsystem = &key[10];

		if (strncmp(key, "SEQNUM=", 7) == 0)
			msg->seqnum = strtoull(&key[7], NULL, 10);

		if (strncmp(key, "PHYSDEVPATH=", 12) == 0)
			msg->physdevpath = &key[12];

		if (strncmp(key, "TIMEOUT=", 8) == 0)
			msg->timeout = strtoull(&key[8], NULL, 10);
	}
	msg->envp[i++] = "UDEVD_EVENT=1";
	msg->envp[i] = NULL;

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
	struct hotplug_msg *msg;

	list_for_each_entry(msg, &running_list, node) {
		if (msg->pid == pid) {
			dbg("<== exec seq %llu came back", msg->seqnum);
			run_queue_delete(msg);

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

static int init_udevsend_socket(void)
{
	struct sockaddr_un saddr;
	socklen_t addrlen;
	const int feature_on = 1;
	int retval;

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	udevsendsock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (udevsendsock == -1) {
		err("error getting socket, %s", strerror(errno));
		return -1;
	}

	/* the bind takes care of ensuring only one copy running */
	retval = bind(udevsendsock, (struct sockaddr *) &saddr, addrlen);
	if (retval < 0) {
		err("bind failed, %s", strerror(errno));
		close(udevsendsock);
		return -1;
	}

	/* enable receiving of the sender credentials */
	setsockopt(udevsendsock, SOL_SOCKET, SO_PASSCRED, &feature_on, sizeof(feature_on));

	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	struct sysinfo info;
	int maxsockplus;
	int retval;
	int fd;
	struct sigaction act;
	fd_set readfds;
	const char *udevd_expected_seqnum;

	logging_init("udevd");
	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	if (getuid() != 0) {
		err("need to be root, exit");
		goto exit;
	}

	/* daemonize on request */
	if (argc == 2 && strcmp(argv[1], "-d") == 0) {
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

	/* make sure we don't lock any path */
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

	if (init_udevsend_socket() < 0) {
		if (errno == EADDRINUSE)
			dbg("another udevd running, exit");
		else
			dbg("error initialising udevsend socket: %s", strerror(errno));

		goto exit;
	}

	/* possible override of udev binary, used for testing */
	udev_bin = getenv("UDEV_BIN");
	if (udev_bin != NULL)
		info("udev binary is set to '%s'", udev_bin);
	else
		udev_bin = UDEV_BIN;

	/* possible init of expected_seqnum value */
	udevd_expected_seqnum = getenv("UDEVD_EXPECTED_SEQNUM");
	if (udevd_expected_seqnum != NULL) {
		expected_seqnum = strtoull(udevd_expected_seqnum, NULL, 10);
		info("initialize expected_seqnum to %llu", expected_seqnum);
	}

	/* get current time to provide shorter timeout on startup */
	sysinfo(&info);
	startup_time = info.uptime;

	FD_ZERO(&readfds);
	FD_SET(udevsendsock, &readfds);
	FD_SET(pipefds[0], &readfds);
	maxsockplus = udevsendsock+1;
	while (1) {
		struct hotplug_msg *msg;

		fd_set workreadfds = readfds;
		retval = select(maxsockplus, &workreadfds, NULL, NULL, NULL);

		if (retval < 0) {
			if (errno != EINTR)
				dbg("error in select: %s", strerror(errno));
			continue;
		}

		if (FD_ISSET(udevsendsock, &workreadfds)) {
			msg = get_udevsend_msg();
			if (msg)
				msg_queue_insert(msg);
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
			exec_queue_manager();
		}
	}

exit:
	logging_close();
	return 1;
}
