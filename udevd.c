/*
 * udevd.c - event listener and serializer
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
#include <syslog.h>
#include <time.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "list.h"
#include "udev_libc_wrapper.h"
#include "udev.h"
#include "udev_version.h"
#include "udev_rules.h"
#include "udev_utils.h"
#include "udevd.h"
#include "logging.h"

struct udev_rules rules;
static int udevd_sock;
static int uevent_netlink_sock;
static int inotify_fd;
static pid_t sid;

static int signal_pipe[2] = {-1, -1};
static volatile int sigchilds_waiting;
static volatile int udev_exit;
static volatile int reload_config;
static int run_exec_q;
static int stop_exec_q;
static int max_childs;
static int max_childs_running;
static char udev_log[32];

static LIST_HEAD(exec_list);
static LIST_HEAD(running_list);


#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void asmlinkage udev_event_sig_handler(int signum)
{
	if (signum == SIGALRM)
		exit(1);
}

static int udev_event_process(struct uevent_msg *msg)
{
	struct sigaction act;
	struct udevice udev;
	struct name_entry *name_loop;
	int i;
	int retval;

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) udev_event_sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_ALARM_TIMEOUT);

	/* reconstruct env from message */
	for (i = 0; msg->envp[i]; i++)
		putenv(msg->envp[i]);

	udev_init_device(&udev, msg->devpath, msg->subsystem, msg->action);
	retval = udev_process_event(&rules, &udev);

	/* run programs collected by RUN-key*/
	if (!retval) {
		list_for_each_entry(name_loop, &udev.run_list, node) {
			if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0)
				pass_env_to_socket(&name_loop->name[strlen("socket:")], msg->devpath, msg->action);
			else
				if (run_program(name_loop->name, udev.subsystem, NULL, 0, NULL,
						(udev_log_priority >= LOG_INFO)))
					retval = -1;
		}
	}

	udev_cleanup_device(&udev);

	return retval;
}

enum event_state {
	EVENT_QUEUED,
	EVENT_FINISHED,
	EVENT_FAILED,
};

static void export_event_state(struct uevent_msg *msg, enum event_state state)
{
	char filename[PATH_SIZE];
	char filename_failed[PATH_SIZE];
	char target[PATH_SIZE];
	size_t start, end, i;
	struct uevent_msg *loop_msg;

	/* add location of queue files */
	strlcpy(filename, udev_root, sizeof(filename));
	strlcat(filename, "/", sizeof(filename));
	start = strlcat(filename, EVENT_QUEUE_DIR, sizeof(filename));
	end = strlcat(filename, msg->devpath, sizeof(filename));
	if (end > sizeof(filename))
		end = sizeof(filename);

	/* replace '/' to transform path into a filename */
	for (i = start+1; i < end; i++)
		if (filename[i] == '/')
			filename[i] = PATH_TO_NAME_CHAR;

	/* add location of failed files */
	strlcpy(filename_failed, udev_root, sizeof(filename_failed));
	strlcat(filename_failed, "/", sizeof(filename_failed));
	start = strlcat(filename_failed, EVENT_FAILED_DIR, sizeof(filename_failed));
	end = strlcat(filename_failed, msg->devpath, sizeof(filename_failed));
	if (end > sizeof(filename_failed))
		end = sizeof(filename_failed);

	/* replace '/' to transform path into a filename */
	for (i = start+1; i < end; i++)
		if (filename_failed[i] == '/')
			filename_failed[i] = PATH_TO_NAME_CHAR;

	switch (state) {
	case EVENT_QUEUED:
		unlink(filename_failed);

		strlcpy(target, sysfs_path, sizeof(target));
		strlcat(target, msg->devpath, sizeof(target));
		create_path(filename);
		symlink(target, filename);
		return;
	case EVENT_FINISHED:
		unlink(filename_failed);

		/* don't remove if events for the same path are still pending */
		list_for_each_entry(loop_msg, &running_list, node)
			if (loop_msg->devpath && strcmp(loop_msg->devpath, msg->devpath) == 0)
				return;
		unlink(filename);
		return;
	case EVENT_FAILED:
		create_path(filename_failed);
		rename(filename, filename_failed);
		return;
	}
}

static void msg_queue_delete(struct uevent_msg *msg)
{
	list_del(&msg->node);

	/* mark as failed, if add event returns non-zero */
	if (msg->exitstatus && strcmp(msg->action, "add") == 0)
		export_event_state(msg, EVENT_FAILED);
	else
		export_event_state(msg, EVENT_FINISHED);

	free(msg);
}

static void udev_event_run(struct uevent_msg *msg)
{
	pid_t pid;
	int retval;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		close(uevent_netlink_sock);
		close(udevd_sock);
		if (inotify_fd > 0)
			close(inotify_fd);
		close(signal_pipe[READ_END]);
		close(signal_pipe[WRITE_END]);
		logging_close();

		logging_init("udevd-event");
		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);
		retval = udev_event_process(msg);
		info("seq %llu finished", msg->seqnum);

		logging_close();
		if (retval)
			exit(1);
		exit(0);
	case -1:
		err("fork of child failed: %s", strerror(errno));
		msg_queue_delete(msg);
		break;
	default:
		/* get SIGCHLD in main loop */
		info("seq %llu forked, pid [%d], '%s' '%s', %ld seconds old",
		     msg->seqnum, pid,  msg->action, msg->subsystem, time(NULL) - msg->queue_time);
		msg->pid = pid;
	}
}

static void msg_queue_insert(struct uevent_msg *msg)
{
	msg->queue_time = time(NULL);

	export_event_state(msg, EVENT_QUEUED);

	/* run all events with a timeout set immediately */
	if (msg->timeout != 0) {
		list_add_tail(&msg->node, &running_list);
		udev_event_run(msg);
		return;
	}

	list_add_tail(&msg->node, &exec_list);
	run_exec_q = 1;
}

/* runs event and removes event from run queue when finished */
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

	len = read(f, buf, sizeof(buf)-1);
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

		len = read(f, line, sizeof(line)-1);
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

	list_for_each_entry(loop_msg, &running_list, node) {
		if (limit && childs_count++ > limit) {
			dbg("%llu, maximum number (%i) of child reached", msg->seqnum, childs_count);
			return 1;
		}

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
static void msg_queue_manager(void)
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
				dbg("delay seq %llu, too many processes already running", loop_msg->seqnum);
				return;
			}
		}

		/* don't run two processes for the same devpath and wait for the parent*/
		if (running_with_devpath(loop_msg, max_childs)) {
			dbg("delay seq %llu (%s)", loop_msg->seqnum, loop_msg->devpath);
			continue;
		}

		/* move event to run list */
		list_move_tail(&loop_msg->node, &running_list);
		udev_event_run(loop_msg);
		running++;
		dbg("moved seq %llu to running list", loop_msg->seqnum);
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

	if (!msg->devpath) {
		info("DEVPATH missing, ignore message");
		free(msg);
		return NULL;
	}

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
			err("unable to receive udevd message: %s", strerror(errno));
		return NULL;
	}
	cmsg = CMSG_FIRSTHDR(&smsg);
	cred = (struct ucred *) CMSG_DATA(cmsg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		err("no sender credentials received, message ignored");
		return NULL;
	}

	if (cred->uid != 0) {
		err("sender uid=%i, message ignored", cred->uid);
		return NULL;
	}

	if (strncmp(usend_msg.magic, UDEV_MAGIC, sizeof(UDEV_MAGIC)) != 0 ) {
		err("message magic '%s' doesn't match, ignore it", usend_msg.magic);
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
		msg_queue_manager();
		break;
	case UDEVD_SET_LOG_LEVEL:
		intval = (int *) usend_msg.envbuf;
		info("udevd message (SET_LOG_PRIORITY) received, udev_log_priority=%i", *intval);
		udev_log_priority = *intval;
		sprintf(udev_log, "UDEV_LOG=%i", udev_log_priority);
		putenv(udev_log);
		break;
	case UDEVD_SET_MAX_CHILDS:
		intval = (int *) usend_msg.envbuf;
		info("udevd message (UDEVD_SET_MAX_CHILDS) received, max_childs=%i", *intval);
		max_childs = *intval;
		break;
	case UDEVD_RELOAD_RULES:
		info("udevd message (RELOAD_RULES) received");
		reload_config = 1;
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
			err("unable to receive udevd message: %s", strerror(errno));
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
		err("invalid uevent '%s'", buffer);
		free(msg);
		return NULL;
	}
	pos[0] = '\0';

	if (msg->action == NULL) {
		info("no ACTION in payload found, skip event '%s'", buffer);
		free(msg);
		return NULL;
	}

	if (strcmp(msg->action, buffer) != 0) {
		err("ACTION in payload does not match uevent, skip event '%s'", buffer);
		free(msg);
		return NULL;
	}

	return msg;
}

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			udev_exit = 1;
			break;
		case SIGCHLD:
			/* set flag, then write to pipe if needed */
			sigchilds_waiting = 1;
			break;
		case SIGHUP:
			reload_config = 1;
			break;
	}

	/* write to pipe, which will wakeup select() in our mainloop */
	write(signal_pipe[WRITE_END], "", 1);
}

static void udev_done(int pid, int exitstatus)
{
	/* find msg associated with pid and delete it */
	struct uevent_msg *msg;

	list_for_each_entry(msg, &running_list, node) {
		if (msg->pid == pid) {
			info("seq %llu, pid [%d] exit with %i, %ld seconds old", msg->seqnum, msg->pid,
			     exitstatus, time(NULL) - msg->queue_time);
			msg->exitstatus = exitstatus;
			msg_queue_delete(msg);

			/* there may be events waiting with the same devpath */
			run_exec_q = 1;
			return;
		}
	}
}

static void reap_sigchilds(void)
{
	pid_t pid;
	int status;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			break;
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			status = WTERMSIG(status) + 128;
		else
			status = 0;
		udev_done(pid, status);
	}
}

static int init_udevd_socket(void)
{
	struct sockaddr_un saddr;
	const int buffersize = 16 * 1024 * 1024;
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
		err("error getting socket: %s", strerror(errno));
		return -1;
	}

	/* set receive buffersize */
	setsockopt(udevd_sock, SOL_SOCKET, SO_RCVBUFFORCE, &buffersize, sizeof(buffersize));

	/* the bind takes care of ensuring only one copy running */
	retval = bind(udevd_sock, (struct sockaddr *) &saddr, addrlen);
	if (retval < 0) {
		err("bind failed: %s", strerror(errno));
		return -1;
	}

	/* enable receiving of the sender credentials */
	setsockopt(udevd_sock, SOL_SOCKET, SO_PASSCRED, &feature_on, sizeof(feature_on));

	return 0;
}

static int init_uevent_netlink_sock(void)
{
	struct sockaddr_nl snl;
	const int buffersize = 16 * 1024 * 1024;
	int retval;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 0xffffffff;

	uevent_netlink_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_netlink_sock == -1) {
		err("error getting socket: %s", strerror(errno));
		return -1;
	}

	/* set receive buffersize */
	setsockopt(uevent_netlink_sock, SOL_SOCKET, SO_RCVBUFFORCE, &buffersize, sizeof(buffersize));

	retval = bind(uevent_netlink_sock, (struct sockaddr *) &snl, sizeof(struct sockaddr_nl));
	if (retval < 0) {
		err("bind failed: %s", strerror(errno));
		close(uevent_netlink_sock);
		uevent_netlink_sock = -1;
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	int retval;
	int fd;
	struct sigaction act;
	fd_set readfds;
	const char *value;
	int daemonize = 0;
	int i;
	int rc = 0;
	int maxfd;

	/* redirect std fd's, if the kernel forks us, we don't have them at all */
	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		if (fd != STDIN_FILENO)
			dup2(fd, STDIN_FILENO);
		if (fd != STDOUT_FILENO)
			dup2(fd, STDOUT_FILENO);
		if (fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}

	logging_init("udevd");
	if (fd < 0)
		err("fatal, could not open /dev/null: %s", strerror(errno));

	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	if (getuid() != 0) {
		err("need to be root, exit");
		goto exit;
	}

	/* parse commandline options */
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

	/* init sockets to receive events */
	if (init_udevd_socket() < 0) {
		if (errno == EADDRINUSE) {
			err("another udevd running, exit");
			rc = 1;
		} else {
			err("error initializing udevd socket: %s", strerror(errno));
			rc = 2;
		}
		goto exit;
	}

	if (init_uevent_netlink_sock() < 0) {
		err("uevent socket not available");
		rc = 3;
		goto exit;
	}

	/* parse the rules and keep it in memory */
	udev_rules_init(&rules, 1);

	if (daemonize) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			dbg("daemonized fork running");
			break;
		case -1:
			err("fork of daemon failed: %s", strerror(errno));
			rc = 4;
			goto exit;
		default:
			dbg("child [%u] running, parent exits", pid);
			goto exit;
		}
	}

	/* set scheduling priority for the daemon */
	setpriority(PRIO_PROCESS, 0, UDEVD_PRIORITY);

	chdir("/");
	umask(022);

	/* become session leader */
	sid = setsid();
	dbg("our session is %d", sid);

	/* OOM_DISABLE == -17 */
	fd = open("/proc/self/oom_adj", O_RDWR);
	if (fd < 0)
		err("error disabling OOM: %s", strerror(errno));
	else {
		write(fd, "-17", 3);
		close(fd);
	}

	/* setup signal handler pipe */
	retval = pipe(signal_pipe);
	if (retval < 0) {
		err("error getting pipes: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[READ_END], F_SETFL, O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[WRITE_END], F_SETFL, O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	/* watch rules directory */
	inotify_fd = inotify_init();
	if (inotify_fd > 0)
		inotify_add_watch(inotify_fd, udev_rules_filename, IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

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

	/* clear environment for forked event processes */
	clearenv();

	/* export log_priority , as called programs may want to follow that setting */
	sprintf(udev_log, "UDEV_LOG=%i", udev_log_priority);
	putenv(udev_log);

	maxfd = udevd_sock;
	maxfd = UDEV_MAX(maxfd, uevent_netlink_sock);
	maxfd = UDEV_MAX(maxfd, signal_pipe[READ_END]);
	maxfd = UDEV_MAX(maxfd, inotify_fd);

	while (!udev_exit) {
		struct uevent_msg *msg;
		int fdcount;

		FD_ZERO(&readfds);
		FD_SET(signal_pipe[READ_END], &readfds);
		FD_SET(udevd_sock, &readfds);
		FD_SET(uevent_netlink_sock, &readfds);
		if (inotify_fd > 0)
			FD_SET(inotify_fd, &readfds);

		fdcount = select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (fdcount < 0) {
			if (errno != EINTR)
				err("error in select: %s", strerror(errno));
			continue;
		}

		/* get user socket message */
		if (FD_ISSET(udevd_sock, &readfds)) {
			msg = get_udevd_msg();
			if (msg) {
				if (msg->type == UDEVD_UEVENT_UDEVSEND && msg->seqnum != 0) {
					info("skip non-kernel message with SEQNUM");
					free(msg);
				} else
					msg_queue_insert(msg);
			}
		}

		/* get kernel netlink message */
		if (FD_ISSET(uevent_netlink_sock, &readfds)) {
			msg = get_netlink_msg();
			if (msg)
				msg_queue_insert(msg);
		}

		/* received a signal, clear our notification pipe */
		if (FD_ISSET(signal_pipe[READ_END], &readfds)) {
			char buf[256];

			read(signal_pipe[READ_END], &buf, sizeof(buf));
		}

		/* rules directory inotify watch */
		if ((inotify_fd > 0) && FD_ISSET(inotify_fd, &readfds)) {
			int nbytes;

			/* discard all possible events, we can just reload the config */
			if ((ioctl(inotify_fd, FIONREAD, &nbytes) == 0) && nbytes) {
				char *buf;

				reload_config = 1;
				buf = malloc(nbytes);
				if (!buf) {
					err("error getting buffer for inotify, disable watching");
					close(inotify_fd);
					inotify_fd = -1;
				}
				read(inotify_fd, buf, nbytes);
				free(buf);
			}
		}

		/* rules changed, set by inotify or a signal*/
		if (reload_config) {
			reload_config = 0;
			udev_rules_close(&rules);
			udev_rules_init(&rules, 1);
		}

		/* forked child has returned */
		if (sigchilds_waiting) {
			sigchilds_waiting = 0;
			reap_sigchilds();
		}

		if (run_exec_q) {
			run_exec_q = 0;
			if (!stop_exec_q)
				msg_queue_manager();
		}
	}

exit:
	udev_rules_close(&rules);

	if (signal_pipe[READ_END] > 0)
		close(signal_pipe[READ_END]);
	if (signal_pipe[WRITE_END] > 0)
		close(signal_pipe[WRITE_END]);

	if (udevd_sock > 0)
		close(udevd_sock);
	if (inotify_fd > 0)
		close(inotify_fd);
	if (uevent_netlink_sock > 0)
		close(uevent_netlink_sock);

	logging_close();

	return rc;
}
