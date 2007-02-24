/*
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include <getopt.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "udev.h"
#include "udev_rules.h"
#include "udevd.h"
#include "udev_selinux.h"

static int debug_trace;
static int verbose;

static struct udev_rules rules;
static int udevd_sock = -1;
static int uevent_netlink_sock = -1;
static int inotify_fd = -1;
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

	if (verbose) {
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		printf("\n");
	}
}

#endif

static void asmlinkage udev_event_sig_handler(int signum)
{
	if (signum == SIGALRM)
		exit(1);
}

static int udev_event_process(struct udevd_uevent_msg *msg)
{
	struct sigaction act;
	struct udevice *udev;
	int i;
	int retval;

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) udev_event_sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);

	/* reset to default */
	act.sa_handler = SIG_DFL;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_ALARM_TIMEOUT);

	/* reconstruct event environment from message */
	for (i = 0; msg->envp[i]; i++)
		putenv(msg->envp[i]);

	udev = udev_device_init();
	if (udev == NULL)
		return -1;
	strlcpy(udev->action, msg->action, sizeof(udev->action));
	sysfs_device_set_values(udev->dev, msg->devpath, msg->subsystem, msg->driver);
	udev->devt = msg->devt;

	retval = udev_device_event(&rules, udev);

	/* run programs collected by RUN-key*/
	if (retval == 0 && !udev->ignore_device && udev_run) {
		struct name_entry *name_loop;

		dbg("executing run list");
		list_for_each_entry(name_loop, &udev->run_list, node) {
			if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0)
				pass_env_to_socket(&name_loop->name[strlen("socket:")], udev->dev->devpath, udev->action);
			else {
				char program[PATH_SIZE];

				strlcpy(program, name_loop->name, sizeof(program));
				udev_rules_apply_format(udev, program, sizeof(program));
				if (run_program(program, udev->dev->subsystem, NULL, 0, NULL,
						(udev_log_priority >= LOG_INFO)))
					retval = -1;
			}
		}
	}

	udev_device_cleanup(udev);
	return retval;
}

enum event_state {
	EVENT_QUEUED,
	EVENT_FINISHED,
	EVENT_FAILED,
};

static void export_event_state(struct udevd_uevent_msg *msg, enum event_state state)
{
	char filename[PATH_SIZE];
	char filename_failed[PATH_SIZE];
	size_t start, end, i;
	struct udevd_uevent_msg *loop_msg;
	int fd;

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
		delete_path(filename_failed);
		create_path(filename);
		fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd > 0)
			close(fd);
		return;
	case EVENT_FINISHED:
	case EVENT_FAILED:
		unlink(filename_failed);
		delete_path(filename_failed);

		/* don't remove, if events for the same path are still pending */
		list_for_each_entry(loop_msg, &running_list, node)
			if (loop_msg->devpath && strcmp(loop_msg->devpath, msg->devpath) == 0)
				return;

		list_for_each_entry(loop_msg, &exec_list, node)
			if (loop_msg->devpath && strcmp(loop_msg->devpath, msg->devpath) == 0)
				return;

		/* move failed events to the failed directory */
		if (state == EVENT_FAILED) {
			create_path(filename_failed);
			rename(filename, filename_failed);
		} else {
			unlink(filename);
		}

		/* clean up the queue directory */
		delete_path(filename);

		return;
	}
}

static void msg_queue_delete(struct udevd_uevent_msg *msg)
{
	list_del(&msg->node);

	/* mark as failed, if add event returns non-zero */
	if (msg->exitstatus && strcmp(msg->action, "add") == 0)
		export_event_state(msg, EVENT_FAILED);
	else
		export_event_state(msg, EVENT_FINISHED);

	free(msg);
}

static void udev_event_run(struct udevd_uevent_msg *msg)
{
	pid_t pid;
	int retval;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		close(uevent_netlink_sock);
		close(udevd_sock);
		if (inotify_fd >= 0)
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

static void msg_queue_insert(struct udevd_uevent_msg *msg)
{
	char filename[PATH_SIZE];
	int fd;

	msg->queue_time = time(NULL);

	strlcpy(filename, udev_root, sizeof(filename));
	strlcat(filename, "/" EVENT_SEQNUM, sizeof(filename));
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		char str[32];
		int len;

		len = sprintf(str, "%llu\n", msg->seqnum);
		write(fd, str, len);
		close(fd);
	}

	export_event_state(msg, EVENT_QUEUED);

	/* run one event after the other in debug mode */
	if (debug_trace) {
		list_add_tail(&msg->node, &running_list);
		udev_event_run(msg);
		waitpid(msg->pid, NULL, 0);
		msg_queue_delete(msg);
		return;
	}

	/* run all events with a timeout set immediately */
	if (msg->timeout != 0) {
		list_add_tail(&msg->node, &running_list);
		udev_event_run(msg);
		return;
	}

	list_add_tail(&msg->node, &exec_list);
	run_exec_q = 1;
}

static int mem_size_mb(void)
{
	int f;
	char buf[8192];
	long int len;
	const char *pos;
	long int memsize;

	f = open("/proc/meminfo", O_RDONLY);
	if (f == -1)
		return -1;

	len = read(f, buf, sizeof(buf)-1);
	close(f);

	if (len <= 0)
		return -1;
	buf[len] = '\0';

	pos = strstr(buf, "MemTotal: ");
	if (pos == NULL)
		return -1;

	if (sscanf(pos, "MemTotal: %ld kB", &memsize) != 1)
		return -1;

	return memsize / 1024;
}

static int cpu_count(void)
{
	int f;
	char buf[32768];
	int len;
	const char *pos;
	int count = 0;

	f = open("/proc/stat", O_RDONLY);
	if (f == -1)
		return -1;

	len = read(f, buf, sizeof(buf)-1);
	close(f);
	if (len <= 0)
		return -1;
	buf[len] = '\0';

	pos = strstr(buf, "cpu");
	if (pos == NULL)
		return -1;

	while (pos != NULL) {
		if (strncmp(pos, "cpu", 3) == 0 &&isdigit(pos[3]))
			count++;
		pos = strstr(&pos[3], "cpu");
	}

	if (count == 0)
		return -1;
	return count;
}

static int running_processes(void)
{
	int f;
	char buf[32768];
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
static int running_with_devpath(struct udevd_uevent_msg *msg, int limit)
{
	struct udevd_uevent_msg *loop_msg;
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
	struct udevd_uevent_msg *loop_msg;
	struct udevd_uevent_msg *tmp_msg;
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

static struct udevd_uevent_msg *get_msg_from_envbuf(const char *buf, int buf_size)
{
	int bufpos;
	int i;
	struct udevd_uevent_msg *msg;
	char *physdevdriver_key = NULL;
	int maj = 0;
	int min = 0;

	msg = malloc(sizeof(struct udevd_uevent_msg) + buf_size);
	if (msg == NULL)
		return NULL;
	memset(msg, 0x00, sizeof(struct udevd_uevent_msg) + buf_size);

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
		else if (strncmp(key, "DRIVER=", 7) == 0)
			msg->driver = &key[7];
		else if (strncmp(key, "SEQNUM=", 7) == 0)
			msg->seqnum = strtoull(&key[7], NULL, 10);
		else if (strncmp(key, "PHYSDEVPATH=", 12) == 0)
			msg->physdevpath = &key[12];
		else if (strncmp(key, "PHYSDEVDRIVER=", 14) == 0)
			physdevdriver_key = key;
		else if (strncmp(key, "MAJOR=", 6) == 0)
			maj = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "MINOR=", 6) == 0)
			min = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "TIMEOUT=", 8) == 0)
			msg->timeout = strtoull(&key[8], NULL, 10);
	}
	msg->devt = makedev(maj, min);
	msg->envp[i++] = "UDEVD_EVENT=1";

	if (msg->driver == NULL && msg->physdevpath == NULL && physdevdriver_key != NULL) {
		/* for older kernels DRIVER is empty for a bus device, export PHYSDEVDRIVER as DRIVER */
		msg->envp[i++] = &physdevdriver_key[7];
		msg->driver = &physdevdriver_key[14];
	}

	msg->envp[i] = NULL;

	if (msg->devpath == NULL || msg->action == NULL) {
		info("DEVPATH or ACTION missing, ignore message");
		free(msg);
		return NULL;
	}
	return msg;
}

/* receive the udevd message from userspace */
static void get_ctrl_msg(void)
{
	struct udevd_ctrl_msg ctrl_msg;
	ssize_t size;
	struct msghdr smsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *cred;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	int *intval;

	memset(&ctrl_msg, 0x00, sizeof(struct udevd_ctrl_msg));
	iov.iov_base = &ctrl_msg;
	iov.iov_len = sizeof(struct udevd_ctrl_msg);

	memset(&smsg, 0x00, sizeof(struct msghdr));
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = sizeof(cred_msg);

	size = recvmsg(udevd_sock, &smsg, 0);
	if (size <  0) {
		if (errno != EINTR)
			err("unable to receive user udevd message: %s", strerror(errno));
		return;
	}
	cmsg = CMSG_FIRSTHDR(&smsg);
	cred = (struct ucred *) CMSG_DATA(cmsg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		err("no sender credentials received, message ignored");
		return;
	}

	if (cred->uid != 0) {
		err("sender uid=%i, message ignored", cred->uid);
		return;
	}

	if (strncmp(ctrl_msg.magic, UDEVD_CTRL_MAGIC, sizeof(UDEVD_CTRL_MAGIC)) != 0 ) {
		err("message magic '%s' doesn't match, ignore it", ctrl_msg.magic);
		return;
	}

	switch (ctrl_msg.type) {
	case UDEVD_CTRL_STOP_EXEC_QUEUE:
		info("udevd message (STOP_EXEC_QUEUE) received");
		stop_exec_q = 1;
		break;
	case UDEVD_CTRL_START_EXEC_QUEUE:
		info("udevd message (START_EXEC_QUEUE) received");
		stop_exec_q = 0;
		msg_queue_manager();
		break;
	case UDEVD_CTRL_SET_LOG_LEVEL:
		intval = (int *) ctrl_msg.buf;
		info("udevd message (SET_LOG_PRIORITY) received, udev_log_priority=%i", *intval);
		udev_log_priority = *intval;
		sprintf(udev_log, "UDEV_LOG=%i", udev_log_priority);
		putenv(udev_log);
		break;
	case UDEVD_CTRL_SET_MAX_CHILDS:
		intval = (int *) ctrl_msg.buf;
		info("udevd message (UDEVD_SET_MAX_CHILDS) received, max_childs=%i", *intval);
		max_childs = *intval;
		break;
	case UDEVD_CTRL_SET_MAX_CHILDS_RUNNING:
		intval = (int *) ctrl_msg.buf;
		info("udevd message (UDEVD_SET_MAX_CHILDS_RUNNING) received, max_childs=%i", *intval);
		max_childs_running = *intval;
		break;
	case UDEVD_CTRL_RELOAD_RULES:
		info("udevd message (RELOAD_RULES) received");
		reload_config = 1;
		break;
	default:
		err("unknown control message type");
	}
}

/* receive the kernel user event message and do some sanity checks */
static struct udevd_uevent_msg *get_netlink_msg(void)
{
	struct udevd_uevent_msg *msg;
	int bufpos;
	ssize_t size;
	static char buffer[UEVENT_BUFFER_SIZE+512];
	char *pos;

	size = recv(uevent_netlink_sock, &buffer, sizeof(buffer), 0);
	if (size <  0) {
		if (errno != EINTR)
			err("unable to receive kernel netlink message: %s", strerror(errno));
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
	struct udevd_uevent_msg *msg;

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
	socklen_t addrlen;
	const int feature_on = 1;
	int retval;

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_CTRL_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	udevd_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (udevd_sock == -1) {
		err("error getting socket: %s", strerror(errno));
		return -1;
	}

	/* the bind takes care of ensuring only one copy running */
	retval = bind(udevd_sock, (struct sockaddr *) &saddr, addrlen);
	if (retval < 0) {
		err("bind failed: %s", strerror(errno));
		close(udevd_sock);
		udevd_sock = -1;
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
	snl.nl_groups = 1;

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

static void export_initial_seqnum(void)
{
	char filename[PATH_SIZE];
	int fd;
	char seqnum[32];
	ssize_t len = 0;

	strlcpy(filename, sysfs_path, sizeof(filename));
	strlcat(filename, "/kernel/uevent_seqnum", sizeof(filename));
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
	}
	if (len <= 0) {
		strcpy(seqnum, "0\n");
		len = 3;
	}
	strlcpy(filename, udev_root, sizeof(filename));
	strlcat(filename, "/" EVENT_SEQNUM, sizeof(filename));
	create_path(filename);
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		write(fd, seqnum, len);
		close(fd);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	int retval;
	int fd;
	struct sigaction act;
	fd_set readfds;
	const char *value;
	int daemonize = 0;
	int option;
	static const struct option options[] = {
		{ "daemon", 0, NULL, 'd' },
		{ "debug-trace", 0, NULL, 't' },
		{ "verbose", 0, NULL, 'v' },
		{ "help", 0, NULL, 'h' },
		{ "version", 0, NULL, 'V' },
		{}
	};
	int rc = 1;
	int maxfd;

	logging_init("udevd");
	udev_config_init();
	selinux_init();
	dbg("version %s", UDEV_VERSION);

	/* parse commandline options */
	while (1) {
		option = getopt_long(argc, argv, "dtvhV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			daemonize = 1;
			break;
		case 't':
			debug_trace = 1;
			break;
		case 'v':
			verbose = 1;
			if (udev_log_priority < LOG_INFO)
				udev_log_priority = LOG_INFO;
			break;
		case 'h':
			printf("Usage: udevd [--help] [--daemon] [--debug-trace] [--verbose] [--version]\n");
			goto exit;
		case 'V':
			printf("%s\n", UDEV_VERSION);
			goto exit;
		default:
			goto exit;
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		err("root privileges required");
		goto exit;
	}

	/* init sockets to receive events */
	if (init_udevd_socket() < 0) {
		if (errno == EADDRINUSE) {
			fprintf(stderr, "another udev daemon already running\n");
			err("another udev daemon already running");
			rc = 1;
		} else {
			fprintf(stderr, "error initializing udevd socket\n");
			err("error initializing udevd socket");
			rc = 2;
		}
		goto exit;
	}

	if (init_uevent_netlink_sock() < 0) {
		fprintf(stderr, "error initializing netlink socket\n");
		err("error initializing netlink socket");
		rc = 3;
		goto exit;
	}

	/* setup signal handler pipe */
	retval = pipe(signal_pipe);
	if (retval < 0) {
		err("error getting pipes: %s", strerror(errno));
		goto exit;
	}

	retval = fcntl(signal_pipe[READ_END], F_GETFL, 0);
	if (retval < 0) {
		err("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[READ_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}

	retval = fcntl(signal_pipe[WRITE_END], F_GETFL, 0);
	if (retval < 0) {
		err("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(signal_pipe[WRITE_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		err("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}

	/* parse the rules and keep them in memory */
	sysfs_init();
	udev_rules_init(&rules, 1);

	export_initial_seqnum();

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
			rc = 0;
			goto exit;
		}
	}

	/* redirect std fd's */
	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, STDIN_FILENO);
		if (!verbose)
			dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	} else
		err("error opening /dev/null: %s", strerror(errno));

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
	if (inotify_fd >= 0)
		inotify_add_watch(inotify_fd, udev_rules_dir, IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	else if (errno == ENOSYS)
		err("the kernel does not support inotify, udevd can't monitor configuration file changes");
	else
		err("inotify_init failed: %s", strerror(errno));

	/* maximum limit of forked childs */
	value = getenv("UDEVD_MAX_CHILDS");
	if (value)
		max_childs = strtoul(value, NULL, 10);
	else {
		int memsize = mem_size_mb();
		if (memsize > 0)
			max_childs = 128 + (memsize / 4);
		else
			max_childs = UDEVD_MAX_CHILDS;
	}
	info("initialize max_childs to %u", max_childs);

	/* start to throttle forking if maximum number of _running_ childs is reached */
	value = getenv("UDEVD_MAX_CHILDS_RUNNING");
	if (value)
		max_childs_running = strtoull(value, NULL, 10);
	else {
		int cpus = cpu_count();
		if (cpus > 0)
			max_childs_running = 8 + (8 * cpus);
		else
			max_childs_running = UDEVD_MAX_CHILDS_RUNNING;
	}
	info("initialize max_childs_running to %u", max_childs_running);

	/* clear environment for forked event processes */
	clearenv();

	/* export log_priority , as called programs may want to follow that setting */
	sprintf(udev_log, "UDEV_LOG=%i", udev_log_priority);
	putenv(udev_log);
	if (debug_trace)
		putenv("DEBUG=1");

	maxfd = udevd_sock;
	maxfd = UDEV_MAX(maxfd, uevent_netlink_sock);
	maxfd = UDEV_MAX(maxfd, signal_pipe[READ_END]);
	maxfd = UDEV_MAX(maxfd, inotify_fd);

	while (!udev_exit) {
		struct udevd_uevent_msg *msg;
		int fdcount;

		FD_ZERO(&readfds);
		FD_SET(signal_pipe[READ_END], &readfds);
		FD_SET(udevd_sock, &readfds);
		FD_SET(uevent_netlink_sock, &readfds);
		if (inotify_fd >= 0)
			FD_SET(inotify_fd, &readfds);

		fdcount = select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (fdcount < 0) {
			if (errno != EINTR)
				err("error in select: %s", strerror(errno));
			continue;
		}

		/* get control message */
		if (FD_ISSET(udevd_sock, &readfds))
			get_ctrl_msg();

		/* get netlink message */
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
		if ((inotify_fd >= 0) && FD_ISSET(inotify_fd, &readfds)) {
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

		/* rules changed, set by inotify or a HUP signal */
		if (reload_config) {
			reload_config = 0;
			udev_rules_cleanup(&rules);
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
	rc = 0;

exit:
	udev_rules_cleanup(&rules);
	sysfs_cleanup();

	if (signal_pipe[READ_END] >= 0)
		close(signal_pipe[READ_END]);
	if (signal_pipe[WRITE_END] >= 0)
		close(signal_pipe[WRITE_END]);

	if (udevd_sock >= 0)
		close(udevd_sock);
	if (inotify_fd >= 0)
		close(inotify_fd);
	if (uevent_netlink_sock >= 0)
		close(uevent_netlink_sock);

	logging_close();

	return rc;
}
