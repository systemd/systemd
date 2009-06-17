/*
 * Copyright (C) 2004-2009 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Chris Friesen <chris_friesen@sympatico.ca>
 * Copyright (C) 2009 Canonical Ltd.
 * Copyright (C) 2009 Scott James Remnant <scott@netsplit.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>

#include "udev.h"

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

static int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "[%d] %s: ", (int) getpid(), fn);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

static int debug_trace;
static struct udev_rules *rules;
static struct udev_queue_export *udev_queue_export;
static struct udev_ctrl *udev_ctrl;
static struct udev_monitor *monitor;
static int worker_watch[2];
static pid_t settle_pid;
static int stop_exec_queue;
static int reload_config;
static int max_childs;
static int childs;
static struct udev_list_node event_list;
static struct udev_list_node worker_list;
static int udev_exit;
static volatile sig_atomic_t worker_exit;

enum poll_fd {
	FD_CONTROL,
	FD_NETLINK,
	FD_INOTIFY,
	FD_SIGNAL,
	FD_WORKER,
};

static struct pollfd pfd[] = {
	[FD_NETLINK] = { .events = POLLIN },
	[FD_WORKER] =  { .events = POLLIN },
	[FD_SIGNAL] =  { .events = POLLIN },
	[FD_INOTIFY] = { .events = POLLIN },
	[FD_CONTROL] = { .events = POLLIN },
};

enum event_state {
	EVENT_UNDEF,
	EVENT_QUEUED,
	EVENT_RUNNING,
};

struct event {
	struct udev_list_node node;
	struct udev *udev;
	struct udev_device *dev;
	enum event_state state;
	int exitcode;
	unsigned long long int delaying_seqnum;
	unsigned long long int seqnum;
	const char *devpath;
	size_t devpath_len;
	const char *devpath_old;
};

static struct event *node_to_event(struct udev_list_node *node)
{
	char *event;

	event = (char *)node;
	event -= offsetof(struct event, node);
	return (struct event *)event;
}

enum worker_state {
	WORKER_UNDEF,
	WORKER_RUNNING,
	WORKER_IDLE,
	WORKER_KILLED,
};

struct worker {
	struct udev_list_node node;
	pid_t pid;
	struct udev_monitor *monitor;
	enum worker_state state;
	struct event *event;
};

/* passed from worker to main process */
struct worker_message {
	pid_t pid;
	int exitcode;
};

static struct worker *node_to_worker(struct udev_list_node *node)
{
	char *worker;

	worker = (char *)node;
	worker -= offsetof(struct worker, node);
	return (struct worker *)worker;
}

static void event_queue_delete(struct event *event)
{
	udev_list_node_remove(&event->node);

	/* mark as failed, if "add" event returns non-zero */
	if (event->exitcode && strcmp(udev_device_get_action(event->dev), "add") == 0)
		udev_queue_export_device_failed(udev_queue_export, event->dev);
	else
		udev_queue_export_device_finished(udev_queue_export, event->dev);

	info(event->udev, "seq %llu done with %i\n", udev_device_get_seqnum(event->dev), event->exitcode);
	udev_device_unref(event->dev);
	free(event);
}

static void event_sig_handler(int signum)
{
	switch (signum) {
	case SIGALRM:
		_exit(1);
		break;
	case SIGTERM:
		worker_exit = 1;
		break;
	}
}

static void worker_unref(struct worker *worker)
{
	udev_monitor_unref(worker->monitor);
	free(worker);
}

static void worker_new(struct event *event)
{
	struct worker *worker;
	struct udev_monitor *worker_monitor;
	pid_t pid;
	struct sigaction act;

	/* listen for new events */
	worker_monitor = udev_monitor_new_from_netlink(event->udev, NULL);
	if (worker_monitor == NULL)
		return;
	/* allow the main daemon netlink address to send devices to the worker */
	udev_monitor_allow_unicast_sender(worker_monitor, monitor);
	udev_monitor_enable_receiving(worker_monitor);
	util_set_fd_cloexec(udev_monitor_get_fd(worker_monitor));

	worker = calloc(1, sizeof(struct worker));
	if (worker == NULL)
		return;

	pid = fork();
	switch (pid) {
	case 0: {
		sigset_t mask;
		struct udev_device *dev;

		udev_queue_export_unref(udev_queue_export);
		udev_monitor_unref(monitor);
		udev_ctrl_unref(udev_ctrl);
		close(pfd[FD_SIGNAL].fd);
		close(worker_watch[READ_END]);
		udev_log_close();
		udev_log_init("udevd-work");
		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);

		/* set signal handlers */
		memset(&act, 0x00, sizeof(act));
		act.sa_handler = event_sig_handler;
		sigemptyset (&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGTERM, &act, NULL);
		sigaction(SIGALRM, &act, NULL);

		/* unblock signals */
		sigfillset(&mask);
		sigdelset(&mask, SIGTERM);
		sigdelset(&mask, SIGALRM);
		sigprocmask(SIG_SETMASK, &mask, NULL);

		/* request TERM signal if parent exits */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		/* initial device */
		dev = event->dev;

		while (!worker_exit) {
			struct udev_event *udev_event;
			struct worker_message msg;
			int err;

			udev_event = udev_event_new(dev);
			if (udev_event == NULL)
				_exit(3);

			/* set timeout to prevent hanging processes */
			alarm(UDEV_EVENT_TIMEOUT);

			/* apply rules, create node, symlinks */
			err = udev_event_execute_rules(udev_event, rules);

			/* rules may change/disable the timeout */
			if (udev_device_get_event_timeout(dev) >= 0)
				alarm(udev_device_get_event_timeout(dev));

			/* execute RUN= */
			if (err == 0 && !udev_event->ignore_device && udev_get_run(udev_event->udev))
				udev_event_execute_run(udev_event);

			/* reset alarm */
			alarm(0);

			/* apply/restore inotify watch */
			if (err == 0 && udev_event->inotify_watch) {
				udev_watch_begin(udev_event->udev, dev);
				udev_device_update_db(dev);
			}

			/* send processed event back to libudev listeners */
			udev_monitor_send_device(worker_monitor, NULL, dev);

			info(event->udev, "seq %llu processed with %i\n", udev_device_get_seqnum(dev), err);
			udev_device_unref(dev);
			udev_event_unref(udev_event);

			/* send back the result of the event execution */
			msg.exitcode = err;
			msg.pid = getpid();
			send(worker_watch[WRITE_END], &msg, sizeof(struct worker_message), 0);

			/* wait for more device messages from udevd */
			do
				dev = udev_monitor_receive_device(worker_monitor);
			while (!worker_exit && dev == NULL);
		}

		udev_monitor_unref(worker_monitor);
		udev_log_close();
		exit(0);
	}
	case -1:
		udev_monitor_unref(worker_monitor);
		event->state = EVENT_QUEUED;
		free(worker);
		err(event->udev, "fork of child failed: %m\n");
		break;
	default:
		/* close monitor, but keep address around */
		udev_monitor_disconnect(worker_monitor);
		worker->monitor = worker_monitor;
		worker->pid = pid;
		worker->state = WORKER_RUNNING;
		worker->event = event;
		event->state = EVENT_RUNNING;
		udev_list_node_append(&worker->node, &worker_list);
		childs++;
		info(event->udev, "seq %llu forked new worker [%u]\n", udev_device_get_seqnum(event->dev), pid);
		break;
	}
}

static void event_run(struct event *event)
{
	struct udev_list_node *loop;

	udev_list_node_foreach(loop, &worker_list) {
		struct worker *worker = node_to_worker(loop);
		ssize_t count;

		if (worker->state != WORKER_IDLE)
			continue;

		worker->event = event;
		worker->state = WORKER_RUNNING;
		event->state = EVENT_RUNNING;
		count = udev_monitor_send_device(monitor, worker->monitor, event->dev);
		if (count < 0) {
			err(event->udev, "worker [%u] did not accept message, kill it\n", worker->pid);
			event->state = EVENT_QUEUED;
			worker->state = WORKER_KILLED;
			kill(worker->pid, SIGKILL);
			continue;
		}
		return;
	}

	if (childs >= max_childs) {
		info(event->udev, "maximum number (%i) of childs reached\n", childs);
		return;
	}

	/* start new worker and pass initial device */
	worker_new(event);
}

static void event_queue_insert(struct udev_device *dev)
{
	struct event *event;

	event = calloc(1, sizeof(struct event));
	if (event == NULL)
		return;

	event->udev = udev_device_get_udev(dev);
	event->dev = dev;
	event->seqnum = udev_device_get_seqnum(dev);
	event->devpath = udev_device_get_devpath(dev);
	event->devpath_len = strlen(event->devpath);
	event->devpath_old = udev_device_get_devpath_old(dev);

	udev_queue_export_device_queued(udev_queue_export, dev);
	info(event->udev, "seq %llu queued, '%s' '%s'\n", udev_device_get_seqnum(dev),
	     udev_device_get_action(dev), udev_device_get_subsystem(dev));

	event->state = EVENT_QUEUED;
	udev_list_node_append(&event->node, &event_list);

	/* run all events with a timeout set immediately */
	if (udev_device_get_timeout(dev) > 0) {
		worker_new(event);
		return;
	}
}

static void worker_kill(int retain)
{
	struct udev_list_node *loop;
	int max;

	if (childs <= retain)
		return;

	max = childs - retain;

	udev_list_node_foreach(loop, &worker_list) {
		struct worker *worker = node_to_worker(loop);

		if (max-- <= 0)
			break;

		if (worker->state == WORKER_KILLED)
			continue;

		worker->state = WORKER_KILLED;
		kill(worker->pid, SIGTERM);
	}
}

static int mem_size_mb(void)
{
	FILE *f;
	char buf[4096];
	long int memsize = -1;

	f = fopen("/proc/meminfo", "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		long int value;

		if (sscanf(buf, "MemTotal: %ld kB", &value) == 1) {
			memsize = value / 1024;
			break;
		}
	}

	fclose(f);
	return memsize;
}

/* lookup event for identical, parent, child device */
static int devpath_busy(struct event *event)
{
	struct udev_list_node *loop;
	size_t common;

	/* check if queue contains events we depend on */
	udev_list_node_foreach(loop, &event_list) {
		struct event *loop_event = node_to_event(loop);

		/* we already found a later event, earlier can not block us, no need to check again */
		if (loop_event->seqnum < event->delaying_seqnum)
			continue;

		/* event we checked earlier still exists, no need to check again */
		if (loop_event->seqnum == event->delaying_seqnum)
			return 2;

		/* found ourself, no later event can block us */
		if (loop_event->seqnum >= event->seqnum)
			break;

		/* check our old name */
		if (event->devpath_old != NULL)
			if (strcmp(loop_event->devpath, event->devpath_old) == 0) {
				event->delaying_seqnum = loop_event->seqnum;
				return 3;
			}

		/* compare devpath */
		common = MIN(loop_event->devpath_len, event->devpath_len);

		/* one devpath is contained in the other? */
		if (memcmp(loop_event->devpath, event->devpath, common) != 0)
			continue;

		/* identical device event found */
		if (loop_event->devpath_len == event->devpath_len) {
			event->delaying_seqnum = loop_event->seqnum;
			return 4;
		}

		/* parent device event found */
		if (event->devpath[common] == '/') {
			event->delaying_seqnum = loop_event->seqnum;
			return 5;
		}

		/* child device event found */
		if (loop_event->devpath[common] == '/') {
			event->delaying_seqnum = loop_event->seqnum;
			return 6;
		}

		/* no matching device */
		continue;
	}

	return 0;
}

static void events_start(struct udev *udev)
{
	struct udev_list_node *loop;

	udev_list_node_foreach(loop, &event_list) {
		struct event *event = node_to_event(loop);

		if (event->state != EVENT_QUEUED)
			continue;

		/* do not start event if parent or child event is still running */
		if (devpath_busy(event) != 0) {
			dbg(udev, "delay seq %llu (%s)\n", event->seqnum, event->devpath);
			continue;
		}

		event_run(event);
	}
}

static void worker_returned(void)
{
	while (1) {
		struct worker_message msg;
		ssize_t size;
		struct udev_list_node *loop;

		size = recv(pfd[FD_WORKER].fd, &msg, sizeof(struct worker_message), MSG_DONTWAIT);
		if (size != sizeof(struct worker_message))
			break;

		/* lookup worker who sent the signal */
		udev_list_node_foreach(loop, &worker_list) {
			struct worker *worker = node_to_worker(loop);

			if (worker->pid != msg.pid)
				continue;

			/* worker returned */
			worker->event->exitcode = msg.exitcode;
			event_queue_delete(worker->event);
			worker->event = NULL;
			worker->state = WORKER_IDLE;
			break;
		}
	}
}

/* receive the udevd message from userspace */
static void handle_ctrl_msg(struct udev_ctrl *uctrl)
{
	struct udev *udev = udev_ctrl_get_udev(uctrl);
	struct udev_ctrl_msg *ctrl_msg;
	const char *str;
	int i;

	ctrl_msg = udev_ctrl_receive_msg(uctrl);
	if (ctrl_msg == NULL)
		return;

	i = udev_ctrl_get_set_log_level(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_LOG_PRIORITY) received, log_priority=%i\n", i);
		udev_set_log_priority(udev, i);
		worker_kill(0);
	}

	if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (STOP_EXEC_QUEUE) received\n");
		stop_exec_queue = 1;
	}

	if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (START_EXEC_QUEUE) received\n");
		stop_exec_queue = 0;
	}

	if (udev_ctrl_get_reload_rules(ctrl_msg) > 0) {
		info(udev, "udevd message (RELOAD_RULES) received\n");
		reload_config = 1;
	}

	str = udev_ctrl_get_set_env(ctrl_msg);
	if (str != NULL) {
		char *key;

		key = strdup(str);
		if (key != NULL) {
			char *val;

			val = strchr(key, '=');
			if (val != NULL) {
				val[0] = '\0';
				val = &val[1];
				if (val[0] == '\0') {
					info(udev, "udevd message (ENV) received, unset '%s'\n", key);
					udev_add_property(udev, key, NULL);
				} else {
					info(udev, "udevd message (ENV) received, set '%s=%s'\n", key, val);
					udev_add_property(udev, key, val);
				}
			} else {
				err(udev, "wrong key format '%s'\n", key);
			}
			free(key);
		}
		worker_kill(0);
	}

	i = udev_ctrl_get_set_max_childs(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_MAX_CHILDS) received, max_childs=%i\n", i);
		max_childs = i;
	}

	settle_pid = udev_ctrl_get_settle(ctrl_msg);
	if (settle_pid > 0) {
		info(udev, "udevd message (SETTLE) received\n");
		kill(settle_pid, SIGUSR1);
		settle_pid = 0;
	}
	udev_ctrl_msg_unref(ctrl_msg);
}

/* read inotify messages */
static int handle_inotify(struct udev *udev)
{
	ssize_t nbytes, pos;
	char *buf;
	struct inotify_event *ev;

	if ((ioctl(pfd[FD_INOTIFY].fd, FIONREAD, &nbytes) < 0) || (nbytes <= 0))
		return 0;

	buf = malloc(nbytes);
	if (buf == NULL) {
		err(udev, "error getting buffer for inotify\n");
		return -1;
	}

	nbytes = read(pfd[FD_INOTIFY].fd, buf, nbytes);

	for (pos = 0; pos < nbytes; pos += sizeof(struct inotify_event) + ev->len) {
		struct udev_device *dev;

		ev = (struct inotify_event *)(buf + pos);
		if (ev->len) {
			dbg(udev, "inotify event: %x for %s\n", ev->mask, ev->name);
			reload_config = 1;
			continue;
		}

		dev = udev_watch_lookup(udev, ev->wd);
		if (dev != NULL) {
			dbg(udev, "inotify event: %x for %s\n", ev->mask, udev_device_get_devnode(dev));
			if (ev->mask & IN_CLOSE_WRITE) {
				char filename[UTIL_PATH_SIZE];
				int fd;

				info(udev, "device %s closed, synthesising 'change'\n", udev_device_get_devnode(dev));
				util_strscpyl(filename, sizeof(filename), udev_device_get_syspath(dev), "/uevent", NULL);
				fd = open(filename, O_WRONLY);
				if (fd < 0 || write(fd, "change", 6) < 0)
					info(udev, "error writing uevent: %m\n");
				close(fd);
			}
			if (ev->mask & IN_IGNORED)
				udev_watch_end(udev, dev);

			udev_device_unref(dev);
		}

	}

	free(buf);
	return 0;
}

static void handle_signal(struct udev *udev, int signo)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		udev_exit = 1;
		break;
	case SIGCHLD:
		while (1) {
			pid_t pid;
			int status;
			struct udev_list_node *loop, *tmp;

			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				break;

			udev_list_node_foreach_safe(loop, tmp, &worker_list) {
				struct worker *worker = node_to_worker(loop);

				if (worker->pid != pid)
					continue;

				/* fail event, if worker died unexpectedly */
				if (worker->event != NULL) {
					int exitcode;

					if (WIFEXITED(status))
						exitcode = WEXITSTATUS(status);
					else if (WIFSIGNALED(status))
						exitcode = WTERMSIG(status) + 128;
					else
						exitcode = 0;
					worker->event->exitcode = exitcode;
					err(udev, "worker [%u] unexpectedly returned with %i\n", pid, exitcode);
					event_queue_delete(worker->event);
				}

				udev_list_node_remove(&worker->node);
				worker_unref(worker);
				childs--;
				info(udev, "worker [%u] exit\n", pid);
				break;
			}
		}
		break;
	case SIGHUP:
		reload_config = 1;
		break;
	}
}

static void startup_log(struct udev *udev)
{
	FILE *f;
	char path[UTIL_PATH_SIZE];
	struct stat statbuf;

	f = fopen("/dev/kmsg", "w");
	if (f != NULL)
		fprintf(f, "<6>udev: starting version " VERSION "\n");

	util_strscpyl(path, sizeof(path), udev_get_sys_path(udev), "/class/mem/null", NULL);
	if (lstat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
		const char *depr_str =
			"udev: missing sysfs features; please update the kernel "
			"or disable the kernel's CONFIG_SYSFS_DEPRECATED option; "
			"udev may fail to work correctly";

		if (f != NULL)
			fprintf(f, "<3>%s\n", depr_str);
		err(udev, "%s\n", depr_str);
		sleep(3);
	}

	if (f != NULL)
		fclose(f);
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	int fd;
	sigset_t mask;
	const char *value;
	int daemonize = 0;
	int resolve_names = 1;
	static const struct option options[] = {
		{ "daemon", no_argument, NULL, 'd' },
		{ "debug-trace", no_argument, NULL, 't' },
		{ "debug", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ "resolve-names", required_argument, NULL, 'N' },
		{}
	};
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("udevd");
	udev_set_log_fn(udev, log_fn);
	info(udev, "version %s\n", VERSION);
	udev_selinux_init(udev);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dDthV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			daemonize = 1;
			break;
		case 't':
			debug_trace = 1;
			break;
		case 'D':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'N':
			if (strcmp (optarg, "early") == 0) {
				resolve_names = 1;
			} else if (strcmp (optarg, "late") == 0) {
				resolve_names = 0;
			} else if (strcmp (optarg, "never") == 0) {
				resolve_names = -1;
			} else {
				fprintf(stderr, "resolve-names must be early, late or never\n");
				err(udev, "resolve-names must be early, late or never\n");
				goto exit;
			}
			break;
		case 'h':
			printf("Usage: udevd [--help] [--daemon] [--debug-trace] [--debug] "
			       "[--resolve-names=early|late|never] [--version]\n");
			goto exit;
		case 'V':
			printf("%s\n", VERSION);
			goto exit;
		default:
			goto exit;
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		err(udev, "root privileges required\n");
		goto exit;
	}

	/* make sure std{in,out,err} fd's are in a sane state */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "cannot open /dev/null\n");
		err(udev, "cannot open /dev/null\n");
	}
	if (write(STDOUT_FILENO, 0, 0) < 0)
		dup2(fd, STDOUT_FILENO);
	if (write(STDERR_FILENO, 0, 0) < 0)
		dup2(fd, STDERR_FILENO);

	/* init control socket, bind() ensures, that only one udevd instance is running */
	udev_ctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
	if (udev_ctrl == NULL) {
		fprintf(stderr, "error initializing control socket");
		err(udev, "error initializing udevd socket");
		rc = 1;
		goto exit;
	}
	if (udev_ctrl_enable_receiving(udev_ctrl) < 0) {
		fprintf(stderr, "error binding control socket, seems udevd is already running\n");
		err(udev, "error binding control socket, seems udevd is already running\n");
		rc = 1;
		goto exit;
	}
	pfd[FD_CONTROL].fd = udev_ctrl_get_fd(udev_ctrl);

	monitor = udev_monitor_new_from_netlink(udev, "kernel");
	if (monitor == NULL || udev_monitor_enable_receiving(monitor) < 0) {
		fprintf(stderr, "error initializing netlink socket\n");
		err(udev, "error initializing netlink socket\n");
		rc = 3;
		goto exit;
	}
	udev_monitor_set_receive_buffer_size(monitor, 128*1024*1024);
	pfd[FD_NETLINK].fd = udev_monitor_get_fd(monitor);

	pfd[FD_INOTIFY].fd = udev_watch_init(udev);
	if (pfd[FD_INOTIFY].fd < 0) {
		fprintf(stderr, "error initializing inotify\n");
		err(udev, "error initializing inotify\n");
		rc = 4;
		goto exit;
	}

	if (udev_get_rules_path(udev) != NULL) {
		inotify_add_watch(pfd[FD_INOTIFY].fd, udev_get_rules_path(udev),
				  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	} else {
		char filename[UTIL_PATH_SIZE];

		inotify_add_watch(pfd[FD_INOTIFY].fd, LIBEXECDIR "/rules.d",
				  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		inotify_add_watch(pfd[FD_INOTIFY].fd, SYSCONFDIR "/udev/rules.d",
				  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

		/* watch dynamic rules directory */
		util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/rules.d", NULL);
		inotify_add_watch(pfd[FD_INOTIFY].fd, filename,
				  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	}
	udev_watch_restore(udev);

	/* block and listen to all signals on signalfd */
	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);
	pfd[FD_SIGNAL].fd = signalfd(-1, &mask, 0);
	if (pfd[FD_SIGNAL].fd < 0) {
		fprintf(stderr, "error getting signalfd\n");
		err(udev, "error getting signalfd\n");
		rc = 5;
		goto exit;
	}

	/* unnamed socket from workers to the main daemon */
	if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, worker_watch) < 0) {
		fprintf(stderr, "error getting socketpair\n");
		err(udev, "error getting socketpair\n");
		rc = 6;
		goto exit;
	}
	pfd[FD_WORKER].fd = worker_watch[READ_END];
	util_set_fd_cloexec(worker_watch[WRITE_END]);

	rules = udev_rules_new(udev, resolve_names);
	if (rules == NULL) {
		err(udev, "error reading rules\n");
		goto exit;
	}

	udev_queue_export = udev_queue_export_new(udev);
	if (udev_queue_export == NULL) {
		err(udev, "error creating queue file\n");
		goto exit;
	}

	if (daemonize) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			break;
		case -1:
			err(udev, "fork of daemon failed: %m\n");
			rc = 4;
			goto exit;
		default:
			rc = 0;
			goto exit;
		}
	}

	startup_log(udev);

	/* redirect std{out,err} */
	if (!debug && !debug_trace) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	}
	if (fd > STDERR_FILENO)
		close(fd);

	/* set scheduling priority for the daemon */
	setpriority(PRIO_PROCESS, 0, UDEVD_PRIORITY);

	chdir("/");
	umask(022);
	setsid();

	/* OOM_DISABLE == -17 */
	fd = open("/proc/self/oom_adj", O_RDWR);
	if (fd < 0) {
		err(udev, "error disabling OOM: %m\n");
	} else {
		write(fd, "-17", 3);
		close(fd);
	}

	/* in trace mode run one event after the other */
	if (debug_trace) {
		max_childs = 1;
	} else {
		int memsize = mem_size_mb();

		if (memsize > 0)
			max_childs = 128 + (memsize / 8);
		else
			max_childs = 128;
	}

	/* possibly overwrite maximum limit of executed events */
	value = getenv("UDEVD_MAX_CHILDS");
	if (value)
		max_childs = strtoul(value, NULL, 10);
	info(udev, "initialize max_childs to %u\n", max_childs);

	udev_list_init(&event_list);
	udev_list_init(&worker_list);

	while (!udev_exit) {
		int fdcount;
		int timeout;

		/* set timeout to kill idle workers */
		if (udev_list_is_empty(&event_list) && childs > 2)
			timeout = 3 * 1000;
		else
			timeout = -1;
		/* wait for events */
		fdcount = poll(pfd, ARRAY_SIZE(pfd), timeout);
		if (fdcount < 0)
			continue;

		/* timeout - kill idle workers */
		if (fdcount == 0)
			worker_kill(2);

		/* event has finished */
		if (pfd[FD_WORKER].revents & POLLIN)
			worker_returned();

		/* get kernel uevent */
		if (pfd[FD_NETLINK].revents & POLLIN) {
			struct udev_device *dev;

			dev = udev_monitor_receive_device(monitor);
			if (dev != NULL)
				event_queue_insert(dev);
			else
				udev_device_unref(dev);
		}

		/* start new events */
		if (!udev_list_is_empty(&event_list) && !stop_exec_queue)
			events_start(udev);

		/* get signal */
		if (pfd[FD_SIGNAL].revents & POLLIN) {
			struct signalfd_siginfo fdsi;
			ssize_t size;

			size = read(pfd[FD_SIGNAL].fd, &fdsi, sizeof(struct signalfd_siginfo));
			if (size == sizeof(struct signalfd_siginfo))
				handle_signal(udev, fdsi.ssi_signo);
		}

		/* device node and rules directory inotify watch */
		if (pfd[FD_INOTIFY].revents & POLLIN)
			handle_inotify(udev);

		/*
		 * get control message
		 *
		 * This needs to be after the inotify handling, to make sure,
		 * that the settle signal is send back after the possibly generated
		 * "change" events by the inotify device node watch.
		 */
		if (pfd[FD_CONTROL].revents & POLLIN)
			handle_ctrl_msg(udev_ctrl);

		/* rules changed, set by inotify or a HUP signal */
		if (reload_config) {
			struct udev_rules *rules_new;

			worker_kill(0);
			rules_new = udev_rules_new(udev, resolve_names);
			if (rules_new != NULL) {
				udev_rules_unref(rules);
				rules = rules_new;
			}
			reload_config = 0;
		}
	}

	udev_queue_export_cleanup(udev_queue_export);
	rc = 0;
exit:
	udev_queue_export_unref(udev_queue_export);
	udev_rules_unref(rules);
	udev_ctrl_unref(udev_ctrl);
	if (pfd[FD_SIGNAL].fd >= 0)
		close(pfd[FD_SIGNAL].fd);
	if (worker_watch[READ_END] >= 0)
		close(worker_watch[READ_END]);
	if (worker_watch[WRITE_END] >= 0)
		close(worker_watch[WRITE_END]);
	udev_monitor_unref(monitor);
	udev_selinux_exit(udev);
	udev_unref(udev);
	udev_log_close();
	return rc;
}
