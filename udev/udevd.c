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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/utsname.h>

#include "udev.h"

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

static bool debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		char buf[1024];
		struct timeval tv;
		struct timezone tz;

		vsnprintf(buf, sizeof(buf), format, args);
		gettimeofday(&tv, &tz);
		fprintf(stderr, "%llu.%06u [%u] %s: %s",
			(unsigned long long) tv.tv_sec, (unsigned int) tv.tv_usec,
			(int) getpid(), fn, buf);
	} else {
		vsyslog(priority, format, args);
	}
}

static struct udev_rules *rules;
static struct udev_queue_export *udev_queue_export;
static struct udev_ctrl *udev_ctrl;
static struct udev_monitor *monitor;
static int worker_watch[2];
static pid_t settle_pid;
static bool stop_exec_queue;
static bool reload_config;
static int children;
static int children_max;
static int exec_delay;
static sigset_t orig_sigmask;
static struct udev_list_node event_list;
static struct udev_list_node worker_list;
static bool udev_exit;
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
	dev_t devnum;
	bool is_block;
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
	struct udev *udev;
	int refcount;
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
	if (event->exitcode != 0 && strcmp(udev_device_get_action(event->dev), "remove") != 0)
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
		worker_exit = true;
		break;
	}
}

static struct worker *worker_ref(struct worker *worker)
{
	worker->refcount++;
	return worker;
}

static void worker_unref(struct worker *worker)
{
	worker->refcount--;
	if (worker->refcount > 0)
		return;

	udev_list_node_remove(&worker->node);
	udev_monitor_unref(worker->monitor);
	children--;
	info(worker->udev, "worker [%u] cleaned up\n", worker->pid);
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

	worker = calloc(1, sizeof(struct worker));
	if (worker == NULL)
		return;
	/* worker + event reference */
	worker->refcount = 2;
	worker->udev = event->udev;

	pid = fork();
	switch (pid) {
	case 0: {
		sigset_t sigmask;
		struct udev_device *dev;
		struct pollfd pmon = {
			.fd = udev_monitor_get_fd(worker_monitor),
			.events = POLLIN,
		};

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

		/* unblock SIGALRM */
		sigfillset(&sigmask);
		sigdelset(&sigmask, SIGALRM);
		sigprocmask(SIG_SETMASK, &sigmask, NULL);
		/* SIGTERM is unblocked in ppoll() */
		sigdelset(&sigmask, SIGTERM);

		/* request TERM signal if parent exits */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		/* initial device */
		dev = event->dev;

		do {
			struct udev_event *udev_event;
			struct worker_message msg = {};
			int err;
			int failed = 0;

			info(event->udev, "seq %llu running\n", udev_device_get_seqnum(dev));
			udev_event = udev_event_new(dev);
			if (udev_event == NULL)
				_exit(3);

			/* set timeout to prevent hanging processes */
			alarm(UDEV_EVENT_TIMEOUT);

			if (exec_delay > 0)
				udev_event->exec_delay = exec_delay;

			/* apply rules, create node, symlinks */
			err = udev_event_execute_rules(udev_event, rules);

			/* rules may change/disable the timeout */
			if (udev_device_get_event_timeout(dev) >= 0)
				alarm(udev_device_get_event_timeout(dev));

			if (err == 0)
				failed = udev_event_execute_run(udev_event, &orig_sigmask);

			alarm(0);

			/* apply/restore inotify watch */
			if (err == 0 && udev_event->inotify_watch) {
				udev_watch_begin(udev_event->udev, dev);
				udev_device_update_db(dev);
			}

			/* send processed event back to libudev listeners */
			udev_monitor_send_device(worker_monitor, NULL, dev);

			/* send udevd the result of the event execution */
			if (err != 0)
				msg.exitcode = err;
			else if (failed != 0)
				msg.exitcode = failed;
			msg.pid = getpid();
			send(worker_watch[WRITE_END], &msg, sizeof(struct worker_message), 0);

			info(event->udev, "seq %llu processed with %i\n", udev_device_get_seqnum(dev), err);
			udev_event_unref(udev_event);
			udev_device_unref(dev);
			dev = NULL;

			/* wait for more device messages or signal from udevd */
			while (!worker_exit) {
				int fdcount;

				fdcount = ppoll(&pmon, 1, NULL, &sigmask);
				if (fdcount < 0)
					continue;

				if (pmon.revents & POLLIN) {
					dev = udev_monitor_receive_device(worker_monitor);
					if (dev != NULL)
						break;
				}
			}
		} while (dev != NULL);

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
		children++;
		info(event->udev, "seq %llu forked new worker [%u]\n", udev_device_get_seqnum(event->dev), pid);
		break;
	}
}

static void event_run(struct event *event, bool force)
{
	struct udev_list_node *loop;

	udev_list_node_foreach(loop, &worker_list) {
		struct worker *worker = node_to_worker(loop);
		ssize_t count;

		if (worker->state != WORKER_IDLE)
			continue;

		count = udev_monitor_send_device(monitor, worker->monitor, event->dev);
		if (count < 0) {
			err(event->udev, "worker [%u] did not accept message %zi (%m), kill it\n", worker->pid, count);
			kill(worker->pid, SIGKILL);
			worker->state = WORKER_KILLED;
			continue;
		}
		worker_ref(worker);
		worker->event = event;
		worker->state = WORKER_RUNNING;
		event->state = EVENT_RUNNING;
		return;
	}

	if (!force && children >= children_max) {
		if (children_max > 1)
			info(event->udev, "maximum number (%i) of children reached\n", children);
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
	event->devnum = udev_device_get_devnum(dev);
	event->is_block = (strcmp("block", udev_device_get_subsystem(dev)) == 0);

	udev_queue_export_device_queued(udev_queue_export, dev);
	info(event->udev, "seq %llu queued, '%s' '%s'\n", udev_device_get_seqnum(dev),
	     udev_device_get_action(dev), udev_device_get_subsystem(dev));

	event->state = EVENT_QUEUED;
	udev_list_node_append(&event->node, &event_list);

	/* run all events with a timeout set immediately */
	if (udev_device_get_timeout(dev) > 0) {
		event_run(event, true);
		return;
	}
}

static void worker_kill(struct udev *udev, int retain)
{
	struct udev_list_node *loop;
	int max;

	if (children <= retain)
		return;

	max = children - retain;

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

/* lookup event for identical, parent, child device */
static bool is_devpath_busy(struct event *event)
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
			return true;

		/* found ourself, no later event can block us */
		if (loop_event->seqnum >= event->seqnum)
			break;

		/* check major/minor */
		if (major(event->devnum) != 0 && event->devnum == loop_event->devnum && event->is_block == loop_event->is_block)
			return true;

		/* check our old name */
		if (event->devpath_old != NULL && strcmp(loop_event->devpath, event->devpath_old) == 0) {
			event->delaying_seqnum = loop_event->seqnum;
			return true;
		}

		/* compare devpath */
		common = MIN(loop_event->devpath_len, event->devpath_len);

		/* one devpath is contained in the other? */
		if (memcmp(loop_event->devpath, event->devpath, common) != 0)
			continue;

		/* identical device event found */
		if (loop_event->devpath_len == event->devpath_len) {
			event->delaying_seqnum = loop_event->seqnum;
			return true;
		}

		/* parent device event found */
		if (event->devpath[common] == '/') {
			event->delaying_seqnum = loop_event->seqnum;
			return true;
		}

		/* child device event found */
		if (loop_event->devpath[common] == '/') {
			event->delaying_seqnum = loop_event->seqnum;
			return true;
		}

		/* no matching device */
		continue;
	}

	return false;
}

static void events_start(struct udev *udev)
{
	struct udev_list_node *loop;

	udev_list_node_foreach(loop, &event_list) {
		struct event *event = node_to_event(loop);

		if (event->state != EVENT_QUEUED)
			continue;

		/* do not start event if parent or child event is still running */
		if (is_devpath_busy(event)) {
			dbg(udev, "delay seq %llu (%s)\n", event->seqnum, event->devpath);
			continue;
		}

		event_run(event, false);
	}
}

static void worker_returned(void)
{
	for (;;) {
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
			if (worker->state != WORKER_KILLED)
				worker->state = WORKER_IDLE;
			worker_unref(worker);
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
		worker_kill(udev, 0);
	}

	if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (STOP_EXEC_QUEUE) received\n");
		stop_exec_queue = true;
	}

	if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (START_EXEC_QUEUE) received\n");
		stop_exec_queue = false;
	}

	if (udev_ctrl_get_reload_rules(ctrl_msg) > 0) {
		info(udev, "udevd message (RELOAD_RULES) received\n");
		reload_config = true;
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
		worker_kill(udev, 0);
	}

	i = udev_ctrl_get_set_children_max(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_MAX_CHILDREN) received, children_max=%i\n", i);
		children_max = i;
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
	int nbytes, pos;
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
			const char *s;

			info(udev, "inotify event: %x for %s\n", ev->mask, ev->name);
			s = strstr(ev->name, ".rules");
			if (s == NULL)
				continue;
			if (strlen(s) != strlen(".rules"))
				continue;
			reload_config = true;
			continue;
		}

		dev = udev_watch_lookup(udev, ev->wd);
		if (dev != NULL) {
			info(udev, "inotify event: %x for %s\n", ev->mask, udev_device_get_devnode(dev));
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
		udev_exit = true;
		break;
	case SIGCHLD:
		for (;;) {
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

				info(udev, "worker [%u] exit\n", pid);
				if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
					err(udev, "worker [%u] unexpectedly returned with status 0x%04x\n", pid, status);
					if (worker->event != NULL) {
						err(udev, "worker [%u] failed while handling '%s'\n", pid, worker->event->devpath);
						worker->event->exitcode = -32;
						event_queue_delete(worker->event);
						/* drop reference from running event */
						worker_unref(worker);
					}
				}
				worker_unref(worker);
				break;
			}
		}
		break;
	case SIGHUP:
		reload_config = true;
		break;
	}
}

static void static_dev_create_from_modules(struct udev *udev)
{
	struct utsname kernel;
	char modules[UTIL_PATH_SIZE];
	char buf[4096];
	FILE *f;

	uname(&kernel);
	util_strscpyl(modules, sizeof(modules), "/lib/modules/", kernel.release, "/modules.devname", NULL);
	f = fopen(modules, "r");
	if (f == NULL)
		return;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *s;
		const char *modname;
		const char *devname;
		const char *devno;
		int maj, min;
		char type;
		mode_t mode;
		char filename[UTIL_PATH_SIZE];

		if (buf[0] == '#')
			continue;

		modname = buf;
		s = strchr(modname, ' ');
		if (s == NULL)
			continue;
		s[0] = '\0';

		devname = &s[1];
		s = strchr(devname, ' ');
		if (s == NULL)
			continue;
		s[0] = '\0';

		devno = &s[1];
		s = strchr(devno, ' ');
		if (s == NULL)
			s = strchr(devno, '\n');
		if (s != NULL)
			s[0] = '\0';
		if (sscanf(devno, "%c%u:%u", &type, &maj, &min) != 3)
			continue;

		if (type == 'c')
			mode = 0600 | S_IFCHR;
		else if (type == 'b')
			mode = 0600 | S_IFBLK;
		else
			continue;

		util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/", devname, NULL);
		util_create_path(udev, filename);
		udev_selinux_setfscreatecon(udev, filename, mode);
		info(udev, "mknod '%s' %c%u:%u\n", filename, type, maj, min);
		if (mknod(filename, mode, makedev(maj, min)) < 0 && errno == EEXIST)
			utimensat(AT_FDCWD, filename, NULL, 0);
		udev_selinux_resetfscreatecon(udev);
	}

	fclose(f);
}

static int copy_dir(struct udev *udev, DIR *dir_from, DIR *dir_to, int maxdepth)
{
	struct dirent *dent;

	for (dent = readdir(dir_from); dent != NULL; dent = readdir(dir_from)) {
		struct stat stats;

		if (dent->d_name[0] == '.')
			continue;
		if (fstatat(dirfd(dir_from), dent->d_name, &stats, AT_SYMLINK_NOFOLLOW) != 0)
			continue;

		if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
			udev_selinux_setfscreateconat(udev, dirfd(dir_to), dent->d_name, stats.st_mode & 0777);
			if (mknodat(dirfd(dir_to), dent->d_name, stats.st_mode, stats.st_rdev) == 0) {
				fchmodat(dirfd(dir_to), dent->d_name, stats.st_mode & 0777, 0);
				fchownat(dirfd(dir_to), dent->d_name, stats.st_uid, stats.st_gid, 0);
			} else {
				utimensat(dirfd(dir_to), dent->d_name, NULL, 0);
			}
			udev_selinux_resetfscreatecon(udev);
		} else if (S_ISLNK(stats.st_mode)) {
			char target[UTIL_PATH_SIZE];
			ssize_t len;

			len = readlinkat(dirfd(dir_from), dent->d_name, target, sizeof(target));
			if (len <= 0 || len == (ssize_t)sizeof(target))
				continue;
			target[len] = '\0';
			udev_selinux_setfscreateconat(udev, dirfd(dir_to), dent->d_name, S_IFLNK);
			if (symlinkat(target, dirfd(dir_to), dent->d_name) < 0 && errno == EEXIST)
				utimensat(dirfd(dir_to), dent->d_name, NULL, AT_SYMLINK_NOFOLLOW);
			udev_selinux_resetfscreatecon(udev);
		} else if (S_ISDIR(stats.st_mode)) {
			DIR *dir2_from, *dir2_to;

			if (maxdepth == 0)
				continue;

			udev_selinux_setfscreateconat(udev, dirfd(dir_to), dent->d_name, S_IFDIR|0755);
			mkdirat(dirfd(dir_to), dent->d_name, 0755);
			udev_selinux_resetfscreatecon(udev);

			dir2_to = fdopendir(openat(dirfd(dir_to), dent->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));
			if (dir2_to == NULL)
				continue;

			dir2_from = fdopendir(openat(dirfd(dir_from), dent->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));
			if (dir2_from == NULL) {
				closedir(dir2_to);
				continue;
			}

			copy_dir(udev, dir2_from, dir2_to, maxdepth-1);

			closedir(dir2_to);
			closedir(dir2_from);
		}
	}

	return 0;
}

static void static_dev_create_links(struct udev *udev, DIR *dir)
{
	struct stdlinks {
		const char *link;
		const char *target;
	};
	static const struct stdlinks stdlinks[] = {
		{ "core", "/proc/kcore" },
		{ "fd", "/proc/self/fd" },
		{ "stdin", "/proc/self/fd/0" },
		{ "stdout", "/proc/self/fd/1" },
		{ "stderr", "/proc/self/fd/2" },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(stdlinks); i++) {
		udev_selinux_setfscreateconat(udev, dirfd(dir), stdlinks[i].link, S_IFLNK);
		if (symlinkat(stdlinks[i].target, dirfd(dir), stdlinks[i].link) < 0 && errno == EEXIST)
			utimensat(dirfd(dir), stdlinks[i].link, NULL, AT_SYMLINK_NOFOLLOW);
		udev_selinux_resetfscreatecon(udev);
	}
}

static void static_dev_create_from_devices(struct udev *udev, DIR *dir)
{
	DIR *dir_from;

	dir_from = opendir(LIBEXECDIR "/devices");
	if (dir_from == NULL)
		return;
	copy_dir(udev, dir_from, dir, 8);
	closedir(dir_from);
}

static void static_dev_create(struct udev *udev)
{
	DIR *dir;

	dir = opendir(udev_get_dev_path(udev));
	if (dir == NULL)
		return;

	static_dev_create_links(udev, dir);
	static_dev_create_from_devices(udev, dir);

	closedir(dir);
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

static int init_notify(const char *state)
{
	int fd = -1, r;
	struct msghdr msghdr;
	struct iovec iovec;
	struct ucred *ucred;
	union {
		struct sockaddr sa;
		struct sockaddr_un un;
	} sockaddr;
	union {
		struct cmsghdr cmsghdr;
		uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
	} control;
	const char *e;

	if (!(e = getenv("NOTIFY_SOCKET"))) {
		r = 0;
		goto finish;
	}

	/* Must be an abstract socket, or an absolute path */
	if ((e[0] != '@' && e[0] != '/') || e[1] == 0) {
		r = -EINVAL;
		goto finish;
	}

	if ((fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
		r = -errno;
		goto finish;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sa.sa_family = AF_UNIX;
	strncpy(sockaddr.un.sun_path, e, sizeof(sockaddr.un.sun_path));

	if (sockaddr.un.sun_path[0] == '@')
		sockaddr.un.sun_path[0] = 0;

	memset(&iovec, 0, sizeof(iovec));
	iovec.iov_base = (char*) state;
	iovec.iov_len = strlen(state);

	memset(&control, 0, sizeof(control));
	control.cmsghdr.cmsg_level = SOL_SOCKET;
	control.cmsghdr.cmsg_type = SCM_CREDENTIALS;
	control.cmsghdr.cmsg_len = CMSG_LEN(sizeof(struct ucred));

	ucred = (struct ucred*) CMSG_DATA(&control.cmsghdr);
	ucred->pid = getpid();
	ucred->uid = getuid();
	ucred->gid = getgid();

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name = &sockaddr;
	msghdr.msg_namelen = sizeof(sa_family_t) + strlen(e);
	if (msghdr.msg_namelen > sizeof(struct sockaddr_un))
		msghdr.msg_namelen = sizeof(struct sockaddr_un);
	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = &control;
	msghdr.msg_controllen = control.cmsghdr.cmsg_len;

	if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0) {
		r = -errno;
		goto finish;
	}

	r = 0;

finish:
	if (fd >= 0)
		close(fd);

	return r;
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	int fd;
	FILE *f;
	sigset_t mask;
	int daemonize = false;
	int resolve_names = 1;
	static const struct option options[] = {
		{ "daemon", no_argument, NULL, 'd' },
		{ "debug", no_argument, NULL, 'D' },
		{ "children-max", required_argument, NULL, 'c' },
		{ "exec-delay", required_argument, NULL, 'e' },
		{ "resolve-names", required_argument, NULL, 'N' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
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

	for (;;) {
		int option;

		option = getopt_long(argc, argv, "cdeDthV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			daemonize = true;
			break;
		case 'c':
			children_max = strtoul(optarg, NULL, 0);
			break;
		case 'e':
			exec_delay = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			debug = true;
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
			printf("Usage: udevd OPTIONS\n"
			       "  --daemon\n"
			       "  --debug\n"
			       "  --children-max=<maximum number of workers>\n"
			       "  --exec-delay=<seconds to wait before executing RUN=>\n"
			       "  --resolve-names=early|late|never\n" 
			       "  --version\n"
			       "  --help\n"
			       "\n");
			goto exit;
		case 'V':
			printf("%s\n", VERSION);
			goto exit;
		default:
			goto exit;
		}
	}

	/*
	 * read the kernel commandline, in case we need to get into debug mode
	 *   udev.log-priority=<level>              syslog priority
	 *   udev.children-max=<number of workers>  events are fully serialized if set to 1
	 *
	 */
	f = fopen("/proc/cmdline", "r");
	if (f != NULL) {
		char cmdline[4096];

		if (fgets(cmdline, sizeof(cmdline), f) != NULL) {
			char *pos;

			pos = strstr(cmdline, "udev.log-priority=");
			if (pos != NULL) {
				pos += strlen("udev.log-priority=");
				udev_set_log_priority(udev, util_log_priority(pos));
			}

			pos = strstr(cmdline, "udev.children-max=");
			if (pos != NULL) {
				pos += strlen("udev.children-max=");
				children_max = strtoul(pos, NULL, 0);
			}

			pos = strstr(cmdline, "udev.exec-delay=");
			if (pos != NULL) {
				pos += strlen("udev.exec-delay=");
				exec_delay = strtoul(pos, NULL, 0);
			}
		}
		fclose(f);
	}

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		err(udev, "root privileges required\n");
		goto exit;
	}

	/* set umask before creating any file/directory */
	chdir("/");
	umask(022);

	/* before opening new files, make sure std{in,out,err} fds are in a sane state */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "cannot open /dev/null\n");
		err(udev, "cannot open /dev/null\n");
	}
	if (write(STDOUT_FILENO, 0, 0) < 0)
		dup2(fd, STDOUT_FILENO);
	if (write(STDERR_FILENO, 0, 0) < 0)
		dup2(fd, STDERR_FILENO);

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
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	} else {
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;

		inotify_add_watch(pfd[FD_INOTIFY].fd, LIBEXECDIR "/rules.d",
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		inotify_add_watch(pfd[FD_INOTIFY].fd, SYSCONFDIR "/udev/rules.d",
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

		/* watch dynamic rules directory */
		util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/rules.d", NULL);
		if (stat(filename, &statbuf) != 0) {
			util_create_path(udev, filename);
			udev_selinux_setfscreatecon(udev, filename, S_IFDIR|0755);
			mkdir(filename, 0755);
			udev_selinux_resetfscreatecon(udev);
		}
		inotify_add_watch(pfd[FD_INOTIFY].fd, filename,
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	}
	udev_watch_restore(udev);

	/* block and listen to all signals on signalfd */
	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, &orig_sigmask);
	pfd[FD_SIGNAL].fd = signalfd(-1, &mask, 0);
	if (pfd[FD_SIGNAL].fd < 0) {
		fprintf(stderr, "error getting signalfd\n");
		err(udev, "error getting signalfd\n");
		rc = 5;
		goto exit;
	}

	/* unnamed socket from workers to the main daemon */
	if (socketpair(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0, worker_watch) < 0) {
		fprintf(stderr, "error getting socketpair\n");
		err(udev, "error getting socketpair\n");
		rc = 6;
		goto exit;
	}
	pfd[FD_WORKER].fd = worker_watch[READ_END];

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

	if (!debug) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	}
	if (fd > STDERR_FILENO)
		close(fd);

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
	} else {
		init_notify("READY=1");
	}

	/* set scheduling priority for the main daemon process */
	setpriority(PRIO_PROCESS, 0, UDEVD_PRIORITY);

	setsid();

	f = fopen("/dev/kmsg", "w");
	if (f != NULL) {
		fprintf(f, "<6>udev: starting version " VERSION "\n");
		fclose(f);
	}

	/* OOM_DISABLE == -17 */
	fd = open("/proc/self/oom_adj", O_RDWR);
	if (fd < 0) {
		err(udev, "error disabling OOM: %m\n");
	} else {
		write(fd, "-17", 3);
		close(fd);
	}

	if (children_max <= 0) {
		int memsize = mem_size_mb();

		/* set value depending on the amount of RAM */
		if (memsize > 0)
			children_max = 128 + (memsize / 8);
		else
			children_max = 128;
	}
	info(udev, "set children_max to %u\n", children_max);

	static_dev_create(udev);
	static_dev_create_from_modules(udev);
	udev_rules_apply_static_dev_perms(rules);

	udev_list_init(&event_list);
	udev_list_init(&worker_list);

	while (!udev_exit) {
		int fdcount;
		int timeout;

		/* set timeout to kill idle workers */
		if (udev_list_is_empty(&event_list) && children > 2)
			timeout = 3 * 1000;
		else
			timeout = -1;
		/* wait for events */
		fdcount = poll(pfd, ARRAY_SIZE(pfd), timeout);
		if (fdcount < 0)
			continue;

		/* timeout - kill idle workers */
		if (fdcount == 0)
			worker_kill(udev, 2);

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

			worker_kill(udev, 0);
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
