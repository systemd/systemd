/*
 * Copyright (C) 2004-2011 Kay Sievers <kay.sievers@vrfy.org>
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
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/utsname.h>

#include "udev.h"
#include "sd-daemon.h"

static bool debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		char buf[1024];
		struct timespec ts;

		vsnprintf(buf, sizeof(buf), format, args);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		fprintf(stderr, "[%llu.%06u] [%u] %s: %s",
			(unsigned long long) ts.tv_sec, (unsigned int) ts.tv_nsec/1000,
			(int) getpid(), fn, buf);
	} else {
		vsyslog(priority, format, args);
	}
}

static struct udev_rules *rules;
static struct udev_queue_export *udev_queue_export;
static struct udev_ctrl *udev_ctrl;
static struct udev_monitor *monitor;
static int worker_watch[2] = { -1, -1 };
static int fd_signal = -1;
static int fd_ep = -1;
static int fd_inotify = -1;
static bool stop_exec_queue;
static bool reload_config;
static int children;
static int children_max;
static int exec_delay;
static sigset_t sigmask_orig;
static UDEV_LIST(event_list);
static UDEV_LIST(worker_list);
static bool udev_exit;

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
	int ifindex;
};

static struct event *node_to_event(struct udev_list_node *node)
{
	char *event;

	event = (char *)node;
	event -= offsetof(struct event, node);
	return (struct event *)event;
}

static void event_queue_cleanup(struct udev *udev, enum event_state type);

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

static void event_queue_delete(struct event *event, bool export)
{
	udev_list_node_remove(&event->node);

	if (export) {
		/* mark as failed, if "add" event returns non-zero */
		if (event->exitcode != 0 && strcmp(udev_device_get_action(event->dev), "remove") != 0)
			udev_queue_export_device_failed(udev_queue_export, event->dev);
		else
			udev_queue_export_device_finished(udev_queue_export, event->dev);
		info(event->udev, "seq %llu done with %i\n", udev_device_get_seqnum(event->dev), event->exitcode);
	}
	udev_device_unref(event->dev);
	free(event);
}

static struct worker *worker_ref(struct worker *worker)
{
	worker->refcount++;
	return worker;
}

static void worker_cleanup(struct worker *worker)
{
	udev_list_node_remove(&worker->node);
	udev_monitor_unref(worker->monitor);
	children--;
	free(worker);
}

static void worker_unref(struct worker *worker)
{
	worker->refcount--;
	if (worker->refcount > 0)
		return;
	info(worker->udev, "worker [%u] cleaned up\n", worker->pid);
	worker_cleanup(worker);
}

static void worker_list_cleanup(struct udev *udev)
{
	struct udev_list_node *loop, *tmp;

	udev_list_node_foreach_safe(loop, tmp, &worker_list) {
		struct worker *worker = node_to_worker(loop);

		worker_cleanup(worker);
	}
}

static void worker_new(struct event *event)
{
	struct udev *udev = event->udev;
	struct worker *worker;
	struct udev_monitor *worker_monitor;
	pid_t pid;

	/* listen for new events */
	worker_monitor = udev_monitor_new_from_netlink(udev, NULL);
	if (worker_monitor == NULL)
		return;
	/* allow the main daemon netlink address to send devices to the worker */
	udev_monitor_allow_unicast_sender(worker_monitor, monitor);
	udev_monitor_enable_receiving(worker_monitor);

	worker = calloc(1, sizeof(struct worker));
	if (worker == NULL) {
		udev_monitor_unref(worker_monitor);
		return;
	}
	/* worker + event reference */
	worker->refcount = 2;
	worker->udev = udev;

	pid = fork();
	switch (pid) {
	case 0: {
		struct udev_device *dev = NULL;
		int fd_monitor;
		struct epoll_event ep_signal, ep_monitor;
		sigset_t mask;
		int rc = EXIT_SUCCESS;

		/* move initial device from queue */
		dev = event->dev;
		event->dev = NULL;

		free(worker);
		worker_list_cleanup(udev);
		event_queue_cleanup(udev, EVENT_UNDEF);
		udev_queue_export_unref(udev_queue_export);
		udev_monitor_unref(monitor);
		udev_ctrl_unref(udev_ctrl);
		close(fd_signal);
		close(fd_ep);
		close(worker_watch[READ_END]);

		sigfillset(&mask);
		fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
		if (fd_signal < 0) {
			err(udev, "error creating signalfd %m\n");
			rc = 2;
			goto out;
		}

		fd_ep = epoll_create1(EPOLL_CLOEXEC);
		if (fd_ep < 0) {
			err(udev, "error creating epoll fd: %m\n");
			rc = 3;
			goto out;
		}

		memset(&ep_signal, 0, sizeof(struct epoll_event));
		ep_signal.events = EPOLLIN;
		ep_signal.data.fd = fd_signal;

		fd_monitor = udev_monitor_get_fd(worker_monitor);
		memset(&ep_monitor, 0, sizeof(struct epoll_event));
		ep_monitor.events = EPOLLIN;
		ep_monitor.data.fd = fd_monitor;

		if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
		    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_monitor, &ep_monitor) < 0) {
			err(udev, "fail to add fds to epoll: %m\n");
			rc = 4;
			goto out;
		}

		/* request TERM signal if parent exits */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		for (;;) {
			struct udev_event *udev_event;
			struct worker_message msg;
			int failed = 0;
			int err;

			info(udev, "seq %llu running\n", udev_device_get_seqnum(dev));
			udev_event = udev_event_new(dev);
			if (udev_event == NULL) {
				rc = 5;
				goto out;
			}

			/* needed for SIGCHLD/SIGTERM in spawn() */
			udev_event->fd_signal = fd_signal;

			if (exec_delay > 0)
				udev_event->exec_delay = exec_delay;

			/* apply rules, create node, symlinks */
			err = udev_event_execute_rules(udev_event, rules, &sigmask_orig);

			if (err == 0)
				failed = udev_event_execute_run(udev_event, &sigmask_orig);

			/* apply/restore inotify watch */
			if (err == 0 && udev_event->inotify_watch) {
				udev_watch_begin(udev, dev);
				udev_device_update_db(dev);
			}

			/* send processed event back to libudev listeners */
			udev_monitor_send_device(worker_monitor, NULL, dev);

			/* send udevd the result of the event execution */
			memset(&msg, 0, sizeof(struct worker_message));
			if (err != 0)
				msg.exitcode = err;
			else if (failed != 0)
				msg.exitcode = failed;
			msg.pid = getpid();
			send(worker_watch[WRITE_END], &msg, sizeof(struct worker_message), 0);

			info(udev, "seq %llu processed with %i\n", udev_device_get_seqnum(dev), err);

			udev_device_unref(dev);
			dev = NULL;

			if (udev_event->sigterm) {
				udev_event_unref(udev_event);
				goto out;
			}

			udev_event_unref(udev_event);

			/* wait for more device messages from main udevd, or term signal */
			while (dev == NULL) {
				struct epoll_event ev[4];
				int fdcount;
				int i;

				fdcount = epoll_wait(fd_ep, ev, ARRAY_SIZE(ev), -1);
				if (fdcount < 0) {
					if (errno == EINTR)
						continue;
					err = -errno;
					err(udev, "failed to poll: %m\n");
					goto out;
				}

				for (i = 0; i < fdcount; i++) {
					if (ev[i].data.fd == fd_monitor && ev[i].events & EPOLLIN) {
						dev = udev_monitor_receive_device(worker_monitor);
					} else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN) {
						struct signalfd_siginfo fdsi;
						ssize_t size;

						size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
						if (size != sizeof(struct signalfd_siginfo))
							continue;
						switch (fdsi.ssi_signo) {
						case SIGTERM:
							goto out;
						}
					}
				}
			}
		}
out:
		udev_device_unref(dev);
		if (fd_signal >= 0)
			close(fd_signal);
		if (fd_ep >= 0)
			close(fd_ep);
		close(fd_inotify);
		close(worker_watch[WRITE_END]);
		udev_rules_unref(rules);
		udev_monitor_unref(worker_monitor);
		udev_unref(udev);
		udev_log_close();
		exit(rc);
	}
	case -1:
		udev_monitor_unref(worker_monitor);
		event->state = EVENT_QUEUED;
		free(worker);
		err(udev, "fork of child failed: %m\n");
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
		info(udev, "seq %llu forked new worker [%u]\n", udev_device_get_seqnum(event->dev), pid);
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

static int event_queue_insert(struct udev_device *dev)
{
	struct event *event;

	event = calloc(1, sizeof(struct event));
	if (event == NULL)
		return -1;

	event->udev = udev_device_get_udev(dev);
	event->dev = dev;
	event->seqnum = udev_device_get_seqnum(dev);
	event->devpath = udev_device_get_devpath(dev);
	event->devpath_len = strlen(event->devpath);
	event->devpath_old = udev_device_get_devpath_old(dev);
	event->devnum = udev_device_get_devnum(dev);
	event->is_block = (strcmp("block", udev_device_get_subsystem(dev)) == 0);
	event->ifindex = udev_device_get_ifindex(dev);

	udev_queue_export_device_queued(udev_queue_export, dev);
	info(event->udev, "seq %llu queued, '%s' '%s'\n", udev_device_get_seqnum(dev),
	     udev_device_get_action(dev), udev_device_get_subsystem(dev));

	event->state = EVENT_QUEUED;
	udev_list_node_append(&event->node, &event_list);

	/* run all events with a timeout set immediately */
	if (udev_device_get_timeout(dev) > 0) {
		event_run(event, true);
		return 0;
	}

	return 0;
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

		/* check network device ifindex */
		if (event->ifindex != 0 && event->ifindex == loop_event->ifindex)
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
			/* devices names might have changed/swapped in the meantime */
			if (major(event->devnum) != 0 && (event->devnum != loop_event->devnum || event->is_block != loop_event->is_block))
				continue;
			if (event->ifindex != 0 && event->ifindex != loop_event->ifindex)
				continue;
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

static void event_queue_start(struct udev *udev)
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

static void event_queue_cleanup(struct udev *udev, enum event_state match_type)
{
	struct udev_list_node *loop, *tmp;

	udev_list_node_foreach_safe(loop, tmp, &event_list) {
		struct event *event = node_to_event(loop);

		if (match_type != EVENT_UNDEF && match_type != event->state)
			continue;

		event_queue_delete(event, false);
	}
}

static void worker_returned(int fd_worker)
{
	for (;;) {
		struct worker_message msg;
		ssize_t size;
		struct udev_list_node *loop;

		size = recv(fd_worker, &msg, sizeof(struct worker_message), MSG_DONTWAIT);
		if (size != sizeof(struct worker_message))
			break;

		/* lookup worker who sent the signal */
		udev_list_node_foreach(loop, &worker_list) {
			struct worker *worker = node_to_worker(loop);

			if (worker->pid != msg.pid)
				continue;

			/* worker returned */
			worker->event->exitcode = msg.exitcode;
			event_queue_delete(worker->event, true);
			worker->event = NULL;
			if (worker->state != WORKER_KILLED)
				worker->state = WORKER_IDLE;
			worker_unref(worker);
			break;
		}
	}
}

/* receive the udevd message from userspace */
static struct udev_ctrl_connection *handle_ctrl_msg(struct udev_ctrl *uctrl)
{
	struct udev *udev = udev_ctrl_get_udev(uctrl);
	struct udev_ctrl_connection *ctrl_conn;
	struct udev_ctrl_msg *ctrl_msg = NULL;
	const char *str;
	int i;

	ctrl_conn = udev_ctrl_get_connection(uctrl);
	if (ctrl_conn == NULL)
		goto out;

	ctrl_msg = udev_ctrl_receive_msg(ctrl_conn);
	if (ctrl_msg == NULL)
		goto out;

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

	if (udev_ctrl_get_ping(ctrl_msg) > 0)
		info(udev, "udevd message (SYNC) received\n");

	if (udev_ctrl_get_exit(ctrl_msg) > 0) {
		info(udev, "udevd message (EXIT) received\n");
		udev_exit = true;
		/* keep reference to block the client until we exit */
		udev_ctrl_connection_ref(ctrl_conn);
	}
out:
	udev_ctrl_msg_unref(ctrl_msg);
	return udev_ctrl_connection_unref(ctrl_conn);
}

/* read inotify messages */
static int handle_inotify(struct udev *udev)
{
	int nbytes, pos;
	char *buf;
	struct inotify_event *ev;

	if ((ioctl(fd_inotify, FIONREAD, &nbytes) < 0) || (nbytes <= 0))
		return 0;

	buf = malloc(nbytes);
	if (buf == NULL) {
		err(udev, "error getting buffer for inotify\n");
		return -1;
	}

	nbytes = read(fd_inotify, buf, nbytes);

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
				if (fd >= 0) {
					if (write(fd, "change", 6) < 0)
						info(udev, "error writing uevent: %m\n");
					close(fd);
				}
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

				if (WIFEXITED(status)) {
					if (WEXITSTATUS(status) != 0)
						err(udev, "worker [%u] exit with return code %i\n", pid, WEXITSTATUS(status));
				} else if (WIFSIGNALED(status)) {
					err(udev, "worker [%u] terminated by signal %i (%s)\n",
					    pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
				} else if (WIFSTOPPED(status)) {
					err(udev, "worker [%u] stopped\n", pid);
				} else if (WIFCONTINUED(status)) {
					err(udev, "worker [%u] continued\n", pid);
				} else {
					err(udev, "worker [%u] exit with status 0x%04x\n", pid, status);
				}

				if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
					if (worker->event != NULL) {
						err(udev, "worker [%u] failed while handling '%s'\n",
						    pid, worker->event->devpath);
						worker->event->exitcode = -32;
						event_queue_delete(worker->event, true);
						/* drop reference taken for state 'running' */
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
		util_create_path_selinux(udev, filename);
		udev_selinux_setfscreatecon(udev, filename, mode);
		info(udev, "mknod '%s' %c%u:%u\n", filename, type, maj, min);
		if (mknod(filename, mode, makedev(maj, min)) < 0 && errno == EEXIST)
			utimensat(AT_FDCWD, filename, NULL, 0);
		udev_selinux_resetfscreatecon(udev);
	}

	fclose(f);
}

static int copy_dev_dir(struct udev *udev, DIR *dir_from, DIR *dir_to, int maxdepth)
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

			copy_dev_dir(udev, dir2_from, dir2_to, maxdepth-1);

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
		struct stat sb;

		if (stat(stdlinks[i].target, &sb) == 0) {
			udev_selinux_setfscreateconat(udev, dirfd(dir), stdlinks[i].link, S_IFLNK);
			if (symlinkat(stdlinks[i].target, dirfd(dir), stdlinks[i].link) < 0 && errno == EEXIST)
				utimensat(dirfd(dir), stdlinks[i].link, NULL, AT_SYMLINK_NOFOLLOW);
			udev_selinux_resetfscreatecon(udev);
		}
	}
}

static void static_dev_create_from_devices(struct udev *udev, DIR *dir)
{
	DIR *dir_from;

	dir_from = opendir(LIBEXECDIR "/devices");
	if (dir_from == NULL)
		return;
	copy_dev_dir(udev, dir_from, dir, 8);
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

static int convert_db(struct udev *udev)
{
	char filename[UTIL_PATH_SIZE];
	FILE *f;
	struct udev_enumerate *udev_enumerate;
	struct udev_list_entry *list_entry;

	/* current database */
	util_strscpyl(filename, sizeof(filename), udev_get_run_path(udev), "/data", NULL);
	if (access(filename, F_OK) >= 0)
		return 0;

	/* make sure we do not get here again */
	util_create_path(udev, filename);
	mkdir(filename, 0755);

	/* old database */
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/db", NULL);
	if (access(filename, F_OK) < 0)
		return 0;

	f = fopen("/dev/kmsg", "w");
	if (f != NULL) {
		fprintf(f, "<30>udevd[%u]: converting old udev database\n", getpid());
		fclose(f);
	}

	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		return -1;
	udev_enumerate_scan_devices(udev_enumerate);
	udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(udev_enumerate)) {
		struct udev_device *device;

		device = udev_device_new_from_syspath(udev, udev_list_entry_get_name(list_entry));
		if (device == NULL)
			continue;

		/* try to find the old database for devices without a current one */
		if (udev_device_read_db(device, NULL) < 0) {
			bool have_db;
			const char *id;
			struct stat stats;
			char devpath[UTIL_PATH_SIZE];
			char from[UTIL_PATH_SIZE];

			have_db = false;

			/* find database in old location */
			id = udev_device_get_id_filename(device);
			util_strscpyl(from, sizeof(from), udev_get_dev_path(udev), "/.udev/db/", id, NULL);
			if (lstat(from, &stats) == 0) {
				if (!have_db) {
					udev_device_read_db(device, from);
					have_db = true;
				}
				unlink(from);
			}

			/* find old database with $subsys:$sysname name */
			util_strscpyl(from, sizeof(from), udev_get_dev_path(udev),
				     "/.udev/db/", udev_device_get_subsystem(device), ":",
				     udev_device_get_sysname(device), NULL);
			if (lstat(from, &stats) == 0) {
				if (!have_db) {
					udev_device_read_db(device, from);
					have_db = true;
				}
				unlink(from);
			}

			/* find old database with the encoded devpath name */
			util_path_encode(udev_device_get_devpath(device), devpath, sizeof(devpath));
			util_strscpyl(from, sizeof(from), udev_get_dev_path(udev), "/.udev/db/", devpath, NULL);
			if (lstat(from, &stats) == 0) {
				if (!have_db) {
					udev_device_read_db(device, from);
					have_db = true;
				}
				unlink(from);
			}

			/* write out new database */
			if (have_db)
				udev_device_update_db(device);
		}
		udev_device_unref(device);
	}
	udev_enumerate_unref(udev_enumerate);
	return 0;
}

static int systemd_fds(struct udev *udev, int *rctrl, int *rnetlink)
{
	int ctrl = -1, netlink = -1;
	int fd, n;

	n = sd_listen_fds(true);
	if (n <= 0)
		return -1;

	for (fd = SD_LISTEN_FDS_START; fd < n + SD_LISTEN_FDS_START; fd++) {
		if (sd_is_socket(fd, AF_LOCAL, SOCK_SEQPACKET, -1)) {
			if (ctrl >= 0)
				return -1;
			ctrl = fd;
			continue;
		}

		if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1)) {
			if (netlink >= 0)
				return -1;
			netlink = fd;
			continue;
		}

		return -1;
	}

	if (ctrl < 0 || netlink < 0)
		return -1;

	info(udev, "ctrl=%i netlink=%i\n", ctrl, netlink);
	*rctrl = ctrl;
	*rnetlink = netlink;
	return 0;
}

int main(int argc, char *argv[])
{
	struct udev *udev;
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
	int fd_ctrl = -1;
	int fd_netlink = -1;
	int fd_worker = -1;
	struct epoll_event ep_ctrl, ep_inotify, ep_signal, ep_netlink, ep_worker;
	struct udev_ctrl_connection *ctrl_conn = NULL;
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("udevd");
	udev_set_log_fn(udev, log_fn);
	info(udev, "version %s\n", VERSION);
	udev_selinux_init(udev);

	/* make sure, that our runtime dir exists and is writable */
	if (utimensat(AT_FDCWD, udev_get_run_config_path(udev), NULL, 0) < 0) {
		/* try to create our own subdirectory, do not create parent directories */
		mkdir(udev_get_run_config_path(udev), 0755);

		if (utimensat(AT_FDCWD, udev_get_run_config_path(udev), NULL, 0) >= 0) {
			/* directory seems writable now */
			udev_set_run_path(udev, udev_get_run_config_path(udev));
		} else {
			/* fall back to /dev/.udev */
			char filename[UTIL_PATH_SIZE];

			util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev", NULL);
			if (udev_set_run_path(udev, filename) == NULL)
				goto exit;
			mkdir(udev_get_run_path(udev), 0755);
			err(udev, "error: runtime directory '%s' not writable, for now falling back to '%s'",
			    udev_get_run_config_path(udev), udev_get_run_path(udev));
		}
	}
	/* relabel runtime dir only if it resides below /dev */
	if (strncmp(udev_get_run_path(udev), udev_get_dev_path(udev), strlen(udev_get_dev_path(udev))) == 0)
		udev_selinux_lsetfilecon(udev, udev_get_run_path(udev), 0755);
	info(udev, "runtime dir '%s'\n", udev_get_run_path(udev));

	for (;;) {
		int option;

		option = getopt_long(argc, argv, "c:deDtN:hV", options, NULL);
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

	/* create standard links, copy static nodes, create nodes from modules */
	static_dev_create(udev);
	static_dev_create_from_modules(udev);

	/* before opening new files, make sure std{in,out,err} fds are in a sane state */
	if (daemonize) {
		int fd;

		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			if (write(STDOUT_FILENO, 0, 0) < 0)
				dup2(fd, STDOUT_FILENO);
			if (write(STDERR_FILENO, 0, 0) < 0)
				dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		} else {
			fprintf(stderr, "cannot open /dev/null\n");
			err(udev, "cannot open /dev/null\n");
		}
	}

	if (systemd_fds(udev, &fd_ctrl, &fd_netlink) >= 0) {
		/* get control and netlink socket from from systemd */
		udev_ctrl = udev_ctrl_new_from_socket_fd(udev, UDEV_CTRL_SOCK_PATH, fd_ctrl);
		if (udev_ctrl == NULL) {
			err(udev, "error taking over udev control socket");
			rc = 1;
			goto exit;
		}

		monitor = udev_monitor_new_from_netlink_fd(udev, "kernel", fd_netlink);
		if (monitor == NULL) {
			err(udev, "error taking over netlink socket\n");
			rc = 3;
			goto exit;
		}
	} else {
		/* open control and netlink socket */
		udev_ctrl = udev_ctrl_new_from_socket(udev, UDEV_CTRL_SOCK_PATH);
		if (udev_ctrl == NULL) {
			fprintf(stderr, "error initializing udev control socket");
			err(udev, "error initializing udev control socket");
			rc = 1;
			goto exit;
		}
		fd_ctrl = udev_ctrl_get_fd(udev_ctrl);

		monitor = udev_monitor_new_from_netlink(udev, "kernel");
		if (monitor == NULL) {
			fprintf(stderr, "error initializing netlink socket\n");
			err(udev, "error initializing netlink socket\n");
			rc = 3;
			goto exit;
		}
		fd_netlink = udev_monitor_get_fd(monitor);
	}

	if (udev_monitor_enable_receiving(monitor) < 0) {
		fprintf(stderr, "error binding netlink socket\n");
		err(udev, "error binding netlink socket\n");
		rc = 3;
		goto exit;
	}

	if (udev_ctrl_enable_receiving(udev_ctrl) < 0) {
		fprintf(stderr, "error binding udev control socket\n");
		err(udev, "error binding udev control socket\n");
		rc = 1;
		goto exit;
	}

	udev_monitor_set_receive_buffer_size(monitor, 128*1024*1024);

	/* create queue file before signalling 'ready', to make sure we block 'settle' */
	udev_queue_export = udev_queue_export_new(udev);
	if (udev_queue_export == NULL) {
		err(udev, "error creating queue file\n");
		goto exit;
	}

	if (daemonize) {
		pid_t pid;
		int fd;

		pid = fork();
		switch (pid) {
		case 0:
			break;
		case -1:
			err(udev, "fork of daemon failed: %m\n");
			rc = 4;
			goto exit;
		default:
			rc = EXIT_SUCCESS;
			goto exit_keep_queue;
		}

		setsid();

		fd = open("/proc/self/oom_score_adj", O_RDWR);
		if (fd < 0) {
			/* Fallback to old interface */
			fd = open("/proc/self/oom_adj", O_RDWR);
			if (fd < 0) {
				err(udev, "error disabling OOM: %m\n");
			} else {
				/* OOM_DISABLE == -17 */
				write(fd, "-17", 3);
				close(fd);
			}
		} else {
			write(fd, "-1000", 5);
			close(fd);
		}
	} else {
		sd_notify(1, "READY=1");
	}

	f = fopen("/dev/kmsg", "w");
	if (f != NULL) {
		fprintf(f, "<30>udevd[%u]: starting version " VERSION "\n", getpid());
		fclose(f);
	}

	if (!debug) {
		int fd;

		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}

	fd_inotify = udev_watch_init(udev);
	if (fd_inotify < 0) {
		fprintf(stderr, "error initializing inotify\n");
		err(udev, "error initializing inotify\n");
		rc = 4;
		goto exit;
	}

	if (udev_get_rules_path(udev) != NULL) {
		inotify_add_watch(fd_inotify, udev_get_rules_path(udev),
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	} else {
		char filename[UTIL_PATH_SIZE];
		struct stat statbuf;

		inotify_add_watch(fd_inotify, LIBEXECDIR "/rules.d",
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		inotify_add_watch(fd_inotify, SYSCONFDIR "/udev/rules.d",
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

		/* watch dynamic rules directory */
		util_strscpyl(filename, sizeof(filename), udev_get_run_path(udev), "/rules.d", NULL);
		if (stat(filename, &statbuf) != 0) {
			util_create_path(udev, filename);
			mkdir(filename, 0755);
		}
		inotify_add_watch(fd_inotify, filename,
				  IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
	}
	udev_watch_restore(udev);

	/* block and listen to all signals on signalfd */
	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
	fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
	if (fd_signal < 0) {
		fprintf(stderr, "error creating signalfd\n");
		err(udev, "error creating signalfd\n");
		rc = 5;
		goto exit;
	}

	/* unnamed socket from workers to the main daemon */
	if (socketpair(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0, worker_watch) < 0) {
		fprintf(stderr, "error creating socketpair\n");
		err(udev, "error creating socketpair\n");
		rc = 6;
		goto exit;
	}
	fd_worker = worker_watch[READ_END];

	rules = udev_rules_new(udev, resolve_names);
	if (rules == NULL) {
		err(udev, "error reading rules\n");
		goto exit;
	}

	memset(&ep_ctrl, 0, sizeof(struct epoll_event));
	ep_ctrl.events = EPOLLIN;
	ep_ctrl.data.fd = fd_ctrl;

	memset(&ep_inotify, 0, sizeof(struct epoll_event));
	ep_inotify.events = EPOLLIN;
	ep_inotify.data.fd = fd_inotify;

	memset(&ep_signal, 0, sizeof(struct epoll_event));
	ep_signal.events = EPOLLIN;
	ep_signal.data.fd = fd_signal;

	memset(&ep_netlink, 0, sizeof(struct epoll_event));
	ep_netlink.events = EPOLLIN;
	ep_netlink.data.fd = fd_netlink;

	memset(&ep_worker, 0, sizeof(struct epoll_event));
	ep_worker.events = EPOLLIN;
	ep_worker.data.fd = fd_worker;

	fd_ep = epoll_create1(EPOLL_CLOEXEC);
	if (fd_ep < 0) {
		err(udev, "error creating epoll fd: %m\n");
		goto exit;
	}
	if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_ctrl, &ep_ctrl) < 0 ||
	    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_inotify, &ep_inotify) < 0 ||
	    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_signal, &ep_signal) < 0 ||
	    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_netlink, &ep_netlink) < 0 ||
	    epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_worker, &ep_worker) < 0) {
		err(udev, "fail to add fds to epoll: %m\n");
		goto exit;
	}

	/* if needed, convert old database from earlier udev version */
	convert_db(udev);

	if (children_max <= 0) {
		int memsize = mem_size_mb();

		/* set value depending on the amount of RAM */
		if (memsize > 0)
			children_max = 128 + (memsize / 8);
		else
			children_max = 128;
	}
	info(udev, "set children_max to %u\n", children_max);

	udev_rules_apply_static_dev_perms(rules);

	udev_list_init(&event_list);
	udev_list_init(&worker_list);

	for (;;) {
		struct epoll_event ev[8];
		int fdcount;
		int timeout;
		bool is_worker, is_signal, is_inotify, is_netlink, is_ctrl;
		int i;

		if (udev_exit) {
			/* close sources of new events and discard buffered events */
			if (fd_ctrl >= 0) {
				epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_ctrl, NULL);
				fd_ctrl = -1;
			}
			if (monitor != NULL) {
				epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_netlink, NULL);
				udev_monitor_unref(monitor);
				monitor = NULL;
			}
			if (fd_inotify >= 0) {
				epoll_ctl(fd_ep, EPOLL_CTL_DEL, fd_inotify, NULL);
				close(fd_inotify);
				fd_inotify = -1;
			}

			/* discard queued events and kill workers */
			event_queue_cleanup(udev, EVENT_QUEUED);
			worker_kill(udev, 0);

			/* exit after all has cleaned up */
			if (udev_list_is_empty(&event_list) && udev_list_is_empty(&worker_list))
				break;

			/* timeout at exit for workers to finish */
			timeout = 60 * 1000;
		} else if (udev_list_is_empty(&event_list) && children > 2) {
			/* set timeout to kill idle workers */
			timeout = 3 * 1000;
		} else {
			timeout = -1;
		}
		fdcount = epoll_wait(fd_ep, ev, ARRAY_SIZE(ev), timeout);
		if (fdcount < 0)
			continue;

		if (fdcount == 0) {
			if (udev_exit) {
				info(udev, "timeout, giving up waiting for workers to finish\n");
				break;
			}

			/* timeout - kill idle workers */
			worker_kill(udev, 2);
		}

		is_worker = is_signal = is_inotify = is_netlink = is_ctrl = false;
		for (i = 0; i < fdcount; i++) {
			if (ev[i].data.fd == fd_worker && ev[i].events & EPOLLIN)
				is_worker = true;
			else if (ev[i].data.fd == fd_netlink && ev[i].events & EPOLLIN)
				is_netlink = true;
			else if (ev[i].data.fd == fd_signal && ev[i].events & EPOLLIN)
				is_signal = true;
			else if (ev[i].data.fd == fd_inotify && ev[i].events & EPOLLIN)
				is_inotify = true;
			else if (ev[i].data.fd == fd_ctrl && ev[i].events & EPOLLIN)
				is_ctrl = true;
		}

		/* event has finished */
		if (is_worker)
			worker_returned(fd_worker);

		if (is_netlink) {
			struct udev_device *dev;

			dev = udev_monitor_receive_device(monitor);
			if (dev != NULL)
				if (event_queue_insert(dev) < 0)
					udev_device_unref(dev);
		}

		/* start new events */
		if (!udev_list_is_empty(&event_list) && !udev_exit && !stop_exec_queue)
			event_queue_start(udev);

		if (is_signal) {
			struct signalfd_siginfo fdsi;
			ssize_t size;

			size = read(fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
			if (size == sizeof(struct signalfd_siginfo))
				handle_signal(udev, fdsi.ssi_signo);
		}

		/* we are shutting down, the events below are not handled anymore */
		if (udev_exit)
			continue;

		/* device node and rules directory inotify watch */
		if (is_inotify)
			handle_inotify(udev);

		/*
		 * This needs to be after the inotify handling, to make sure,
		 * that the ping is send back after the possibly generated
		 * "change" events by the inotify device node watch.
		 *
		 * A single time we may receive a client connection which we need to
		 * keep open to block the client. It will be closed right before we
		 * exit.
		 */
		if (is_ctrl)
			ctrl_conn = handle_ctrl_msg(udev_ctrl);

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

	rc = EXIT_SUCCESS;
exit:
	udev_queue_export_cleanup(udev_queue_export);
exit_keep_queue:
	if (fd_ep >= 0)
		close(fd_ep);
	worker_list_cleanup(udev);
	event_queue_cleanup(udev, EVENT_UNDEF);
	udev_rules_unref(rules);
	if (fd_signal >= 0)
		close(fd_signal);
	if (worker_watch[READ_END] >= 0)
		close(worker_watch[READ_END]);
	if (worker_watch[WRITE_END] >= 0)
		close(worker_watch[WRITE_END]);
	udev_monitor_unref(monitor);
	udev_queue_export_unref(udev_queue_export);
	udev_ctrl_connection_unref(ctrl_conn);
	udev_ctrl_unref(udev_ctrl);
	udev_selinux_exit(udev);
	udev_unref(udev);
	udev_log_close();
	return rc;
}
