/*
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
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
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#endif

#include "udev.h"

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

/* maximum limit of forked childs */
#define UDEVD_MAX_CHILDS		256

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

static void reap_sigchilds(void);

static int debug_trace;
static struct udev_rules *rules;
static struct udev_ctrl *udev_ctrl;
static struct udev_monitor *kernel_monitor;
static volatile sig_atomic_t sigchilds_waiting;
static volatile sig_atomic_t udev_exit;
static volatile sig_atomic_t reload_config;
static volatile sig_atomic_t signal_received;
static volatile pid_t settle_pid;
static int run_exec_q;
static int stop_exec_q;
static int max_childs;
static int childs;
static struct udev_list_node event_list;

enum event_state {
	EVENT_QUEUED,
	EVENT_FINISHED,
	EVENT_FAILED,
};

static struct udev_event *node_to_event(struct udev_list_node *node)
{
	char *event;

	event = (char *)node;
	event -= offsetof(struct udev_event, node);
	return (struct udev_event *)event;
}

static void export_event_state(struct udev_event *event, enum event_state state)
{
	char filename[UTIL_PATH_SIZE];
	char filename_failed[UTIL_PATH_SIZE];
	char *s;
	size_t l;

	/* location of queue file */
	snprintf(filename, sizeof(filename), "%s/.udev/queue/%llu",
		 udev_get_dev_path(event->udev), udev_device_get_seqnum(event->dev));

	/* location of failed file */
	s = filename_failed;
	l = util_strpcpyl(&s, sizeof(filename_failed), udev_get_dev_path(event->udev), "/.udev/failed/", NULL);
	util_path_encode(udev_device_get_devpath(event->dev), s, l);

	switch (state) {
	case EVENT_QUEUED:
		if(unlink(filename_failed) == 0)
			util_delete_path(event->udev, filename_failed);
		util_create_path(event->udev, filename);
		udev_selinux_setfscreatecon(event->udev, filename, S_IFLNK);
		symlink(udev_device_get_devpath(event->dev), filename);
		udev_selinux_resetfscreatecon(event->udev);
		break;
	case EVENT_FINISHED:
		if (udev_device_get_devpath_old(event->dev) != NULL) {
			/* "move" event - rename failed file to current name, do not delete failed */
			char filename_failed_old[UTIL_PATH_SIZE];

			s = filename_failed_old;
			l = util_strpcpyl(&s, sizeof(filename_failed_old), udev_get_dev_path(event->udev), "/.udev/failed/", NULL);
			util_path_encode(udev_device_get_devpath_old(event->dev), s, l);
			if (rename(filename_failed_old, filename_failed) == 0)
				info(event->udev, "renamed devpath, moved failed state of '%s' to %s'\n",
				     udev_device_get_devpath_old(event->dev), udev_device_get_devpath(event->dev));
		} else {
			if (unlink(filename_failed) == 0)
				util_delete_path(event->udev, filename_failed);
		}

		unlink(filename);

		/* clean up possibly empty queue directory */
		if (udev_list_is_empty(&event_list))
			util_delete_path(event->udev, filename);
		break;
	case EVENT_FAILED:
		/* move failed event to the failed directory */
		util_create_path(event->udev, filename_failed);
		rename(filename, filename_failed);

		/* clean up possibly empty queue directory */
		if (udev_list_is_empty(&event_list))
			util_delete_path(event->udev, filename);
		break;
	}

	return;
}

static void event_queue_delete(struct udev_event *event)
{
	udev_list_node_remove(&event->node);

	/* mark as failed, if "add" event returns non-zero */
	if (event->exitstatus && strcmp(udev_device_get_action(event->dev), "add") == 0)
		export_event_state(event, EVENT_FAILED);
	else
		export_event_state(event, EVENT_FINISHED);

	udev_device_unref(event->dev);
	udev_event_unref(event);
}

static void event_sig_handler(int signum)
{
	if (signum == SIGALRM)
		_exit(1);
}

static void event_fork(struct udev_event *event)
{
	pid_t pid;
	struct sigaction act;
	int err;

#if 0
	/* single process, no forking, just for testing/profiling */
	err = udev_event_execute_rules(event, rules);
	if (err == 0 && !event->ignore_device && udev_get_run(event->udev))
		udev_event_execute_run(event);
	info(event->udev, "seq %llu exit with %i\n", udev_device_get_seqnum(event->dev), err);
	event_queue_delete(event);
	return;
#endif

	if (debug_trace) {
		event->trace = 1;
		fprintf(stderr, "fork %s (%llu)\n",
		       udev_device_get_syspath(event->dev),
		       udev_device_get_seqnum(event->dev));
	}

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		udev_ctrl_unref(udev_ctrl);
		logging_close();
		logging_init("udevd-event");
		setpriority(PRIO_PROCESS, 0, UDEV_PRIORITY);

		/* set signal handlers */
		memset(&act, 0x00, sizeof(act));
		act.sa_handler = event_sig_handler;
		sigemptyset (&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGALRM, &act, NULL);

		/* reset to default */
		act.sa_handler = SIG_DFL;
		sigaction(SIGINT, &act, NULL);
		sigaction(SIGTERM, &act, NULL);
		sigaction(SIGCHLD, &act, NULL);
		sigaction(SIGHUP, &act, NULL);

		/* set timeout to prevent hanging processes */
		alarm(UDEV_EVENT_TIMEOUT);

		/* apply rules, create node, symlinks */
		err = udev_event_execute_rules(event, rules);

		/* rules may change/disable the timeout */
		if (udev_device_get_event_timeout(event->dev) >= 0)
			alarm(udev_device_get_event_timeout(event->dev));

		/* execute RUN= */
		if (err == 0 && !event->ignore_device && udev_get_run(event->udev))
			udev_event_execute_run(event);

		/* apply/restore inotify watch */
		if (err == 0 && event->inotify_watch) {
			udev_watch_begin(event->udev, event->dev);
			udev_device_update_db(event->dev);
		}

		/* send processed event back to the kernel netlink socket */
		udev_monitor_send_device(kernel_monitor, event->dev);

		info(event->udev, "seq %llu exit with %i\n", udev_device_get_seqnum(event->dev), err);
		logging_close();
		if (err != 0)
			exit(1);
		exit(0);
	case -1:
		err(event->udev, "fork of child failed: %m\n");
		event_queue_delete(event);
		break;
	default:
		/* get SIGCHLD in main loop */
		info(event->udev, "seq %llu forked, pid [%d], '%s' '%s', %ld seconds old\n",
		     udev_device_get_seqnum(event->dev),
		     pid,
		     udev_device_get_action(event->dev),
		     udev_device_get_subsystem(event->dev),
		     time(NULL) - event->queue_time);
		event->pid = pid;
		childs++;
	}
}

static void event_queue_insert(struct udev_event *event)
{
	char filename[UTIL_PATH_SIZE];
	int fd;

	event->queue_time = time(NULL);

	export_event_state(event, EVENT_QUEUED);
	info(event->udev, "seq %llu queued, '%s' '%s'\n", udev_device_get_seqnum(event->dev),
	     udev_device_get_action(event->dev), udev_device_get_subsystem(event->dev));

	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(event->udev), "/.udev/uevent_seqnum", NULL);
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		char str[32];
		int len;

		len = sprintf(str, "%llu\n", udev_device_get_seqnum(event->dev));
		write(fd, str, len);
		close(fd);
	}


	udev_list_node_append(&event->node, &event_list);
	run_exec_q = 1;

	/* run all events with a timeout set immediately */
	if (udev_device_get_timeout(event->dev) > 0) {
		event_fork(event);
		return;
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

static int compare_devpath(const char *running, const char *waiting)
{
	int i = 0;

	while (running[i] != '\0' && running[i] == waiting[i])
		i++;

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
	return 0;
}

/* lookup event for identical, parent, child device */
static int devpath_busy(struct udev_event *event)
{
	struct udev_list_node *loop;

	/* check if queue contains events we depend on */
	udev_list_node_foreach(loop, &event_list) {
		struct udev_event *loop_event = node_to_event(loop);

		/* we already found a later event, earlier can not block us, no need to check again */
		if (udev_device_get_seqnum(loop_event->dev) < event->delaying_seqnum)
			continue;

		/* event we checked earlier still exists, no need to check again */
		if (udev_device_get_seqnum(loop_event->dev) == event->delaying_seqnum)
			return 2;

		/* found ourself, no later event can block us */
		if (udev_device_get_seqnum(loop_event->dev) >= udev_device_get_seqnum(event->dev))
			break;

		/* check our old name */
		if (udev_device_get_devpath_old(event->dev) != NULL)
			if (strcmp(udev_device_get_devpath(loop_event->dev), udev_device_get_devpath_old(event->dev)) == 0) {
				event->delaying_seqnum = udev_device_get_seqnum(loop_event->dev);
				return 3;
			}

		/* check identical, parent, or child device event */
		if (compare_devpath(udev_device_get_devpath(loop_event->dev), udev_device_get_devpath(event->dev)) != 0) {
			dbg(event->udev, "%llu, device event still pending %llu (%s)\n",
			    udev_device_get_seqnum(event->dev),
			    udev_device_get_seqnum(loop_event->dev),
			    udev_device_get_devpath(loop_event->dev));
			event->delaying_seqnum = udev_device_get_seqnum(loop_event->dev);
			return 4;
		}

		/* check for our major:minor number */
		if (major(udev_device_get_devnum(event->dev)) > 0 &&
		    udev_device_get_devnum(loop_event->dev) == udev_device_get_devnum(event->dev) &&
		    strcmp(udev_device_get_subsystem(event->dev), udev_device_get_subsystem(loop_event->dev)) == 0) {
			dbg(event->udev, "%llu, device event still pending %llu (%d:%d)\n",
			    udev_device_get_seqnum(event->dev),
			    udev_device_get_seqnum(loop_event->dev),
			    major(udev_device_get_devnum(loop_event->dev)), minor(udev_device_get_devnum(loop_event->dev)));
			event->delaying_seqnum = udev_device_get_seqnum(loop_event->dev);
			return 5;
		}
	}
	return 0;
}

/* serializes events for the identical and parent and child devices */
static void event_queue_manager(struct udev *udev)
{
	struct udev_list_node *loop;
	struct udev_list_node *tmp;

start_over:
	if (udev_list_is_empty(&event_list)) {
		if (childs > 0) {
			err(udev, "event list empty, but childs count is %i", childs);
			childs = 0;
		}
		return;
	}

	udev_list_node_foreach_safe(loop, tmp, &event_list) {
		struct udev_event *loop_event = node_to_event(loop);

		if (childs >= max_childs) {
			info(udev, "maximum number (%i) of childs reached\n", childs);
			break;
		}

		if (loop_event->pid != 0)
			continue;

		/* do not start event if parent or child event is still running */
		if (devpath_busy(loop_event) != 0) {
			dbg(udev, "delay seq %llu (%s)\n",
			    udev_device_get_seqnum(loop_event->dev),
			    udev_device_get_devpath(loop_event->dev));
			continue;
		}

		event_fork(loop_event);
		dbg(udev, "moved seq %llu to running list\n", udev_device_get_seqnum(loop_event->dev));

		/* retry if events finished in the meantime */
		if (sigchilds_waiting) {
			sigchilds_waiting = 0;
			reap_sigchilds();
			goto start_over;
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
	}

	if (udev_ctrl_get_stop_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (STOP_EXEC_QUEUE) received\n");
		stop_exec_q = 1;
	}

	if (udev_ctrl_get_start_exec_queue(ctrl_msg) > 0) {
		info(udev, "udevd message (START_EXEC_QUEUE) received\n");
		stop_exec_q = 0;
		event_queue_manager(udev);
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
	}

	i = udev_ctrl_get_set_max_childs(ctrl_msg);
	if (i >= 0) {
		info(udev, "udevd message (SET_MAX_CHILDS) received, max_childs=%i\n", i);
		max_childs = i;
	}

	settle_pid = udev_ctrl_get_settle(ctrl_msg);
	if (settle_pid > 0) {
		info(udev, "udevd message (SETTLE) received\n");
	}
	udev_ctrl_msg_unref(ctrl_msg);
}

/* read inotify messages */
static int handle_inotify(struct udev *udev)
{
	int nbytes, pos;
	char *buf;
	struct inotify_event *ev;

	if ((ioctl(inotify_fd, FIONREAD, &nbytes) < 0) || (nbytes <= 0))
		return 0;

	buf = malloc(nbytes);
	if (buf == NULL) {
		err(udev, "error getting buffer for inotify, disable watching\n");
		close(inotify_fd);
		inotify_fd = -1;
		return 0;
	}

	read(inotify_fd, buf, nbytes);

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

	free (buf);
	return 0;
}

static void sig_handler(int signum)
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

	signal_received = 1;
}

static void udev_done(int pid, int exitstatus)
{
	struct udev_list_node *loop;

	/* find event associated with pid and delete it */
	udev_list_node_foreach(loop, &event_list) {
		struct udev_event *loop_event = node_to_event(loop);

		if (loop_event->pid == pid) {
			info(loop_event->udev, "seq %llu cleanup, pid [%d], status %i, %ld seconds old\n",
			     udev_device_get_seqnum(loop_event->dev), loop_event->pid,
			     exitstatus, time(NULL) - loop_event->queue_time);
			loop_event->exitstatus = exitstatus;
			if (debug_trace)
				fprintf(stderr, "exit %s (%llu)\n",
				       udev_device_get_syspath(loop_event->dev),
				       udev_device_get_seqnum(loop_event->dev));
			event_queue_delete(loop_event);
			childs--;

			/* there may be dependent events waiting */
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

static void cleanup_queue_dir(struct udev *udev)
{
	char dirname[UTIL_PATH_SIZE];
	char filename[UTIL_PATH_SIZE];
	DIR *dir;

	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/uevent_seqnum", NULL);
	unlink(filename);

	util_strscpyl(dirname, sizeof(dirname), udev_get_dev_path(udev), "/.udev/queue", NULL);
	dir = opendir(dirname);
	if (dir != NULL) {
		while (1) {
			struct dirent *dent;

			dent = readdir(dir);
			if (dent == NULL || dent->d_name[0] == '\0')
				break;
			if (dent->d_name[0] == '.')
				continue;
			unlinkat(dirfd(dir), dent->d_name, 0);
		}
		closedir(dir);
		rmdir(dirname);
	}
}

static void export_initial_seqnum(struct udev *udev)
{
	char filename[UTIL_PATH_SIZE];
	int fd;
	char seqnum[32];
	ssize_t len = 0;

	util_strscpyl(filename, sizeof(filename), udev_get_sys_path(udev), "/kernel/uevent_seqnum", NULL);
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
	}
	if (len <= 0) {
		strcpy(seqnum, "0\n");
		len = 3;
	}
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/uevent_seqnum", NULL);
	util_create_path(udev, filename);
	fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if (fd >= 0) {
		write(fd, seqnum, len);
		close(fd);
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
	struct sigaction act;
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

	logging_init("udevd");
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

	kernel_monitor = udev_monitor_new_from_netlink(udev, "kernel");
	if (kernel_monitor == NULL || udev_monitor_enable_receiving(kernel_monitor) < 0) {
		fprintf(stderr, "error initializing netlink socket\n");
		err(udev, "error initializing netlink socket\n");
		rc = 3;
		goto exit;
	}
	udev_monitor_set_receive_buffer_size(kernel_monitor, 128*1024*1024);

	rules = udev_rules_new(udev, resolve_names);
	if (rules == NULL) {
		err(udev, "error reading rules\n");
		goto exit;
	}
	udev_list_init(&event_list);
	cleanup_queue_dir(udev);
	export_initial_seqnum(udev);

	if (daemonize) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			dbg(udev, "daemonized fork running\n");
			break;
		case -1:
			err(udev, "fork of daemon failed: %m\n");
			rc = 4;
			goto exit;
		default:
			dbg(udev, "child [%u] running, parent exits\n", pid);
			rc = 0;
			goto exit;
		}
	}

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
	if (fd < 0)
		err(udev, "error disabling OOM: %m\n");
	else {
		write(fd, "-17", 3);
		close(fd);
	}

	startup_log(udev);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(struct sigaction));
	act.sa_handler = sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	/* watch rules directory */
	udev_watch_init(udev);
	if (inotify_fd >= 0) {
		if (udev_get_rules_path(udev) != NULL) {
			inotify_add_watch(inotify_fd, udev_get_rules_path(udev),
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		} else {
			char filename[UTIL_PATH_SIZE];

			inotify_add_watch(inotify_fd, UDEV_PREFIX "/lib/udev/rules.d",
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
			inotify_add_watch(inotify_fd, SYSCONFDIR "/udev/rules.d",
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);

			/* watch dynamic rules directory */
			util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/rules.d", NULL);
			inotify_add_watch(inotify_fd, filename,
					  IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE_WRITE);
		}

		udev_watch_restore(udev);
	}

	/* in trace mode run one event after the other */
	if (debug_trace) {
		max_childs = 1;
	} else {
		int memsize = mem_size_mb();
		if (memsize > 0)
			max_childs = 128 + (memsize / 4);
		else
			max_childs = UDEVD_MAX_CHILDS;
	}
	/* possibly overwrite maximum limit of executed events */
	value = getenv("UDEVD_MAX_CHILDS");
	if (value)
		max_childs = strtoul(value, NULL, 10);
	info(udev, "initialize max_childs to %u\n", max_childs);

	while (!udev_exit) {
		sigset_t blocked_mask, orig_mask;
		struct pollfd pfd[4];
		struct pollfd *ctrl_poll, *monitor_poll, *inotify_poll = NULL;
		int nfds = 0;
		int fdcount;

		sigfillset(&blocked_mask);
		sigprocmask(SIG_SETMASK, &blocked_mask, &orig_mask);
		if (signal_received) {
			sigprocmask(SIG_SETMASK, &orig_mask, NULL);
			goto handle_signals;
		}

		ctrl_poll = &pfd[nfds++];
		ctrl_poll->fd = udev_ctrl_get_fd(udev_ctrl);
		ctrl_poll->events = POLLIN;

		monitor_poll = &pfd[nfds++];
		monitor_poll->fd = udev_monitor_get_fd(kernel_monitor);
		monitor_poll->events = POLLIN;

		if (inotify_fd >= 0) {
			inotify_poll = &pfd[nfds++];
			inotify_poll->fd = inotify_fd;
			inotify_poll->events = POLLIN;
		}

		fdcount = ppoll(pfd, nfds, NULL, &orig_mask);
		sigprocmask(SIG_SETMASK, &orig_mask, NULL);
		if (fdcount < 0) {
			if (errno == EINTR)
				goto handle_signals;
			err(udev, "error in select: %m\n");
			continue;
		}

		/* get control message */
		if (ctrl_poll->revents & POLLIN)
			handle_ctrl_msg(udev_ctrl);

		/* get kernel uevent */
		if (monitor_poll->revents & POLLIN) {
			struct udev_device *dev;

			dev = udev_monitor_receive_device(kernel_monitor);
			if (dev != NULL) {
				struct udev_event *event;

				event = udev_event_new(dev);
				if (event != NULL)
					event_queue_insert(event);
				else
					udev_device_unref(dev);
			}
		}

		/* rules directory inotify watch */
		if (inotify_poll && (inotify_poll->revents & POLLIN))
			handle_inotify(udev);

handle_signals:
		signal_received = 0;

		/* rules changed, set by inotify or a HUP signal */
		if (reload_config) {
			struct udev_rules *rules_new;

			reload_config = 0;
			rules_new = udev_rules_new(udev, resolve_names);
			if (rules_new != NULL) {
				udev_rules_unref(rules);
				rules = rules_new;
			}
		}

		if (sigchilds_waiting) {
			sigchilds_waiting = 0;
			reap_sigchilds();
		}

		if (run_exec_q) {
			run_exec_q = 0;
			if (!stop_exec_q)
				event_queue_manager(udev);
		}

		if (settle_pid > 0) {
			kill(settle_pid, SIGUSR1);
			settle_pid = 0;
		}
	}
	cleanup_queue_dir(udev);
	rc = 0;
exit:
	udev_rules_unref(rules);
	udev_ctrl_unref(udev_ctrl);
	if (inotify_fd >= 0)
		close(inotify_fd);
	udev_monitor_unref(kernel_monitor);
	udev_selinux_exit(udev);
	udev_unref(udev);
	logging_close();
	return rc;
}
