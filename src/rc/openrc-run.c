/*
 * openrc-run.c
 * Handle launching of init scripts.
 */

/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) || (defined(__FreeBSD_kernel__) && defined(__GLIBC__)) \
	|| defined(__GNU__)
#  include <pty.h>
#elif defined(__NetBSD__) || defined(__OpenBSD__)
#  include <util.h>
#else
#  include <libutil.h>
#endif

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-misc.h"
#include "rc-plugin.h"
#include "rc-selinux.h"
#include "_usage.h"

#define PREFIX_LOCK	RC_SVCDIR "/prefix.lock"

#define WAIT_INTERVAL	20000000	/* usecs to poll the lock file */
#define WAIT_TIMEOUT	60		/* seconds until we timeout */
#define WARN_TIMEOUT	10		/* warn about this every N seconds */

const char *applet = NULL;
const char *extraopts = "stop | start | restart | describe | zap";
const char *getoptstring = "dDsSvl:Z" getoptstring_COMMON;
const struct option longopts[] = {
	{ "debug",      0, NULL, 'd'},
	{ "dry-run",    0, NULL, 'Z'},
	{ "ifstarted",  0, NULL, 's'},
	{ "ifstopped",  0, NULL, 'S'},
	{ "nodeps",     0, NULL, 'D'},
	{ "lockfd",     1, NULL, 'l'},
	longopts_COMMON
};
const char *const longopts_help[] = {
	"set xtrace when running the script",
	"show what would be done",
	"only run commands when started",
	"only run commands when stopped",
	"ignore dependencies",
	"fd of the exclusive lock from rc",
	longopts_help_COMMON
};
const char *usagestring = NULL;

static char *service, *runlevel, *ibsave, *prefix;
static RC_DEPTREE *deptree;
static RC_STRINGLIST *applet_list, *services, *tmplist;
static RC_STRINGLIST *restart_services;
static RC_STRINGLIST *need_services;
static RC_STRINGLIST *use_services;
static RC_STRINGLIST *want_services;
static RC_HOOK hook_out;
static int exclusive_fd = -1, master_tty = -1;
static bool sighup, in_background, deps, dry_run;
static pid_t service_pid;
static int signal_pipe[2] = { -1, -1 };

static RC_STRINGLIST *deptypes_b;	/* broken deps */
static RC_STRINGLIST *deptypes_n;	/* needed deps */
static RC_STRINGLIST *deptypes_nw;	/* need+want deps */
static RC_STRINGLIST *deptypes_nwu;	/* need+want+use deps */
static RC_STRINGLIST *deptypes_nwua;	/* need+want+use+after deps */
static RC_STRINGLIST *deptypes_m;	/* needed deps for stopping */
static RC_STRINGLIST *deptypes_mwua;	/* need+want+use+after deps for stopping */

static void
handle_signal(int sig)
{
	int serrno = errno;
	char *signame = NULL;
	struct winsize ws;

	switch (sig) {
	case SIGHUP:
		sighup = true;
		break;

	case SIGCHLD:
		if (signal_pipe[1] > -1) {
			if (write(signal_pipe[1], &sig, sizeof(sig)) == -1)
				eerror("%s: send: %s",
				    service, strerror(errno));
		} else
			rc_waitpid(-1);
		break;

	case SIGWINCH:
		if (master_tty >= 0) {
			ioctl(fileno(stdout), TIOCGWINSZ, &ws);
			ioctl(master_tty, TIOCSWINSZ, &ws);
		}
		break;

	case SIGINT:
		if (!signame)
			xasprintf(&signame, "SIGINT");
		/* FALLTHROUGH */
	case SIGTERM:
		if (!signame)
			xasprintf(&signame, "SIGTERM");
		/* FALLTHROUGH */
	case SIGQUIT:
		if (!signame)
			xasprintf(&signame, "SIGQUIT");
		/* Send the signal to our children too */
		if (service_pid > 0)
			kill(service_pid, sig);
		eerror("%s: caught %s, aborting", applet, signame);
		free(signame);
		exit(EXIT_FAILURE);
		/* NOTREACHED */

	default:
		eerror("%s: caught unknown signal %d", applet, sig);
	}

	/* Restore errno */
	errno = serrno;
}

static void
unhotplug()
{
	char *file = NULL;

	xasprintf(&file, RC_SVCDIR "/hotplugged/%s", applet);
	if (exists(file) && unlink(file) != 0)
		eerror("%s: unlink `%s': %s", applet, file, strerror(errno));
	free(file);
}

static void
start_services(RC_STRINGLIST *list)
{
	RC_STRING *svc;
	RC_SERVICE state = rc_service_state (service);

	if (!list)
		return;

	if (state & RC_SERVICE_INACTIVE ||
	    state & RC_SERVICE_WASINACTIVE ||
	    state & RC_SERVICE_STARTING ||
	    state & RC_SERVICE_STARTED)
	{
		TAILQ_FOREACH(svc, list, entries) {
			if (!(rc_service_state(svc->value) &
				RC_SERVICE_STOPPED))
				continue;
			if (state & RC_SERVICE_INACTIVE ||
			    state & RC_SERVICE_WASINACTIVE)
			{
				rc_service_schedule_start(service,
				    svc->value);
				ewarn("WARNING: %s will start when %s has started",
				    svc->value, applet);
			} else
				service_start(svc->value);
		}
	}
}

static void
restore_state(void)
{
	RC_SERVICE state;

	if (rc_in_plugin || exclusive_fd == -1)
		return;
	state = rc_service_state(applet);
	if (state & RC_SERVICE_STOPPING) {
		if (state & RC_SERVICE_WASINACTIVE)
			rc_service_mark(applet, RC_SERVICE_INACTIVE);
		else
			rc_service_mark(applet, RC_SERVICE_STARTED);
		if (rc_runlevel_stopping())
			rc_service_mark(applet, RC_SERVICE_FAILED);
	} else if (state & RC_SERVICE_STARTING) {
		if (state & RC_SERVICE_WASINACTIVE)
			rc_service_mark(applet, RC_SERVICE_INACTIVE);
		else
			rc_service_mark(applet, RC_SERVICE_STOPPED);
		if (rc_runlevel_starting())
			rc_service_mark(applet, RC_SERVICE_FAILED);
	}
	exclusive_fd = svc_unlock(applet, exclusive_fd);
}

static void
cleanup(void)
{
	restore_state();

	if (!rc_in_plugin) {
		if (hook_out) {
			rc_plugin_run(hook_out, applet);
			if (hook_out == RC_HOOK_SERVICE_START_DONE)
				rc_plugin_run(RC_HOOK_SERVICE_START_OUT,
				    applet);
			else if (hook_out == RC_HOOK_SERVICE_STOP_DONE)
				rc_plugin_run(RC_HOOK_SERVICE_STOP_OUT,
				    applet);
		}

		if (restart_services)
			start_services(restart_services);
	}

	rc_plugin_unload();

	rc_stringlist_free(deptypes_b);
	rc_stringlist_free(deptypes_n);
	rc_stringlist_free(deptypes_nw);
	rc_stringlist_free(deptypes_nwu);
	rc_stringlist_free(deptypes_nwua);
	rc_stringlist_free(deptypes_m);
	rc_stringlist_free(deptypes_mwua);
	rc_deptree_free(deptree);
	rc_stringlist_free(restart_services);
	rc_stringlist_free(need_services);
	rc_stringlist_free(use_services);
	rc_stringlist_free(want_services);
	rc_stringlist_free(services);
	rc_stringlist_free(applet_list);
	rc_stringlist_free(tmplist);
	free(ibsave);
	free(service);
	free(prefix);
	free(runlevel);
}

/* Buffer and lock all output messages so that we get readable content */
/* FIXME: Use a dynamic lock file that contains the tty/pts as well.
 * For example openrc-pts8.lock or openrc-tty1.lock.
 * Using a static lock file makes no sense, esp. in multi-user environments.
 * Why don't we use (f)printf, as it is thread-safe through POSIX already?
 * Bug: 360013
 */
static int
write_prefix(const char *buffer, size_t bytes, bool *prefixed)
{
	size_t i, j;
	const char *ec = ecolor(ECOLOR_HILITE);
	const char *ec_normal = ecolor(ECOLOR_NORMAL);
	ssize_t ret = 0;
	int fd = fileno(stdout), lock_fd = -1;

	/*
	 * Lock the prefix.
	 * open() may fail here when running as user, as RC_SVCDIR may not be writable.
	 */
	lock_fd = open(PREFIX_LOCK, O_WRONLY | O_CREAT, 0664);

	if (lock_fd != -1) {
		while (flock(lock_fd, LOCK_EX) != 0) {
			if (errno != EINTR) {
				ewarnv("flock() failed: %s", strerror(errno));
				break;
			}
		}
	}
	else
		ewarnv("Couldn't open the prefix lock, please make sure you have enough permissions");

	for (i = 0; i < bytes; i++) {
		/* We don't prefix eend calls (cursor up) */
		if (buffer[i] == '\033' && !*prefixed) {
			for (j = i + 1; j < bytes; j++) {
				if (buffer[j] == 'A')
					*prefixed = true;
				if (isalpha((unsigned int)buffer[j]))
					break;
			}
		}

		if (!*prefixed) {
			ret += write(fd, ec, strlen(ec));
			ret += write(fd, prefix, strlen(prefix));
			ret += write(fd, ec_normal, strlen(ec_normal));
			ret += write(fd, "|", 1);
			*prefixed = true;
		}

		if (buffer[i] == '\n')
			*prefixed = false;
		ret += write(fd, buffer + i, 1);
	}

	/* Release the lock */
	close(lock_fd);

	return ret;
}

static int
svc_exec(const char *arg1, const char *arg2)
{
	int ret, fdout = fileno(stdout);
	struct termios tt;
	struct winsize ws;
	int i;
	int flags = 0;
	struct pollfd fd[2];
	int s;
	char *buffer;
	size_t bytes;
	bool prefixed = false;
	int slave_tty;
	sigset_t sigchldmask;
	sigset_t oldmask;

	/* Setup our signal pipe */
	if (pipe(signal_pipe) == -1)
		eerrorx("%s: pipe: %s", service, applet);
	for (i = 0; i < 2; i++)
		if ((flags = fcntl(signal_pipe[i], F_GETFD, 0) == -1 ||
			fcntl(signal_pipe[i], F_SETFD, flags | FD_CLOEXEC) == -1))
			eerrorx("%s: fcntl: %s", service, strerror(errno));

	/* Open a pty for our prefixed output
	 * We do this instead of mapping pipes to stdout, stderr so that
	 * programs can tell if they're attached to a tty or not.
	 * The only loss is that we can no longer tell the difference
	 * between the childs stdout or stderr */
	master_tty = slave_tty = -1;
	if (prefix && isatty(fdout)) {
		tcgetattr(fdout, &tt);
		ioctl(fdout, TIOCGWINSZ, &ws);

		/* If the below call fails due to not enough ptys then we don't
		 * prefix the output, but we still work */
		openpty(&master_tty, &slave_tty, NULL, &tt, &ws);
		if (master_tty >= 0 &&
		    (flags = fcntl(master_tty, F_GETFD, 0)) == 0)
			fcntl(master_tty, F_SETFD, flags | FD_CLOEXEC);

		if (slave_tty >=0 &&
		    (flags = fcntl(slave_tty, F_GETFD, 0)) == 0)
			fcntl(slave_tty, F_SETFD, flags | FD_CLOEXEC);
	}

	service_pid = fork();
	if (service_pid == -1)
		eerrorx("%s: fork: %s", service, strerror(errno));
	if (service_pid == 0) {
		if (slave_tty >= 0) {
			dup2(slave_tty, STDOUT_FILENO);
			dup2(slave_tty, STDERR_FILENO);
		}

		if (exists(RC_SVCDIR "/openrc-run.sh")) {
			if (arg2)
				einfov("Executing: %s %s %s %s %s",
					RC_SVCDIR "/openrc-run.sh", RC_SVCDIR "/openrc-run.sh",
					service, arg1, arg2);
			else
				einfov("Executing: %s %s %s %s",
					RC_SVCDIR "/openrc-run.sh", RC_SVCDIR "/openrc-run.sh",
					service, arg1);
			execl(RC_SVCDIR "/openrc-run.sh",
			    RC_SVCDIR "/openrc-run.sh",
			    service, arg1, arg2, (char *) NULL);
			eerror("%s: exec `" RC_SVCDIR "/openrc-run.sh': %s",
			    service, strerror(errno));
			_exit(EXIT_FAILURE);
		} else {
			if (arg2)
				einfov("Executing: %s %s %s %s %s",
					RC_LIBEXECDIR "/sh/openrc-run.sh",
					RC_LIBEXECDIR "/sh/openrc-run.sh",
			    	service, arg1, arg2);
			else
				einfov("Executing: %s %s %s %s",
					RC_LIBEXECDIR "/sh/openrc-run.sh",
					RC_LIBEXECDIR "/sh/openrc-run.sh",
			    	service, arg1);
			execl(RC_LIBEXECDIR "/sh/openrc-run.sh",
			    RC_LIBEXECDIR "/sh/openrc-run.sh",
			    service, arg1, arg2, (char *) NULL);
			eerror("%s: exec `" RC_LIBEXECDIR "/sh/openrc-run.sh': %s",
			    service, strerror(errno));
			_exit(EXIT_FAILURE);
		}
	}

	buffer = xmalloc(sizeof(char) * BUFSIZ);
	fd[0].fd = signal_pipe[0];
	fd[0].events = fd[1].events = POLLIN;
	fd[0].revents = fd[1].revents = 0;
	if (master_tty >= 0) {
		fd[1].fd = master_tty;
		fd[1].events = POLLIN;
		fd[1].revents = 0;
	}

	for (;;) {
		if ((s = poll(fd, master_tty >= 0 ? 2 : 1, -1)) == -1) {
			if (errno != EINTR) {
				eerror("%s: poll: %s",
				    service, strerror(errno));
				break;
			}
		}

		if (s > 0) {
			if (fd[1].revents & (POLLIN | POLLHUP)) {
				bytes = read(master_tty, buffer, BUFSIZ);
				write_prefix(buffer, bytes, &prefixed);
			}

			/* Only SIGCHLD signals come down this pipe */
			if (fd[0].revents & (POLLIN | POLLHUP))
				break;
		}
	}

	free(buffer);

	sigemptyset (&sigchldmask);
	sigaddset (&sigchldmask, SIGCHLD);
	sigprocmask (SIG_BLOCK, &sigchldmask, &oldmask);

	close(signal_pipe[0]);
	close(signal_pipe[1]);
	signal_pipe[0] = signal_pipe[1] = -1;

	sigprocmask (SIG_SETMASK, &oldmask, NULL);

	if (master_tty >= 0) {
		/* Why did we do this? */
		/* signal (SIGWINCH, SIG_IGN); */
		close(master_tty);
		master_tty = -1;
	}

	ret = rc_waitpid(service_pid);
	ret = WEXITSTATUS(ret);
	if (ret != 0 && errno == ECHILD)
		/* killall5 -9 could cause this */
		ret = 0;
	service_pid = 0;

	return ret;
}

static bool
svc_wait(const char *svc)
{
	char *file = NULL;
	int fd;
	bool forever = false;
	RC_STRINGLIST *keywords;
	struct timespec interval, timeout, warn;

	/* Some services don't have a timeout, like fsck */
	keywords = rc_deptree_depend(deptree, svc, "keyword");
	if (rc_stringlist_find(keywords, "-timeout") ||
	    rc_stringlist_find(keywords, "notimeout"))
		forever = true;
	rc_stringlist_free(keywords);

	xasprintf(&file, RC_SVCDIR "/exclusive/%s", basename_c(svc));

	interval.tv_sec = 0;
	interval.tv_nsec = WAIT_INTERVAL;
	timeout.tv_sec = WAIT_TIMEOUT;
	timeout.tv_nsec = 0;
	warn.tv_sec = WARN_TIMEOUT;
	warn.tv_nsec = 0;
	for (;;) {
		fd = open(file, O_RDONLY | O_NONBLOCK);
		if (fd != -1) {
			if (flock(fd, LOCK_SH | LOCK_NB) == 0) {
				close(fd);
				free(file);
				return true;
			}
			close(fd);
		}
		if (errno == ENOENT) {
			free(file);
			return true;
		}
		if (errno != EWOULDBLOCK) {
			eerror("%s: open `%s': %s", applet, file,
			    strerror(errno));
			free(file);
			exit(EXIT_FAILURE);
		}
		if (nanosleep(&interval, NULL) == -1) {
			if (errno != EINTR)
				goto finish;
		}
		if (!forever) {
			timespecsub(&timeout, &interval, &timeout);
			if (timeout.tv_sec <= 0)
				goto finish;
			timespecsub(&warn, &interval, &warn);
			if (warn.tv_sec <= 0) {
				ewarn("%s: waiting for %s (%d seconds)",
				    applet, svc, (int)timeout.tv_sec);
				warn.tv_sec = WARN_TIMEOUT;
				warn.tv_nsec = 0;
			}
		}
	}
finish:
	free(file);
	return false;
}

static void
get_started_services(void)
{
	RC_STRINGLIST *tmp = rc_services_in_state(RC_SERVICE_INACTIVE);

	rc_stringlist_free(restart_services);
	restart_services = rc_services_in_state(RC_SERVICE_STARTED);
	TAILQ_CONCAT(restart_services, tmp, entries);
	free(tmp);
}

static void
setup_deptypes(void)
{
	deptypes_b = rc_stringlist_new();
	rc_stringlist_add(deptypes_b, "broken");

	deptypes_n = rc_stringlist_new();
	rc_stringlist_add(deptypes_n, "ineed");

	deptypes_nw = rc_stringlist_new();
	rc_stringlist_add(deptypes_nw, "ineed");
	rc_stringlist_add(deptypes_nw, "iwant");

	deptypes_nwu = rc_stringlist_new();
	rc_stringlist_add(deptypes_nwu, "ineed");
	rc_stringlist_add(deptypes_nwu, "iwant");
	rc_stringlist_add(deptypes_nwu, "iuse");

	deptypes_nwua = rc_stringlist_new();
	rc_stringlist_add(deptypes_nwua, "ineed");
	rc_stringlist_add(deptypes_nwua, "iwant");
	rc_stringlist_add(deptypes_nwua, "iuse");
	rc_stringlist_add(deptypes_nwua, "iafter");

	deptypes_m = rc_stringlist_new();
	rc_stringlist_add(deptypes_m, "needsme");

	deptypes_mwua = rc_stringlist_new();
	rc_stringlist_add(deptypes_mwua, "needsme");
	rc_stringlist_add(deptypes_mwua, "wantsme");
	rc_stringlist_add(deptypes_mwua, "usesme");
	rc_stringlist_add(deptypes_mwua, "beforeme");
}

static void
svc_start_check(void)
{
	RC_SERVICE state;

	state = rc_service_state(service);

	if (in_background) {
		if (!(state & (RC_SERVICE_INACTIVE | RC_SERVICE_STOPPED)))
			exit(EXIT_FAILURE);
		if (rc_yesno(getenv("IN_HOTPLUG")))
			rc_service_mark(service, RC_SERVICE_HOTPLUGGED);
		if (strcmp(runlevel, RC_LEVEL_SYSINIT) == 0)
			ewarnx("WARNING: %s will be started in the"
			    " next runlevel", applet);
	}

	if (exclusive_fd == -1)
		exclusive_fd = svc_lock(applet);
	if (exclusive_fd == -1) {
		if (errno == EACCES)
			eerrorx("%s: superuser access required", applet);
		if (state & RC_SERVICE_STOPPING)
			ewarnx("WARNING: %s is stopping", applet);
		else
			ewarnx("WARNING: %s is already starting", applet);
	}
	fcntl(exclusive_fd, F_SETFD,
	    fcntl(exclusive_fd, F_GETFD, 0) | FD_CLOEXEC);

	if (state & RC_SERVICE_STARTED) {
		ewarn("WARNING: %s has already been started", applet);
		exit(EXIT_SUCCESS);
	}
	else if (state & RC_SERVICE_INACTIVE && !in_background)
		ewarnx("WARNING: %s has already started, but is inactive",
		    applet);

	rc_service_mark(service, RC_SERVICE_STARTING);
	hook_out = RC_HOOK_SERVICE_START_OUT;
	rc_plugin_run(RC_HOOK_SERVICE_START_IN, applet);
}

static void
svc_start_deps(void)
{
	bool first;
	RC_STRING *svc, *svc2;
	RC_SERVICE state;
	int depoptions = RC_DEP_TRACE, n;
	size_t len;
	char *p, *tmp;
	pid_t pid;

	errno = 0;
	if (rc_conf_yesno("rc_depend_strict") || errno == ENOENT)
		depoptions |= RC_DEP_STRICT;

	if (!deptree && ((deptree = _rc_deptree_load(0, NULL)) == NULL))
		eerrorx("failed to load deptree");
	if (!deptypes_b)
		setup_deptypes();

	services = rc_deptree_depends(deptree, deptypes_b, applet_list,
	    runlevel, 0);
	if (TAILQ_FIRST(services)) {
		eerrorn("ERROR: %s needs service(s) ", applet);
		first = true;
		TAILQ_FOREACH(svc, services, entries) {
			if (first)
				first = false;
			else
				fprintf(stderr, ", ");
			fprintf(stderr, "%s", svc->value);
		}
		fprintf(stderr, "\n");
		exit(EXIT_FAILURE);
	}
	rc_stringlist_free(services);
	services = NULL;

	need_services = rc_deptree_depends(deptree, deptypes_n,
	    applet_list, runlevel, depoptions);
	want_services = rc_deptree_depends(deptree, deptypes_nw,
	    applet_list, runlevel, depoptions);
	use_services = rc_deptree_depends(deptree, deptypes_nwu,
	    applet_list, runlevel, depoptions);

	if (!rc_runlevel_starting()) {
		TAILQ_FOREACH(svc, use_services, entries) {
			state = rc_service_state(svc->value);
			/* Don't stop failed services again.
			 * If you remove this check, ensure that the
			 * exclusive file isn't created. */
			if (state & RC_SERVICE_FAILED &&
			    rc_runlevel_starting())
				continue;
			if (state & RC_SERVICE_STOPPED) {
				if (dry_run) {
					printf(" %s", svc->value);
					continue;
				}
				pid = service_start(svc->value);
				if (!rc_conf_yesno("rc_parallel"))
					rc_waitpid(pid);
			}
		}
	}

	if (dry_run)
		return;

	/* Now wait for them to start */
	services = rc_deptree_depends(deptree, deptypes_nwua, applet_list,
	    runlevel, depoptions);
	/* We use tmplist to hold our scheduled by list */
	tmplist = rc_stringlist_new();
	TAILQ_FOREACH(svc, services, entries) {
		state = rc_service_state(svc->value);
		if (state & RC_SERVICE_STARTED)
			continue;

		/* Don't wait for services which went inactive but are
		 * now in starting state which we are after */
		if (state & RC_SERVICE_STARTING &&
		    state & RC_SERVICE_WASINACTIVE)
		{
			if (!rc_stringlist_find(need_services, svc->value) &&
			    !rc_stringlist_find(want_services, svc->value) &&
			    !rc_stringlist_find(use_services, svc->value))
				continue;
		}

		if (!svc_wait(svc->value))
			eerror("%s: timed out waiting for %s",
			    applet, svc->value);
		state = rc_service_state(svc->value);
		if (state & RC_SERVICE_STARTED)
			continue;
		if (rc_stringlist_find(need_services, svc->value)) {
			if (state & RC_SERVICE_INACTIVE ||
			    state & RC_SERVICE_WASINACTIVE)
			{
				rc_stringlist_add(tmplist, svc->value);
			} else if (!TAILQ_FIRST(tmplist))
				eerrorx("ERROR: cannot start %s as"
				    " %s would not start",
				    applet, svc->value);
		}
	}

	if (TAILQ_FIRST(tmplist)) {
		/* Set the state now, then unlink our exclusive so that
		   our scheduled list is preserved */
		rc_service_mark(service, RC_SERVICE_STOPPED);

		rc_stringlist_free(use_services);
		use_services = NULL;
		len = 0;
		n = 0;
		TAILQ_FOREACH(svc, tmplist, entries) {
			rc_service_schedule_start(svc->value, service);
			use_services = rc_deptree_depend(deptree,
			    "iprovide", svc->value);
			TAILQ_FOREACH(svc2, use_services, entries)
			    rc_service_schedule_start(svc2->value, service);
			rc_stringlist_free(use_services);
			use_services = NULL;
			len += strlen(svc->value) + 2;
			n++;
		}

		len += 5;
		tmp = p = xmalloc(sizeof(char) * len);
		TAILQ_FOREACH(svc, tmplist, entries) {
			if (p != tmp)
				p += snprintf(p, len, ", ");
			p += snprintf(p, len - (p - tmp),
			    "%s", svc->value);
		}
		rc_stringlist_free(tmplist);
		tmplist = NULL;
		ewarnx("WARNING: %s will start when %s has started", applet, tmp);
		free(tmp);
	}

	rc_stringlist_free(tmplist);
	tmplist = NULL;
	rc_stringlist_free(services);
	services = NULL;
}

static void svc_start_real()
{
	bool started;
	RC_STRING *svc, *svc2;

	if (ibsave)
		setenv("IN_BACKGROUND", ibsave, 1);
	hook_out = RC_HOOK_SERVICE_START_DONE;
	rc_plugin_run(RC_HOOK_SERVICE_START_NOW, applet);
	started = (svc_exec("start", NULL) == 0);
	if (ibsave)
		unsetenv("IN_BACKGROUND");

	if (rc_service_state(service) & RC_SERVICE_INACTIVE)
		ewarnx("WARNING: %s has started, but is inactive", applet);
	else if (!started)
		eerrorx("ERROR: %s failed to start", applet);

	rc_service_mark(service, RC_SERVICE_STARTED);
	exclusive_fd = svc_unlock(applet, exclusive_fd);
	hook_out = RC_HOOK_SERVICE_START_OUT;
	rc_plugin_run(RC_HOOK_SERVICE_START_DONE, applet);

	/* Now start any scheduled services */
	services = rc_services_scheduled(service);
	TAILQ_FOREACH(svc, services, entries)
	    if (rc_service_state(svc->value) & RC_SERVICE_STOPPED)
		    service_start(svc->value);
	rc_stringlist_free(services);
	services = NULL;

	/* Do the same for any services we provide */
	if (deptree) {
		tmplist = rc_deptree_depend(deptree, "iprovide", applet);
		TAILQ_FOREACH(svc, tmplist, entries) {
			services = rc_services_scheduled(svc->value);
			TAILQ_FOREACH(svc2, services, entries)
			    if (rc_service_state(svc2->value) &
				RC_SERVICE_STOPPED)
				    service_start(svc2->value);
			rc_stringlist_free(services);
			services = NULL;
		}
		rc_stringlist_free(tmplist);
		tmplist = NULL;
	}

	hook_out = 0;
	rc_plugin_run(RC_HOOK_SERVICE_START_OUT, applet);
}

static void
svc_start(void)
{
	if (dry_run)
		einfon("start:");
	else
		svc_start_check();
	if (deps)
		svc_start_deps();
	if (dry_run)
		printf(" %s\n", applet);
	else
		svc_start_real();
}

static int
svc_stop_check(RC_SERVICE *state)
{
	*state = rc_service_state(service);

	if (rc_runlevel_stopping() && *state & RC_SERVICE_FAILED)
		exit(EXIT_FAILURE);

	if (in_background &&
	    !(*state & RC_SERVICE_STARTED) &&
	    !(*state & RC_SERVICE_INACTIVE))
		exit(EXIT_FAILURE);

	if (exclusive_fd == -1)
		exclusive_fd = svc_lock(applet);
	if (exclusive_fd == -1) {
		if (errno == EACCES)
			eerrorx("%s: superuser access required", applet);
		if (*state & RC_SERVICE_STOPPING)
			ewarnx("WARNING: %s is already stopping", applet);
		eerrorx("ERROR: %s stopped by something else", applet);
	}
	fcntl(exclusive_fd, F_SETFD,
	    fcntl(exclusive_fd, F_GETFD, 0) | FD_CLOEXEC);

	if (*state & RC_SERVICE_STOPPED) {
		ewarn("WARNING: %s is already stopped", applet);
		return 1;
	}

	rc_service_mark(service, RC_SERVICE_STOPPING);
	hook_out = RC_HOOK_SERVICE_STOP_OUT;
	rc_plugin_run(RC_HOOK_SERVICE_STOP_IN, applet);

	if (!rc_runlevel_stopping()) {
		if (rc_service_in_runlevel(service, RC_LEVEL_SYSINIT))
			ewarn("WARNING: you are stopping a sysinit service");
		else if (rc_service_in_runlevel(service, RC_LEVEL_BOOT))
			ewarn("WARNING: you are stopping a boot service");
	}

	return 0;
}

static void
svc_stop_deps(RC_SERVICE state)
{
	int depoptions = RC_DEP_TRACE;
	RC_STRING *svc;
	pid_t pid;

	if (state & RC_SERVICE_WASINACTIVE)
		return;

	errno = 0;
	if (rc_conf_yesno("rc_depend_strict") || errno == ENOENT)
		depoptions |= RC_DEP_STRICT;

	if (!deptree && ((deptree = _rc_deptree_load(0, NULL)) == NULL))
		eerrorx("failed to load deptree");

	if (!deptypes_m)
		setup_deptypes();

	services = rc_deptree_depends(deptree, deptypes_m, applet_list,
	    runlevel, depoptions);
	tmplist = rc_stringlist_new();
	TAILQ_FOREACH_REVERSE(svc, services, rc_stringlist, entries) {
		state = rc_service_state(svc->value);
		/* Don't stop failed services again.
		 * If you remove this check, ensure that the
		 * exclusive file isn't created. */
		if (state & RC_SERVICE_FAILED &&
		    rc_runlevel_stopping())
			continue;
		if (state & RC_SERVICE_STARTED ||
		    state & RC_SERVICE_INACTIVE)
		{
			if (dry_run) {
				printf(" %s", svc->value);
				continue;
			}
			svc_wait(svc->value);
			state = rc_service_state(svc->value);
			if (state & RC_SERVICE_STARTED ||
			    state & RC_SERVICE_INACTIVE)
			{
				pid = service_stop(svc->value);
				if (!rc_conf_yesno("rc_parallel"))
					rc_waitpid(pid);
				rc_stringlist_add(tmplist, svc->value);
			}
		}
	}
	rc_stringlist_free(services);
	services = NULL;
	if (dry_run)
		return;

	TAILQ_FOREACH(svc, tmplist, entries) {
		if (rc_service_state(svc->value) & RC_SERVICE_STOPPED)
			continue;
		svc_wait(svc->value);
		if (rc_service_state(svc->value) & RC_SERVICE_STOPPED)
			continue;
		if (rc_runlevel_stopping()) {
			/* If shutting down, we should stop even
			 * if a dependant failed */
			if (runlevel &&
			    (strcmp(runlevel,
				RC_LEVEL_SHUTDOWN) == 0 ||
				strcmp(runlevel,
				    RC_LEVEL_SINGLE) == 0))
				continue;
			rc_service_mark(service, RC_SERVICE_FAILED);
		}
		eerrorx("ERROR: cannot stop %s as %s "
		    "is still up", applet, svc->value);
	}
	rc_stringlist_free(tmplist);
	tmplist = NULL;

	/* We now wait for other services that may use us and are
	 * stopping. This is important when a runlevel stops */
	services = rc_deptree_depends(deptree, deptypes_mwua, applet_list,
	    runlevel, depoptions);
	TAILQ_FOREACH(svc, services, entries) {
		if (rc_service_state(svc->value) & RC_SERVICE_STOPPED)
			continue;
		svc_wait(svc->value);
	}
	rc_stringlist_free(services);
	services = NULL;
}

static void
svc_stop_real(void)
{
	bool stopped;

	/* If we're stopping localmount, set LC_ALL=C so that
	 * bash doesn't load anything blocking the unmounting of /usr */
	if (strcmp(applet, "localmount") == 0)
		setenv("LC_ALL", "C", 1);

	if (ibsave)
		setenv("IN_BACKGROUND", ibsave, 1);
	hook_out = RC_HOOK_SERVICE_STOP_DONE;
	rc_plugin_run(RC_HOOK_SERVICE_STOP_NOW, applet);
	stopped = (svc_exec("stop", NULL) == 0);
	if (ibsave)
		unsetenv("IN_BACKGROUND");

	if (!stopped)
		eerrorx("ERROR: %s failed to stop", applet);

	if (in_background)
		rc_service_mark(service, RC_SERVICE_INACTIVE);
	else
		rc_service_mark(service, RC_SERVICE_STOPPED);

	hook_out = RC_HOOK_SERVICE_STOP_OUT;
	rc_plugin_run(RC_HOOK_SERVICE_STOP_DONE, applet);
	hook_out = 0;
	rc_plugin_run(RC_HOOK_SERVICE_STOP_OUT, applet);
}

static int
svc_stop(void)
{
	RC_SERVICE state;

	state = 0;
	if (dry_run)
		einfon("stop:");
	else
		if (svc_stop_check(&state) == 1)
			return 1; /* Service has been stopped already */
	if (deps)
		svc_stop_deps(state);
	if (dry_run)
		printf(" %s\n", applet);
	else
		svc_stop_real();

	return 0;
}

static void
svc_restart(void)
{
	/* This is hairly and a better way needs to be found I think!
	 * The issue is this - openvpn need net and dns. net can restart
	 * dns via resolvconf, so you could have openvpn trying to restart
	 * dnsmasq which in turn is waiting on net which in turn is waiting
	 * on dnsmasq.
	 * The work around is for resolvconf to restart its services with
	 * --nodeps which means just that.
	 * The downside is that there is a small window when our status is
	 * invalid.
	 * One workaround would be to introduce a new status,
	 * or status locking. */
	if (!deps) {
		RC_SERVICE state = rc_service_state(service);
		if (state & RC_SERVICE_STARTED || state & RC_SERVICE_INACTIVE)
			svc_exec("stop", "start");
		else
			svc_exec("start", NULL);
		return;
	}

	if (!(rc_service_state(service) & RC_SERVICE_STOPPED)) {
		get_started_services();
		svc_stop();
		if (dry_run)
			ewarn("Cannot calculate restart start dependencies"
			    " on a dry-run");
	}

	svc_start();
	start_services(restart_services);
	rc_stringlist_free(restart_services);
	restart_services = NULL;
}

static bool
service_plugable(void)
{
	char *list, *p, *token;
	bool allow = true, truefalse;
	char *match = rc_conf_value("rc_hotplug");

	if (!match)
		match = rc_conf_value("rc_plug_services");
	if (!match)
		return false;

	list = xstrdup(match);
	p = list;
	while ((token = strsep(&p, " "))) {
		if (token[0] == '!') {
			truefalse = false;
			token++;
		} else
			truefalse = true;

		if (fnmatch(token, applet, 0) == 0) {
			allow = truefalse;
			break;
		}
	}
	free(list);
	return allow;
}

int main(int argc, char **argv)
{
	bool doneone = false;
	bool runscript = false;
	int retval, opt, depoptions = RC_DEP_TRACE;
	RC_STRING *svc;
	char *path = NULL;
	char *lnk = NULL;
	char *dir, *save = NULL, *saveLnk = NULL;
	char *pidstr = NULL;
	size_t l = 0, ll;
 	const char *file;
	struct stat stbuf;

	/* Show help if insufficient args */
	if (argc < 2 || !exists(argv[1])) {
		fprintf(stderr, "openrc-run should not be run directly\n");
		exit(EXIT_FAILURE);
	}

	applet = basename_c(argv[0]);
	if (strcmp(applet, "runscript") == 0)
		runscript = true;

	if (stat(argv[1], &stbuf) != 0) {
		fprintf(stderr, "openrc-run `%s': %s\n",
		    argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	atexit(cleanup);

	/* We need to work out the real full path to our service.
	 * This works fine, provided that we ONLY allow multiplexed services
	 * to exist in the same directory as the master link.
	 * Also, the master link as to be a real file in the init dir. */
	path = realpath(argv[1], NULL);
	if (!path) {
		fprintf(stderr, "realpath: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	lnk = xmalloc(4096);
	memset(lnk, 0, 4096);
	if (readlink(argv[1], lnk, 4096)) {
		dir = dirname(path);
		if (strchr(lnk, '/')) {
			save = xstrdup(dir);
			saveLnk = xstrdup(lnk);
			dir = dirname(saveLnk);
			if (strcmp(dir, save) == 0)
				file = basename_c(argv[1]);
			else
				file = basename_c(lnk);
			dir = save;
		} else
			file = basename_c(argv[1]);
		ll = strlen(dir) + strlen(file) + 2;
		xasprintf(&service, "%s/%s", dir, file);
		if (stat(service, &stbuf) != 0) {
			free(service);
			service = xstrdup(lnk);
		}
		free(save);
		free(saveLnk);
	}
	free(lnk);
	if (!service)
		service = xstrdup(path);
	applet = basename_c(service);

	if (argc < 3)
		usage(EXIT_FAILURE);

	/* Change dir to / to ensure all init scripts don't use stuff in pwd */
	if (chdir("/") == -1)
		eerror("chdir: %s", strerror(errno));

	if ((runlevel = xstrdup(getenv("RC_RUNLEVEL"))) == NULL) {
		env_filter();
		env_config();
		runlevel = rc_runlevel_get();
	}

	setenv("EINFO_LOG", service, 1);
	setenv("RC_SVCNAME", applet, 1);

	/* Set an env var so that we always know our pid regardless of any
	   subshells the init script may create so that our mark_service_*
	   functions can always instruct us of this change */
	xasprintf(&pidstr, "%d", (int) getpid());
	setenv("RC_OPENRC_PID", pidstr, 1);
	/*
	 * RC_RUNSCRIPT_PID is deprecated, but we will keep it for a while
	 * for safety.
	 */
	setenv("RC_RUNSCRIPT_PID", pidstr, 1);

	/* eprefix is kinda klunky, but it works for our purposes */
	if (rc_conf_yesno("rc_parallel")) {
		/* Get the longest service name */
		services = rc_services_in_runlevel(NULL);
		TAILQ_FOREACH(svc, services, entries) {
			ll = strlen(svc->value);
			if (ll > l)
				l = ll;
		}
		rc_stringlist_free(services);
		services = NULL;
		ll = strlen(applet);
		if (ll > l)
			l = ll;

		/* Make our prefix string */
		prefix = xmalloc(sizeof(char) * l + 1);
		ll = strlen(applet);
		memcpy(prefix, applet, ll);
		memset(prefix + ll, ' ', l - ll);
		memset(prefix + l, 0, 1);
		eprefix(prefix);
	}

	/* Ok, we are ready to go, so setup selinux if applicable */
	selinux_setup(argv);

	deps = true;

	/* Punt the first arg as its our service name */
	argc--;
	argv++;

	/* Right then, parse any options there may be */
	while ((opt = getopt_long(argc, argv, getoptstring,
		    longopts, (int *)0)) != -1)
		switch (opt) {
		case 'd':
			setenv("RC_DEBUG", "YES", 1);
			break;
		case 'l':
			exclusive_fd = atoi(optarg);
			fcntl(exclusive_fd, F_SETFD,
			    fcntl(exclusive_fd, F_GETFD, 0) | FD_CLOEXEC);
			break;
		case 's':
			if (!(rc_service_state(service) & RC_SERVICE_STARTED))
				exit(EXIT_FAILURE);
			break;
		case 'S':
			if (!(rc_service_state(service) & RC_SERVICE_STOPPED))
				exit(EXIT_FAILURE);
			break;
		case 'D':
			deps = false;
			break;
		case 'Z':
			dry_run = true;
			break;
		case_RC_COMMON_GETOPT
		}

	/* If we're changing runlevels and not called by rc then we cannot
	   work with any dependencies */
	if (deps && getenv("RC_PID") == NULL &&
	    (rc_runlevel_starting() || rc_runlevel_stopping()))
		deps = false;

	/* Save the IN_BACKGROUND env flag so it's ONLY passed to the service
	   that is being called and not any dependents */
	if (getenv("IN_BACKGROUND")) {
		ibsave = xstrdup(getenv("IN_BACKGROUND"));
		in_background = rc_yesno(ibsave);
		unsetenv("IN_BACKGROUND");
	}

	if (rc_yesno(getenv("IN_HOTPLUG"))) {
		if (!service_plugable())
			eerrorx("%s: not allowed to be hotplugged", applet);
		in_background = true;
	}

	/* Setup a signal handler */
	signal_setup(SIGHUP, handle_signal);
	signal_setup(SIGINT, handle_signal);
	signal_setup(SIGQUIT, handle_signal);
	signal_setup(SIGTERM, handle_signal);
	signal_setup(SIGCHLD, handle_signal);

	/* Load our plugins */
	rc_plugin_load();

	applet_list = rc_stringlist_new();
	rc_stringlist_add(applet_list, applet);

	if (runscript)
		ewarn("%s uses runscript, please convert to openrc-run.", service);

	/* Now run each option */
	retval = EXIT_SUCCESS;
	while (optind < argc) {
		optarg = argv[optind++];

		/* Abort on a sighup here */
		if (sighup)
			exit (EXIT_FAILURE);

		/* Export the command we're running.
		   This is important as we stamp on the restart function now but
		   some start/stop routines still need to behave differently if
		   restarting. */
		unsetenv("RC_CMD");
		setenv("RC_CMD", optarg, 1);

		doneone = true;

		if (strcmp(optarg, "describe") == 0 ||
		    strcmp(optarg, "help") == 0 ||
		    strcmp(optarg, "depend") == 0)
		{
			save = prefix;
			eprefix(NULL);
			prefix = NULL;
			svc_exec(optarg, NULL);
			eprefix(save);
			prefix = save;
		} else if (strcmp(optarg, "ineed") == 0 ||
		    strcmp(optarg, "iuse") == 0 ||
		    strcmp(optarg, "iwant") == 0 ||
		    strcmp(optarg, "needsme") == 0 ||
		    strcmp(optarg, "usesme") == 0 ||
		    strcmp(optarg, "wantsme") == 0 ||
		    strcmp(optarg, "iafter") == 0 ||
		    strcmp(optarg, "ibefore") == 0 ||
		    strcmp(optarg, "iprovide") == 0)
		{
			errno = 0;
			if (rc_conf_yesno("rc_depend_strict") ||
			    errno == ENOENT)
				depoptions |= RC_DEP_STRICT;

			if (!deptree &&
			    ((deptree = _rc_deptree_load(0, NULL)) == NULL))
				eerrorx("failed to load deptree");

			tmplist = rc_stringlist_new();
			rc_stringlist_add(tmplist, optarg);
			services = rc_deptree_depends(deptree, tmplist,
			    applet_list,
			    runlevel, depoptions);
			rc_stringlist_free(tmplist);
			tmplist = NULL;
			TAILQ_FOREACH(svc, services, entries)
			    printf("%s ", svc->value);
			printf ("\n");
			rc_stringlist_free(services);
			services = NULL;
		} else if (strcmp (optarg, "status") == 0) {
			save = prefix;
			eprefix(NULL);
			prefix = NULL;
			retval = svc_exec("status", NULL);
		} else {
			if (strcmp(optarg, "conditionalrestart") == 0 ||
			    strcmp(optarg, "condrestart") == 0)
			{
				if (rc_service_state(service) &
				    RC_SERVICE_STARTED)
					svc_restart();
			} else if (strcmp(optarg, "restart") == 0) {
				svc_restart();
			} else if (strcmp(optarg, "start") == 0) {
				svc_start();
			} else if (strcmp(optarg, "stop") == 0 || strcmp(optarg, "pause") == 0) {
				if (strcmp(optarg, "pause") == 0) {
					ewarn("WARNING: 'pause' is deprecated; please use '--nodeps stop'");
					deps = false;
				}
				if (deps && in_background)
					get_started_services();
				if (svc_stop() == 1)
					continue; /* Service has been stopped already */
				if (deps) {
					if (!in_background &&
					    !rc_runlevel_stopping() &&
					    rc_service_state(service) &
					    RC_SERVICE_STOPPED)
						unhotplug();

					if (in_background &&
					    rc_service_state(service) &
					    RC_SERVICE_INACTIVE)
					{
						TAILQ_FOREACH(svc,
						    restart_services,
						    entries)
						    if (rc_service_state(svc->value) &
							RC_SERVICE_STOPPED)
							    rc_service_schedule_start(service, svc->value);
					}
				}
			} else if (strcmp(optarg, "zap") == 0) {
				einfo("Manually resetting %s to stopped state",
				    applet);
				if (!rc_service_mark(applet,
					RC_SERVICE_STOPPED))
					eerrorx("rc_service_mark: %s",
					    strerror(errno));
				unhotplug();
			} else
				retval = svc_exec(optarg, NULL);

			/* We should ensure this list is empty after
			 * an action is done */
			rc_stringlist_free(restart_services);
			restart_services = NULL;
		}

		if (!doneone)
			usage(EXIT_FAILURE);
	}

	return retval;
}
