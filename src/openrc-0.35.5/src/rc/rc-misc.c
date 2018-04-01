/*
 * rc-misc.c
 * rc misc functions
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

#include <sys/file.h>
#include <sys/types.h>
#include <sys/utsname.h>

#ifdef __linux__
#  include <sys/sysinfo.h>
#endif

#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-misc.h"
#include "version.h"

extern char **environ;

bool
rc_conf_yesno(const char *setting)
{
	return rc_yesno(rc_conf_value (setting));
}

static const char *const env_whitelist[] = {
	"EERROR_QUIET", "EINFO_QUIET",
	"IN_BACKGROUND", "IN_HOTPLUG",
	"LANG", "LC_MESSAGES", "TERM",
	"EINFO_COLOR", "EINFO_VERBOSE",
	NULL
};

void
env_filter(void)
{
	RC_STRINGLIST *env_allow;
	RC_STRINGLIST *profile;
	RC_STRINGLIST *env_list;
	RC_STRING *env;
	char *e;
	size_t i = 0;

	/* Add the user defined list of vars */
	env_allow = rc_stringlist_split(rc_conf_value("rc_env_allow"), " ");
	/*
	 * If '*' is an entry in rc_env_allow, do nothing as we are to pass
	 * through all environment variables.
	 */
	if (rc_stringlist_find(env_allow, "*"))
		return;
	profile = rc_config_load(RC_PROFILE_ENV);

	/* Copy the env and work from this so we can manipulate it safely */
	env_list = rc_stringlist_new();
	while (environ && environ[i]) {
		env = rc_stringlist_add(env_list, environ[i++]);
		e = strchr(env->value, '=');
		if (e)
			*e = '\0';
	}

	TAILQ_FOREACH(env, env_list, entries) {
		/* Check the whitelist */
		for (i = 0; env_whitelist[i]; i++) {
			if (strcmp(env_whitelist[i], env->value) == 0)
				break;
		}
		if (env_whitelist[i])
			continue;

		/* Check our user defined list */
		if (rc_stringlist_find(env_allow, env->value))
			continue;

		/* OK, not allowed! */
		unsetenv(env->value);
	}

	/* Now add anything missing from the profile */
	TAILQ_FOREACH(env, profile, entries) {
		e = strchr(env->value, '=');
		*e = '\0';
		if (!getenv(env->value))
			setenv(env->value, e + 1, 1);
	}

	rc_stringlist_free(env_list);
	rc_stringlist_free(env_allow);
	rc_stringlist_free(profile);
}

void
env_config(void)
{
	size_t pplen = strlen(RC_PATH_PREFIX);
	char *path;
	char *p;
	char *e;
	size_t l;
	struct utsname uts;
	FILE *fp;
	char *token;
	char *np;
	char *npp;
	char *tok;
	const char *sys = rc_sys();
	char *buffer = NULL;
	size_t size = 0;

	/* Ensure our PATH is prefixed with the system locations first
	   for a little extra security */
	path = getenv("PATH");
	if (! path)
		setenv("PATH", RC_PATH_PREFIX, 1);
	else if (strncmp (RC_PATH_PREFIX, path, pplen) != 0) {
		l = strlen(path) + pplen + 3;
		e = p = xmalloc(sizeof(char) * l);
		p += snprintf(p, l, "%s", RC_PATH_PREFIX);

		/* Now go through the env var and only add bits not in our
		 * PREFIX */
		while ((token = strsep(&path, ":"))) {
			np = npp = xstrdup(RC_PATH_PREFIX);
			while ((tok = strsep(&npp, ":")))
				if (strcmp(tok, token) == 0)
					break;
			if (! tok)
				p += snprintf(p, l - (p - e), ":%s", token);
			free (np);
		}
		*p++ = '\0';
		unsetenv("PATH");
		setenv("PATH", e, 1);
		free(e);
	}

	setenv("RC_VERSION", VERSION, 1);
	setenv("RC_LIBEXECDIR", RC_LIBEXECDIR, 1);
	setenv("RC_SVCDIR", RC_SVCDIR, 1);
	setenv("RC_TMPDIR", RC_SVCDIR "/tmp", 1);
	setenv("RC_BOOTLEVEL", RC_LEVEL_BOOT, 1);
	e = rc_runlevel_get();
	setenv("RC_RUNLEVEL", e, 1);
	free(e);

	if ((fp = fopen(RC_KRUNLEVEL, "r"))) {
		if (getline(&buffer, &size, fp) != -1) {
			l = strlen (buffer) - 1;
			if (buffer[l] == '\n')
				buffer[l] = 0;
			setenv("RC_DEFAULTLEVEL", buffer, 1);
		}
		fclose(fp);
	} else
		setenv("RC_DEFAULTLEVEL", RC_LEVEL_DEFAULT, 1);

	free(buffer);
	if (sys)
		setenv("RC_SYS", sys, 1);

#ifdef PREFIX
	setenv("RC_PREFIX", RC_PREFIX, 1);
#endif

	/* Some scripts may need to take a different code path if
	   Linux/FreeBSD, etc
	   To save on calling uname, we store it in an environment variable */
	if (uname(&uts) == 0)
		setenv("RC_UNAME", uts.sysname, 1);

	/* Be quiet or verbose as necessary */
	if (rc_conf_yesno("rc_quiet"))
		setenv("EINFO_QUIET", "YES", 1);
	if (rc_conf_yesno("rc_verbose"))
		setenv("EINFO_VERBOSE", "YES", 1);

	errno = 0;
	if ((! rc_conf_yesno("rc_color") && errno == 0) ||
	    rc_conf_yesno("rc_nocolor"))
		setenv("EINFO_COLOR", "NO", 1);
}

int
signal_setup(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof (sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handler;
	return sigaction(sig, &sa, NULL);
}

int
signal_setup_restart(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof (sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handler;
	sa.sa_flags = SA_RESTART;
	return sigaction(sig, &sa, NULL);
}

int
svc_lock(const char *applet)
{
	char *file = NULL;
	int fd;

	xasprintf(&file, RC_SVCDIR "/exclusive/%s", applet);
	fd = open(file, O_WRONLY | O_CREAT | O_NONBLOCK, 0664);
	free(file);
	if (fd == -1)
		return -1;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		eerror("Call to flock failed: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

int
svc_unlock(const char *applet, int fd)
{
	char *file = NULL;

	xasprintf(&file, RC_SVCDIR "/exclusive/%s", applet);
	close(fd);
	unlink(file);
	free(file);
	return -1;
}

pid_t
exec_service(const char *service, const char *arg)
{
	char *file, sfd[32];
	int fd;
	pid_t pid = -1;
	sigset_t full;
	sigset_t old;
	struct sigaction sa;

	fd = svc_lock(basename_c(service));
	if (fd == -1)
		return -1;

	file = rc_service_resolve(service);
	if (!exists(file)) {
		rc_service_mark(service, RC_SERVICE_STOPPED);
		svc_unlock(basename_c(service), fd);
		free(file);
		return 0;
	}
	snprintf(sfd, sizeof(sfd), "%d", fd);

	/* We need to block signals until we have forked */
	memset(&sa, 0, sizeof (sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);

	if ((pid = fork()) == 0) {
		/* Restore default handlers */
		sigaction(SIGCHLD, &sa, NULL);
		sigaction(SIGHUP, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGUSR1, &sa, NULL);
		sigaction(SIGWINCH, &sa, NULL);

		/* Unmask signals */
		sigprocmask(SIG_SETMASK, &old, NULL);

		/* Safe to run now */
		execl(file, file, "--lockfd", sfd, arg, (char *) NULL);
		fprintf(stderr, "unable to exec `%s': %s\n",
		    file, strerror(errno));
		svc_unlock(basename_c(service), fd);
		_exit(EXIT_FAILURE);
	}

	if (pid == -1) {
		fprintf(stderr, "fork: %s\n",strerror (errno));
		svc_unlock(basename_c(service), fd);
	} else
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);

	sigprocmask(SIG_SETMASK, &old, NULL);
	free(file);
	return pid;
}

int
parse_mode(mode_t *mode, char *text)
{
	char *p;
	unsigned long l;

	/* Check for a numeric mode */
	if ((*text - '0') < 8) {
		l = strtoul(text, &p, 8);
		if (*p || l > 07777U) {
			errno = EINVAL;
			return -1;
		}
		*mode = (mode_t) l;
		return 0;
	}

	/* We currently don't check g+w type stuff */
	errno = EINVAL;
	return -1;
}

int
is_writable(const char *path)
{
	if (access(path, W_OK) == 0)
		return 1;

	return 0;
}

RC_DEPTREE * _rc_deptree_load(int force, int *regen)
{
	int fd;
	int retval;
	int serrno = errno;
	int merrno;
	time_t t;
	char *file = NULL;
	struct stat st;
	struct utimbuf ut;
	FILE *fp;

	t = 0;
	if (rc_deptree_update_needed(&t, file) || force != 0) {
		/* Test if we have permission to update the deptree */
		fd = open(RC_DEPTREE_CACHE, O_WRONLY);
		merrno = errno;
		errno = serrno;
		if (fd == -1 && merrno == EACCES)
			return rc_deptree_load();
		close(fd);

		if (regen)
			*regen = 1;
		ebegin("Caching service dependencies");
		retval = rc_deptree_update() ? 0 : -1;
		eend (retval, "Failed to update the dependency tree");

		if (retval == 0) {
			if (stat(RC_DEPTREE_CACHE, &st) != 0) {
				eerror("stat(%s): %s", RC_DEPTREE_CACHE, strerror(errno));
				return NULL;
			}
			if (st.st_mtime < t) {
				eerror("Clock skew detected with `%s'", file);
				eerrorn("Adjusting mtime of `" RC_DEPTREE_CACHE
				    "' to %s", ctime(&t));
				fp = fopen(RC_DEPTREE_SKEWED, "w");
				if (fp != NULL) {
					fprintf(fp, "%s\n", file);
					fclose(fp);
				}
				ut.actime = t;
				ut.modtime = t;
				utime(RC_DEPTREE_CACHE, &ut);
			} else {
				if (exists(RC_DEPTREE_SKEWED))
					unlink(RC_DEPTREE_SKEWED);
			}
		}
		if (force == -1 && regen != NULL)
			*regen = retval;
	}
	return rc_deptree_load();
}

bool _rc_can_find_pids(void)
{
	RC_PIDLIST *pids;
	RC_PID *pid;
	RC_PID *pid2;
	bool retval = false;

	if (geteuid() == 0)
		return true;

	/* If we cannot see process 1, then we don't test to see if
	 * services crashed or not */
	pids = rc_find_pids(NULL, NULL, 0, 1);
	if (pids) {
		pid = LIST_FIRST(pids);
		if (pid) {
			retval = true;
			while (pid) {
				pid2 = LIST_NEXT(pid, entries);
				free(pid);
				pid = pid2;
			}
		}
		free(pids);
	}
	return retval;
}

static const struct {
	const char * const name;
	RC_SERVICE bit;
} service_bits[] = {
	{ "service_started",     RC_SERVICE_STARTED,     },
	{ "service_stopped",     RC_SERVICE_STOPPED,     },
	{ "service_inactive",    RC_SERVICE_INACTIVE,    },
	{ "service_starting",    RC_SERVICE_STARTING,    },
	{ "service_stopping",    RC_SERVICE_STOPPING,    },
	{ "service_hotplugged",  RC_SERVICE_HOTPLUGGED,  },
	{ "service_wasinactive", RC_SERVICE_WASINACTIVE, },
	{ "service_failed",      RC_SERVICE_FAILED,      },
};

RC_SERVICE lookup_service_state(const char *service)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(service_bits); ++i)
		if (!strcmp(service, service_bits[i].name))
			return service_bits[i].bit;
	return 0;
}

void from_time_t(char *time_string, time_t tv)
{
	strftime(time_string, 20, "%Y-%m-%d %H:%M:%S", localtime(&tv));
}

time_t to_time_t(char *timestring)
{
	int check = 0;
	int year = 0;
	int month = 0;
	int day = 0;
	int hour = 0;
	int min = 0;
	int sec = 0;
	struct tm breakdown = {0};
	time_t result = -1;

	check = sscanf(timestring, "%4d-%2d-%2d %2d:%2d:%2d",
			&year, &month, &day, &hour, &min, &sec);
	if (check == 6) {
		breakdown.tm_year = year - 1900; /* years since 1900 */
		breakdown.tm_mon = month - 1;
		breakdown.tm_mday = day;
		breakdown.tm_hour = hour;
		breakdown.tm_min = min;
		breakdown.tm_sec = sec;
		breakdown.tm_isdst = -1;
		result = mktime(&breakdown);
	}
	return result;
}

pid_t get_pid(const char *applet,const char *pidfile)
{
	FILE *fp;
	pid_t pid;

	if (! pidfile)
		return -1;

	if ((fp = fopen(pidfile, "r")) == NULL) {
		ewarnv("%s: fopen `%s': %s", applet, pidfile, strerror(errno));
		return -1;
	}

	if (fscanf(fp, "%d", &pid) != 1) {
		ewarnv("%s: no pid found in `%s'", applet, pidfile);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return pid;
}
