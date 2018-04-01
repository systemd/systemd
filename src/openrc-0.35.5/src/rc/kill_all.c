/*
 * kill_all.c
 * Sends a signal to all processes on the system.
 */

/*
 * Copyright (c) 2017 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */


#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "einfo.h"
#include "rc.h"
#include "rc-misc.h"
#include "_usage.h"

const char *applet = NULL;
const char *extraopts = "[signal number]";
const char *getoptstring = "do:" getoptstring_COMMON;
const struct option longopts[] = {
	{ "dry-run",        0, NULL, 'd' },
	{ "omit",        1, NULL, 'o' },
	longopts_COMMON
};
const char * const longopts_help[] = {
	"print what would be done",
	"omit this pid (can be repeated)",
	longopts_help_COMMON
};
const char *usagestring = NULL;

static int mount_proc(void)
{
	pid_t pid;
	pid_t rc;
	int status;

	if (exists("/proc/version"))
		return 0;
	pid = fork();
	switch(pid) {
		case -1:
			syslog(LOG_ERR, "Unable to fork");
			return -1;
			break;
		case 0:
			/* attempt to mount /proc */
			execlp("mount", "mount", "-t", "proc", "proc", "/proc", NULL);
			syslog(LOG_ERR, "Unable to execute mount");
			exit(1);
			break;
		default:
			/* wait for child process */
			while ((rc = wait(&status)) != pid)
				if (rc < 0 && errno == ECHILD)
					break;
			if (rc != pid || WEXITSTATUS(status) != 0)
				syslog(LOG_ERR, "mount returned non-zero exit status");
			break;
	}
	if (! exists("/proc/version")) {
		syslog(LOG_ERR, "Could not mount /proc");
		return -1;
	}
	return 0;
}

static bool is_user_process(pid_t pid)
{
	char *buf = NULL;
	FILE *fp;
	char *path = NULL;
	pid_t temp_pid;
	size_t size;
	bool user_process = true;

	while (pid >0 && user_process) {
		if (pid == 2) {
			user_process = false;
			continue;
		}
		xasprintf(&path, "/proc/%d/status", pid);
		fp = fopen(path, "r");
		free(path);
		/*
		 * if we could not open the file, the process disappeared, which
		 * leaves us no way to determine for sure whether it was a user
		 * process or kernel thread, so we say it is a kernel thread to
		 * avoid accidentally killing it.
		 */
		if (!fp) {
			user_process = false;
			continue;
		}
		temp_pid = -1;
		while (! feof(fp)) {
			buf = NULL;
			if (getline(&buf, &size, fp) != -1) {
				sscanf(buf, "PPid: %d", &temp_pid);
				free(buf);
			} else {
				free(buf);
				break;
			}
		}
		fclose(fp);
		if (temp_pid == -1) {
			syslog(LOG_ERR, "Unable to read pid from /proc/%d/status", pid);
			user_process = false;
			continue;
		}
		pid = temp_pid;
	}
	return user_process;
}

static int signal_processes(int sig, RC_STRINGLIST *omits, bool dryrun)
{
	sigset_t signals;
	sigset_t oldsigs;
	DIR *dir;
	struct dirent	*d;
	char *buf = NULL;
	pid_t pid;
	int sendcount = 0;

	kill(-1, SIGSTOP);
	sigfillset(&signals);
	sigemptyset(&oldsigs);
	sigprocmask(SIG_SETMASK, &signals, &oldsigs);
	/*
	 * Open the /proc directory.
	 * CWD must be /proc to avoid problems if / is affected by the killing
	 * (i.e. depends on fuse).
	 */
	if (chdir("/proc") == -1) {
		syslog(LOG_ERR, "chdir /proc failed");
		sigprocmask(SIG_SETMASK, &oldsigs, NULL);
		kill(-1, SIGCONT);
		return -1;
	}
	dir = opendir(".");
	if (!dir) {
		syslog(LOG_ERR, "cannot opendir(/proc)");
		sigprocmask(SIG_SETMASK, &oldsigs, NULL);
		kill(-1, SIGCONT);
		return -1;
	}

	/* Walk through the directory. */
	while ((d = readdir(dir)) != NULL) {
		/* Is this a process? */
		pid = (pid_t) atoi(d->d_name);
		if (pid == 0)
			continue;

		/* Is this a process we have been requested to omit? */
		if (buf) {
			free(buf);
			buf = NULL;
		}
		xasprintf(&buf, "%d", pid);
		if (rc_stringlist_find(omits, buf))
			continue;

		/* Is this process in our session? */
		if (getsid(getpid()) == getsid(pid))
			continue;

		/* Is this a kernel thread? */
		if (!is_user_process(pid))
			continue;

		if (dryrun)
			einfo("Would send signal %d to process %d", sig, pid);
		else if (kill(pid, sig) == 0)
			sendcount++;
	}
	closedir(dir);
	sigprocmask(SIG_SETMASK, &oldsigs, NULL);
	kill(-1, SIGCONT);
	return sendcount;
}

int main(int argc, char **argv)
{
	char *arg = NULL;
	int opt;
	bool dryrun = false;
	RC_STRINGLIST *omits = rc_stringlist_new();
	int sig = SIGKILL;
	char *here;
	char *token;

	/* Ensure that we are only quiet when explicitly told to be */
	unsetenv("EINFO_QUIET");

	applet = basename_c(argv[0]);
	rc_stringlist_addu(omits, "1");
	while ((opt = getopt_long(argc, argv, getoptstring,
		    longopts, (int *) 0)) != -1)
	{
		switch (opt) {
			case 'd':
				dryrun = true;
				break;
			case 'o':
				here = optarg;
				while ((token = strsep(&here, ",;:"))) {
					if ((pid_t) atoi(token) > 0)
						rc_stringlist_addu(omits, token);
					else {
						eerror("Invalid omit pid value %s", token);
						usage(EXIT_FAILURE);
					}
				}
				break;
			case_RC_COMMON_GETOPT
		}
	}

	if (argc > optind) {
	arg = argv[optind];
	sig = atoi(arg);
	if (sig <= 0 || sig > 31) {
		rc_stringlist_free(omits);
		eerror("Invalid signal %s", arg);
		usage(EXIT_FAILURE);
	}
	}
	
	openlog(applet, LOG_CONS|LOG_PID, LOG_DAEMON);
	if (mount_proc() != 0) {
		rc_stringlist_free(omits);
		eerrorx("Unable to mount /proc file system");
	}
	signal_processes(sig, omits, dryrun);
	rc_stringlist_free(omits);
	return 0;
}
