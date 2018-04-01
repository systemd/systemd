/*
 * openrc-init.c
 * This is the init process (pid 1) for OpenRC.
 *
 * This is based on code written by James Hammons <jlhamm@acm.org>, so
 * I would like to publically thank him for his work.
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

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/wait.h>

#include "helpers.h"
#include "rc.h"
#include "rc-wtmp.h"
#include "version.h"

static const char *path_default = "/sbin:/usr/sbin:/bin:/usr/bin";
static const char *rc_default_runlevel = "default";

static pid_t do_openrc(const char *runlevel)
{
	pid_t pid;
	sigset_t signals;

	pid = fork();
	switch(pid) {
		case -1:
			perror("fork");
			break;
		case 0:
			setsid();
			/* unblock all signals */
			sigemptyset(&signals);
			sigprocmask(SIG_SETMASK, &signals, NULL);
			printf("Starting %s runlevel\n", runlevel);
			execlp("openrc", "openrc", runlevel, NULL);
			perror("exec");
			break;
		default:
			break;
	}
	return pid;
}

static void init(const char *default_runlevel)
{
	const char *runlevel = NULL;
	pid_t pid;

	pid = do_openrc("sysinit");
	waitpid(pid, NULL, 0);
	pid = do_openrc("boot");
	waitpid(pid, NULL, 0);
	if (default_runlevel)
		runlevel = default_runlevel;
	else
		runlevel = rc_conf_value("rc_default_runlevel");
	if (!runlevel)
		runlevel = rc_default_runlevel;
	if (!rc_runlevel_exists(runlevel)) {
		printf("%s is an invalid runlevel\n", runlevel);
		runlevel = rc_default_runlevel;
	}
	pid = do_openrc(runlevel);
	waitpid(pid, NULL, 0);
	log_wtmp("reboot", "~~", 0, RUN_LVL, "~~");
}

static void handle_reexec(char *my_name)
{
	execlp(my_name, my_name, "reexec", NULL);
	return;
}

static void handle_shutdown(const char *runlevel, int cmd)
{
	pid_t pid;

	pid = do_openrc(runlevel);
	while (waitpid(pid, NULL, 0) != pid);
	printf("Sending the final term signal\n");
	kill(-1, SIGTERM);
	sleep(3);
	printf("Sending the final kill signal\n");
	kill(-1, SIGKILL);
	sync();
	reboot(cmd);
}

static void handle_single(void)
{
	pid_t pid;

	pid = do_openrc("single");
	while (waitpid(pid, NULL, 0) != pid);
}

static void reap_zombies(void)
{
	pid_t pid;

	for (;;) {
		pid = waitpid(-1, NULL, WNOHANG);
		if (pid == 0)
			break;
		else if (pid == -1) {
			if (errno == ECHILD)
				break;
			perror("waitpid");
			continue;
		}
	}
}

static void signal_handler(int sig)
{
	switch(sig) {
		case SIGINT:
			handle_shutdown("reboot", RB_AUTOBOOT);
			break;
		case SIGCHLD:
			reap_zombies();
			break;
		default:
			printf("Unknown signal received, %d\n", sig);
			break;
	}
}

int main(int argc, char **argv)
{
	char *default_runlevel;
	char buf[2048];
	int count;
	FILE *fifo;
	bool reexec = false;
	sigset_t signals;
	struct sigaction sa;

	if (getpid() != 1)
		return 1;

	printf("OpenRC init version %s starting\n", VERSION);

	if (argc > 1)
		default_runlevel = argv[1];
	else
		default_runlevel = NULL;

	if (default_runlevel && strcmp(default_runlevel, "reexec") == 0)
		reexec = true;

	/* block all signals we do not handle */
	sigfillset(&signals);
	sigdelset(&signals, SIGCHLD);
	sigdelset(&signals, SIGINT);
	sigprocmask(SIG_SETMASK, &signals, NULL);

	/* install signal  handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	reboot(RB_DISABLE_CAD);

	/* set default path */
	setenv("PATH", path_default, 1);

	if (! reexec)
		init(default_runlevel);

	if (mkfifo(RC_INIT_FIFO, 0600) == -1 && errno != EEXIST)
		perror("mkfifo");

	for (;;) {
		/* This will block until a command is sent down the pipe... */
		fifo = fopen(RC_INIT_FIFO, "r");
		if (!fifo) {
			if (errno != EINTR)
				perror("fopen");
			continue;
		}
		count = fread(buf, 1, sizeof(buf) - 1, fifo);
		buf[count] = 0;
		fclose(fifo);
		printf("PID1: Received \"%s\" from FIFO...\n", buf);
		if (strcmp(buf, "halt") == 0)
			handle_shutdown("shutdown", RB_HALT_SYSTEM);
		else if (strcmp(buf, "kexec") == 0)
			handle_shutdown("reboot", RB_KEXEC);
		else if (strcmp(buf, "poweroff") == 0)
			handle_shutdown("shutdown", RB_POWER_OFF);
		else if (strcmp(buf, "reboot") == 0)
			handle_shutdown("reboot", RB_AUTOBOOT);
		else if (strcmp(buf, "reexec") == 0)
			handle_reexec(argv[0]);
		else if (strcmp(buf, "single") == 0)
			handle_single();
	}
	return 0;
}
