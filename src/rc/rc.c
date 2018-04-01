/*
 * rc.c
 * rc - manager for init scripts which control the startup, shutdown
 * and the running of daemons.
 *
 * Also a multicall binary for various commands that can be used in shell
 * scripts to query service state, mark service state and provide the
 * einfo family of informational functions.
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

const char rc_copyright[] = "Copyright (c) 2007-2008 Roy Marples";

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-logger.h"
#include "rc-misc.h"
#include "rc-plugin.h"

#include "version.h"
#include "_usage.h"

const char *extraopts = NULL;
const char *getoptstring = "a:no:s:S" getoptstring_COMMON;
const struct option longopts[] = {
	{ "no-stop", 0, NULL, 'n' },
	{ "override",    1, NULL, 'o' },
	{ "service",     1, NULL, 's' },
	{ "sys",         0, NULL, 'S' },
	longopts_COMMON
};
const char * const longopts_help[] = {
	"do not stop any services",
	"override the next runlevel to change into\n"
	"when leaving single user or boot runlevels",
	"runs the service specified with the rest\nof the arguments",
	"output the RC system type, if any",
	longopts_help_COMMON
};
const char *usagestring = ""					\
    "Usage: openrc [options] [<runlevel>]";

#define INITSH                  RC_LIBEXECDIR "/sh/init.sh"
#define INITEARLYSH             RC_LIBEXECDIR "/sh/init-early.sh"

#define INTERACTIVE             RC_SVCDIR "/interactive"

#define DEVBOOT			"/dev/.rcboot"

const char *applet = NULL;
static RC_STRINGLIST *main_hotplugged_services;
static RC_STRINGLIST *main_stop_services;
static RC_STRINGLIST *main_start_services;
static RC_STRINGLIST *main_types_nw;
static RC_STRINGLIST *main_types_nwua;
static RC_DEPTREE *main_deptree;
static char *runlevel;
static RC_HOOK hook_out;

struct termios *termios_orig = NULL;

RC_PIDLIST service_pids;

static void
clean_failed(void)
{
	DIR *dp;
	struct dirent *d;
	size_t l;
	char *path;

	/* Clean the failed services state dir now */
	if ((dp = opendir(RC_SVCDIR "/failed"))) {
		while ((d = readdir(dp))) {
			if (d->d_name[0] == '.' &&
			    (d->d_name[1] == '\0' ||
				(d->d_name[1] == '.' && d->d_name[2] == '\0')))
				continue;

			l = strlen(RC_SVCDIR "/failed/") +
			    strlen(d->d_name) + 1;
			path = xmalloc(sizeof(char) * l);
			snprintf(path, l, RC_SVCDIR "/failed/%s", d->d_name);
			if (path) {
				if (unlink(path))
					eerror("%s: unlink `%s': %s",
					    applet, path, strerror(errno));
				free(path);
			}
		}
		closedir(dp);
	}
}

static void
cleanup(void)
{
	RC_PID *p1 = LIST_FIRST(&service_pids);
	RC_PID *p2;

	if (!rc_in_logger && !rc_in_plugin &&
	    applet && (strcmp(applet, "rc") == 0 || strcmp(applet, "openrc") == 0))
	{
		if (hook_out)
			rc_plugin_run(hook_out, runlevel);

		rc_plugin_unload();

		if (termios_orig) {
			tcsetattr(STDIN_FILENO, TCSANOW, termios_orig);
			free(termios_orig);
		}

		/* Clean runlevel start, stop markers */
		rmdir(RC_STARTING);
		rmdir(RC_STOPPING);
		clean_failed();
		rc_logger_close();
	}

	while (p1) {
		p2 = LIST_NEXT(p1, entries);
		free(p1);
		p1 = p2;
	}

	rc_stringlist_free(main_hotplugged_services);
	rc_stringlist_free(main_stop_services);
	rc_stringlist_free(main_start_services);
	rc_stringlist_free(main_types_nw);
	rc_stringlist_free(main_types_nwua);
	rc_deptree_free(main_deptree);
	free(runlevel);
}

static char
read_key(bool block)
{
	struct termios termios;
	char c = 0;
	int fd = STDIN_FILENO;

	if (!isatty(fd))
		return false;

	/* Now save our terminal settings. We need to restore them at exit as
	   we will be changing it for non-blocking reads for Interactive */
	if (!termios_orig) {
		termios_orig = xmalloc(sizeof(*termios_orig));
		tcgetattr(fd, termios_orig);
	}

	tcgetattr(fd, &termios);
	termios.c_lflag &= ~(ICANON | ECHO);
	if (block)
		termios.c_cc[VMIN] = 1;
	else {
		termios.c_cc[VMIN] = 0;
		termios.c_cc[VTIME] = 0;
	}
	tcsetattr(fd, TCSANOW, &termios);
	if (read(fd, &c, 1) == -1)
		eerror("read: %s", strerror(errno));
	tcsetattr(fd, TCSANOW, termios_orig);
	return c;
}

static bool
want_interactive(void)
{
	char c;
	static bool gotinteractive;
	static bool interactive;

	if (rc_yesno(getenv("EINFO_QUIET")))
		return false;
	if (!gotinteractive) {
		gotinteractive = true;
		interactive = rc_conf_yesno("rc_interactive");
	}
	if (!interactive)
		return false;
	c = read_key(false);
	return (c == 'I' || c == 'i') ? true : false;
}

static void
mark_interactive(void)
{
	FILE *fp = fopen(INTERACTIVE, "w");
	if (fp)
		fclose(fp);
}

static void
run_program(const char *prog)
{
	struct sigaction sa;
	sigset_t full;
	sigset_t old;
	pid_t pid;

	/* We need to block signals until we have forked */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);
	pid = fork();

	if (pid == -1)
		eerrorx("%s: fork: %s", applet, strerror(errno));
	if (pid == 0) {
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

		if (termios_orig)
			tcsetattr(STDIN_FILENO, TCSANOW, termios_orig);

		execl(prog, prog, (char *)NULL);
		eerror("%s: unable to exec `%s': %s", applet, prog,
		    strerror(errno));
		_exit(EXIT_FAILURE);
	}

	/* Unmask signals and wait for child */
	sigprocmask(SIG_SETMASK, &old, NULL);
	if (rc_waitpid(pid) == -1)
		eerrorx("%s: failed to exec `%s'", applet, prog);
}

static void
open_shell(void)
{
	const char *shell;
	struct passwd *pw;

#ifdef __linux__
	const char *sys = rc_sys();

	/* VSERVER systems cannot really drop to shells */
	if (sys && strcmp(sys, RC_SYS_VSERVER) == 0)
	{
		execlp("halt", "halt", "-f", (char *) NULL);
		eerrorx("%s: unable to exec `halt -f': %s",
		    applet, strerror(errno));
	}
#endif

	shell = rc_conf_value("rc_shell");
	/* No shell set, so obey env, then passwd, then default to /bin/sh */
	if (shell == NULL) {
		shell = getenv("SHELL");
		if (shell == NULL) {
			pw = getpwuid(getuid());
			if (pw)
				shell = pw->pw_shell;
			if (shell == NULL)
				shell = "/bin/sh";
		}
	}
	run_program(shell);
}

static bool
set_krunlevel(const char *level)
{
	FILE *fp;

	if (!level ||
	    strcmp(level, getenv ("RC_BOOTLEVEL")) == 0 ||
	    strcmp(level, RC_LEVEL_SINGLE) == 0 ||
	    strcmp(level, RC_LEVEL_SYSINIT) == 0)
	{
		if (exists(RC_KRUNLEVEL) &&
		    unlink(RC_KRUNLEVEL) != 0)
			eerror("unlink `%s': %s", RC_KRUNLEVEL,
			    strerror(errno));
		return false;
	}

	if (!(fp = fopen(RC_KRUNLEVEL, "w"))) {
		eerror("fopen `%s': %s", RC_KRUNLEVEL, strerror(errno));
		return false;
	}

	fprintf(fp, "%s", level);
	fclose(fp);
	return true;
}

static char *get_krunlevel(void)
{
	char *buffer = NULL;
	FILE *fp;
	size_t i = 0;

	if (!exists(RC_KRUNLEVEL))
		return NULL;
	if (!(fp = fopen(RC_KRUNLEVEL, "r"))) {
		eerror("fopen `%s': %s", RC_KRUNLEVEL, strerror(errno));
		return NULL;
	}

	if (getline(&buffer, &i, fp) != -1) {
		i = strlen(buffer);
		if (buffer[i - 1] == '\n')
			buffer[i - 1] = 0;
	}
	fclose(fp);
	return buffer;
}

static void
add_pid(pid_t pid)
{
	RC_PID *p = xmalloc(sizeof(*p));
	p->pid = pid;
	LIST_INSERT_HEAD(&service_pids, p, entries);
}

static void
remove_pid(pid_t pid)
{
	RC_PID *p;

	LIST_FOREACH(p, &service_pids, entries)
	    if (p->pid == pid) {
		    LIST_REMOVE(p, entries);
		    free(p);
		    return;
	    }
}

static void
wait_for_services(void)
{
	for (;;) {
		while (waitpid(0, 0, 0) != -1)
			;
		if (errno != EINTR)
			break;
	}
}

static void
handle_signal(int sig)
{
	int serrno = errno;
	char signame[10] = { '\0' };
	pid_t pid;
	RC_PID *pi;
	int status = 0;
	struct winsize ws;
	sigset_t sset;

	switch (sig) {
	case SIGCHLD:
		do {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid < 0) {
				if (errno != ECHILD)
					eerror("waitpid: %s", strerror(errno));
				return;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));

		/* Remove that pid from our list */
		if (pid > 0)
			remove_pid(pid);
		break;

	case SIGWINCH:
		if (rc_logger_tty >= 0) {
			ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
			ioctl(rc_logger_tty, TIOCSWINSZ, &ws);
		}
		break;

	case SIGINT:
		if (!signame[0])
			snprintf(signame, sizeof(signame), "SIGINT");
		/* FALLTHROUGH */
	case SIGTERM:
		if (!signame[0])
			snprintf(signame, sizeof(signame), "SIGTERM");
		/* FALLTHROUGH */
	case SIGQUIT:
		if (!signame[0])
			snprintf(signame, sizeof(signame), "SIGQUIT");
		eerrorx("%s: caught %s, aborting", applet, signame);
		/* NOTREACHED */
	case SIGUSR1:
		eerror("rc: Aborting!");

		/* Block child signals */
		sigemptyset(&sset);
		sigaddset(&sset, SIGCHLD);
		sigprocmask(SIG_BLOCK, &sset, NULL);

		/* Kill any running services we have started */
		LIST_FOREACH(pi, &service_pids, entries)
		    kill(pi->pid, SIGTERM);

		/* Notify plugins we are aborting */
		rc_plugin_run(RC_HOOK_ABORT, NULL);

		exit(EXIT_FAILURE);
		/* NOTREACHED */

	default:
		eerror("%s: caught unknown signal %d", applet, sig);
	}

	/* Restore errno */
	errno = serrno;
}

static void
do_sysinit()
{
	struct utsname uts;
	const char *sys;

	/* exec init-early.sh if it exists
	 * This should just setup the console to use the correct
	 * font. Maybe it should setup the keyboard too? */
	if (exists(INITEARLYSH))
		run_program(INITEARLYSH);

	uname(&uts);
	printf("\n   %sOpenRC %s" VERSION "%s is starting up %s",
	    ecolor(ECOLOR_GOOD), ecolor(ECOLOR_HILITE),
	    ecolor(ECOLOR_NORMAL), ecolor(ECOLOR_BRACKET));
#ifdef BRANDING
	printf(BRANDING " (%s)", uts.machine);
#else
	printf("%s %s (%s)",
	    uts.sysname,
	    uts.release,
	    uts.machine);
#endif

	if ((sys = rc_sys()))
		printf(" [%s]", sys);

	printf("%s\n\n", ecolor(ECOLOR_NORMAL));

	if (!rc_yesno(getenv ("EINFO_QUIET")) &&
	    rc_conf_yesno("rc_interactive"))
		printf("Press %sI%s to enter interactive boot mode\n\n",
		    ecolor(ECOLOR_GOOD), ecolor(ECOLOR_NORMAL));

	setenv("RC_RUNLEVEL", RC_LEVEL_SYSINIT, 1);
	run_program(INITSH);

	/* init may have mounted /proc so we can now detect or real
	 * sys */
	if ((sys = rc_sys()))
		setenv("RC_SYS", sys, 1);
	/* force an update of the dependency tree */
	if ((main_deptree = _rc_deptree_load(1, NULL)) == NULL)
		eerrorx("failed to load deptree");
}

static bool
runlevel_config(const char *service, const char *level)
{
	char *init = rc_service_resolve(service);
	char *conf, *dir;
	size_t l;
	bool retval;

	dir = dirname(init);
	dir = dirname(init);
	l = strlen(dir) + strlen(level) + strlen(service) + 10;
	conf = xmalloc(sizeof(char) * l);
	snprintf(conf, l, "%s/conf.d/%s.%s", dir, service, level);
	retval = exists(conf);
	free(conf);
	free(init);
	return retval;
}

static void
do_stop_services(RC_STRINGLIST *types_nw, RC_STRINGLIST *start_services,
				 const RC_STRINGLIST *stop_services, const RC_DEPTREE *deptree,
				 const char *newlevel, bool parallel, bool going_down)
{
	pid_t pid;
	RC_STRING *service, *svc1, *svc2;
	RC_STRINGLIST *deporder, *tmplist, *kwords;
	RC_SERVICE state;
	RC_STRINGLIST *nostop;
	bool crashed, nstop;

	if (!types_nw) {
		types_nw = rc_stringlist_new();
		rc_stringlist_add(types_nw, "needsme");
		rc_stringlist_add(types_nw, "wantsme");
	}

	crashed = rc_conf_yesno("rc_crashed_stop");

	nostop = rc_stringlist_split(rc_conf_value("rc_nostop"), " ");
	TAILQ_FOREACH_REVERSE(service, stop_services, rc_stringlist, entries)
	{
		state = rc_service_state(service->value);
		if (state & RC_SERVICE_STOPPED || state & RC_SERVICE_FAILED)
			continue;

		/* Sometimes we don't ever want to stop a service. */
		if (rc_stringlist_find(nostop, service->value)) {
			rc_service_mark(service->value, RC_SERVICE_FAILED);
			continue;
		}
		kwords = rc_deptree_depend(deptree, service->value, "keyword");
		if (rc_stringlist_find(kwords, "-stop") ||
		    rc_stringlist_find(kwords, "nostop") ||
		    (going_down &&
			(rc_stringlist_find(kwords, "-shutdown") ||
			    rc_stringlist_find(kwords, "noshutdown"))))
			nstop = true;
		else
			nstop = false;
		rc_stringlist_free(kwords);
		if (nstop) {
			rc_service_mark(service->value, RC_SERVICE_FAILED);
			continue;
		}

		/* If the service has crashed, skip futher checks and just stop
		   it */
		if (crashed &&
		    rc_service_daemons_crashed(service->value))
			goto stop;

		/* If we're in the start list then don't bother stopping us */
		svc1 = rc_stringlist_find(start_services, service->value);
		if (svc1) {
			if (newlevel && strcmp(runlevel, newlevel) != 0) {
				/* So we're in the start list. But we should
				 * be stopped if we have a runlevel
				 * configuration file for either the current
				 * or next so we use the correct one. */
				if (!runlevel_config(service->value,runlevel) &&
				    !runlevel_config(service->value,newlevel))
					continue;
			}
			else
				continue;
		}

		/* We got this far. Last check is to see if any any service
		 * that going to be started depends on us */
		if (!svc1) {
			tmplist = rc_stringlist_new();
			rc_stringlist_add(tmplist, service->value);
			deporder = rc_deptree_depends(deptree, types_nw,
			    tmplist, newlevel ? newlevel : runlevel,
			    RC_DEP_STRICT | RC_DEP_TRACE);
			rc_stringlist_free(tmplist);
			svc2 = NULL;
			TAILQ_FOREACH(svc1, deporder, entries) {
				svc2 = rc_stringlist_find(start_services,
				    svc1->value);
				if (svc2)
					break;
			}
			rc_stringlist_free(deporder);

			if (svc2)
				continue;
		}

stop:
		/* After all that we can finally stop the blighter! */
		pid = service_stop(service->value);
		if (pid > 0) {
			add_pid(pid);
			if (!parallel) {
				rc_waitpid(pid);
				remove_pid(pid);
			}
		}
	}

	rc_stringlist_free(nostop);
}

static void
do_start_services(const RC_STRINGLIST *start_services, bool parallel)
{
	RC_STRING *service;
	pid_t pid;
	bool interactive = false;
	RC_SERVICE state;
	bool crashed = false;

	if (!rc_yesno(getenv("EINFO_QUIET")))
		interactive = exists(INTERACTIVE);
	errno = 0;
	crashed = rc_conf_yesno("rc_crashed_start");
	if (errno == ENOENT)
		crashed = true;

	TAILQ_FOREACH(service, start_services, entries) {
		state = rc_service_state(service->value);
		if (state & RC_SERVICE_FAILED)
			continue;
		if (!(state & RC_SERVICE_STOPPED)) {
			if (crashed &&
			    rc_service_daemons_crashed(service->value))
				rc_service_mark(service->value,
				    RC_SERVICE_STOPPED);
			else
			    continue;
		}
		if (!interactive)
			interactive = want_interactive();

		if (interactive) {
	interactive_retry:
			printf("\n");
			einfo("About to start the service %s",
			    service->value);
			eindent();
			einfo("1) Start the service\t\t2) Skip the service");
			einfo("3) Continue boot process\t\t4) Exit to shell");
			eoutdent();
	interactive_option:
			switch (read_key(true)) {
			case '1': break;
			case '2': continue;
			case '3': interactive = false; break;
			case '4': open_shell(); goto interactive_retry;
			default: goto interactive_option;
			}
		}

		pid = service_start(service->value);
		if (pid == -1)
			break;
		/* Remember the pid if we're running in parallel */
		if (pid > 0) {
			add_pid(pid);
			if (!parallel) {
				rc_waitpid(pid);
				remove_pid(pid);
			}
		}
	}

	/* Store our interactive status for boot */
	if (interactive &&
	    (strcmp(runlevel, RC_LEVEL_SYSINIT) == 0 ||
		strcmp(runlevel, getenv("RC_BOOTLEVEL")) == 0))
		mark_interactive();
	else {
		if (exists(INTERACTIVE))
			unlink(INTERACTIVE);
	}

}

#ifdef RC_DEBUG
static void
handle_bad_signal(int sig)
{
	char pid[10];
	int status;
	pid_t crashed_pid = getpid();

	switch (fork()) {
	case -1:
		_exit(sig);
		/* NOTREACHED */
	case 0:
		sprintf(pid, "%i", crashed_pid);
		printf("\nAuto launching gdb!\n\n");
		_exit(execlp("gdb", "gdb", "--quiet", "--pid", pid,
			"-ex", "bt full", NULL));
		/* NOTREACHED */
	default:
		wait(&status);
	}
	_exit(1);
	/* NOTREACHED */
}
#endif

int main(int argc, char **argv)
{
	const char *bootlevel = NULL;
	char *newlevel = NULL;
	const char *systype = NULL;
	RC_STRINGLIST *deporder = NULL;
	RC_STRINGLIST *tmplist;
	RC_STRING *service;
	bool going_down = false;
	int depoptions = RC_DEP_STRICT | RC_DEP_TRACE;
	char *krunlevel = NULL;
	char pidstr[10];
	int opt;
	bool parallel;
	int regen = 0;
	bool nostop = false;
#ifdef __linux__
	char *proc;
	char *p;
	char *token;
#endif

#ifdef RC_DEBUG
	signal_setup(SIGBUS, handle_bad_signal);
	signal_setup(SIGILL, handle_bad_signal);
	signal_setup(SIGSEGV, handle_bad_signal);
#endif

	applet = basename_c(argv[0]);
	LIST_INIT(&service_pids);
	atexit(cleanup);
	if (!applet)
		eerrorx("arguments required");

	argc--;
	argv++;

	/* Change dir to / to ensure all scripts don't use stuff in pwd */
	if (chdir("/") == -1)
		eerror("chdir: %s", strerror(errno));

	/* Ensure our environment is pure
	 * Also, add our configuration to it */
	env_filter();
	env_config();

	/* complain about old configuration settings if they exist */
	if (exists(RC_CONF_OLD)) {
		ewarn("%s still exists on your system and should be removed.",
				RC_CONF_OLD);
		ewarn("Please migrate to the appropriate settings in %s", RC_CONF);
	}

	argc++;
	argv--;
	while ((opt = getopt_long(argc, argv, getoptstring,
		    longopts, (int *) 0)) != -1)
	{
		switch (opt) {
		case 'n':
			nostop = true;
			break;
		case 'o':
			if (*optarg == '\0')
				optarg = NULL;
			if (!rc_runlevel_exists(optarg)) {
				eerror("runlevel `%s' does not exist", optarg);
				exit(EXIT_FAILURE);
			}
			if (!set_krunlevel(optarg))
				exit(EXIT_FAILURE);
			einfo("Overriding next runlevel to %s", optarg);
			exit(EXIT_SUCCESS);
			/* NOTREACHED */
		case 's':
			newlevel = rc_service_resolve(optarg);
			if (!newlevel)
				eerrorx("%s: service `%s' does not exist",
				    applet, optarg);
			argv += optind - 1;
			*argv = newlevel;
			execv(*argv, argv);
			eerrorx("%s: %s", applet, strerror(errno));
			/* NOTREACHED */
		case 'S':
			systype = rc_sys();
			if (systype)
				printf("%s\n", systype);
			exit(EXIT_SUCCESS);
			/* NOTREACHED */
		case_RC_COMMON_GETOPT
		}
	}

	if (strcmp(applet, "rc") == 0)
		ewarn("rc is deprecated, please use openrc instead.");
	newlevel = argv[optind++];
	/* To make life easier, we only have the shutdown runlevel as
	 * nothing really needs to know that we're rebooting.
	 * But for those that do, you can test against RC_REBOOT. */
	if (newlevel) {
		if (strcmp(newlevel, "reboot") == 0) {
			newlevel = UNCONST(RC_LEVEL_SHUTDOWN);
			setenv("RC_REBOOT", "YES", 1);
		}
	}

	/* Enable logging */
	setenv("EINFO_LOG", "openrc", 1);

	/* Export our PID */
	snprintf(pidstr, sizeof(pidstr), "%d", getpid());
	setenv("RC_PID", pidstr, 1);

	/* Create a list of all services which should be started for the new or
	* current runlevel including those in boot, sysinit and hotplugged
	* runlevels.  Clearly, some of these will already be started so we
	* won't actually be starting them all.
	*/
	bootlevel = getenv("RC_BOOTLEVEL");
	runlevel = rc_runlevel_get();

	rc_logger_open(newlevel ? newlevel : runlevel);

	/* Setup a signal handler */
	signal_setup(SIGINT, handle_signal);
	signal_setup(SIGQUIT, handle_signal);
	signal_setup(SIGTERM, handle_signal);
	signal_setup(SIGUSR1, handle_signal);
	signal_setup(SIGWINCH, handle_signal);

	/* Run any special sysinit foo */
	if (newlevel && strcmp(newlevel, RC_LEVEL_SYSINIT) == 0) {
		do_sysinit();
		free(runlevel);
		runlevel = rc_runlevel_get();
	}

	rc_plugin_load();

	/* Now we start handling our children */
	signal_setup(SIGCHLD, handle_signal);

	if (newlevel &&
	    (strcmp(newlevel, RC_LEVEL_SHUTDOWN) == 0 ||
		strcmp(newlevel, RC_LEVEL_SINGLE) == 0))
	{
		going_down = true;
		if (!exists(RC_KRUNLEVEL))
			set_krunlevel(runlevel);
		rc_runlevel_set(newlevel);
		setenv("RC_RUNLEVEL", newlevel, 1);
		setenv("RC_GOINGDOWN", "YES", 1);
	} else {
		/* We should not use krunevel in sysinit or boot runlevels */
		if (!newlevel ||
		    (strcmp(newlevel, RC_LEVEL_SYSINIT) != 0 &&
			strcmp(newlevel, getenv("RC_BOOTLEVEL")) != 0))
		{
			krunlevel = get_krunlevel();
			if (krunlevel) {
				newlevel = krunlevel;
				set_krunlevel(NULL);
			}
		}

		if (newlevel) {
			if (strcmp(runlevel, newlevel) != 0 &&
			    !rc_runlevel_exists(newlevel))
				eerrorx("%s: not a valid runlevel", newlevel);

#ifdef __linux__
			if (strcmp(newlevel, RC_LEVEL_SYSINIT) == 0) {
				/* If we requested a runlevel, save it now */
				p = rc_proc_getent("rc_runlevel");
				if (p == NULL)
					p = rc_proc_getent("softlevel");
				if (p != NULL) {
					set_krunlevel(p);
					free(p);
				}
			}
#endif
		}
	}

	if (going_down) {
#ifdef __FreeBSD__
		/* FIXME: we shouldn't have todo this */
		/* For some reason, wait_for_services waits for the logger
		 * proccess to finish as well, but only on FreeBSD.
		 * We cannot allow this so we stop logging now. */
		rc_logger_close();
#endif

		rc_plugin_run(RC_HOOK_RUNLEVEL_STOP_IN, newlevel);
	} else {
		rc_plugin_run(RC_HOOK_RUNLEVEL_STOP_IN, runlevel);
	}
	hook_out = RC_HOOK_RUNLEVEL_STOP_OUT;

	/* Check if runlevel is valid if we're changing */
	if (newlevel && strcmp(runlevel, newlevel) != 0 && !going_down) {
		if (!rc_runlevel_exists(newlevel))
			eerrorx("%s: is not a valid runlevel", newlevel);
	}

	/* Load our deptree */
	if ((main_deptree = _rc_deptree_load(0, &regen)) == NULL)
		eerrorx("failed to load deptree");
	if (exists(RC_DEPTREE_SKEWED))
		ewarn("WARNING: clock skew detected!");

	/* Clean the failed services state dir */
	clean_failed();

	if (mkdir(RC_STOPPING, 0755) != 0) {
		if (errno == EACCES)
			eerrorx("%s: superuser access required", applet);
		eerrorx("%s: failed to create stopping dir `%s': %s",
		    applet, RC_STOPPING, strerror(errno));
	}

	/* Create a list of all services which we could stop (assuming
	* they won't be active in the new or current runlevel) including
	* all those services which have been started, are inactive or
	* are currently starting.  Clearly, some of these will be listed
	* in the new or current runlevel so we won't actually be stopping
	* them all.
	*/
	main_stop_services = rc_services_in_state(RC_SERVICE_STARTED);
	tmplist = rc_services_in_state(RC_SERVICE_INACTIVE);
	TAILQ_CONCAT(main_stop_services, tmplist, entries);
	free(tmplist);
	tmplist = rc_services_in_state(RC_SERVICE_STARTING);
	TAILQ_CONCAT(main_stop_services, tmplist, entries);
	free(tmplist);
	if (main_stop_services)
		rc_stringlist_sort(&main_stop_services);

	main_types_nwua = rc_stringlist_new();
	rc_stringlist_add(main_types_nwua, "ineed");
	rc_stringlist_add(main_types_nwua, "iwant");
	rc_stringlist_add(main_types_nwua, "iuse");
	rc_stringlist_add(main_types_nwua, "iafter");

	if (main_stop_services) {
		tmplist = rc_deptree_depends(main_deptree, main_types_nwua, main_stop_services,
		    runlevel, depoptions | RC_DEP_STOP);
		rc_stringlist_free(main_stop_services);
		main_stop_services = tmplist;
	}

	/* Create a list of all services which should be started for the new or
	 * current runlevel including those in boot, sysinit and hotplugged
	 * runlevels.  Clearly, some of these will already be started so we
	 * won't actually be starting them all.
	 */
	main_hotplugged_services = rc_services_in_state(RC_SERVICE_HOTPLUGGED);
	main_start_services = rc_services_in_runlevel_stacked(newlevel ?
	    newlevel : runlevel);
	if (strcmp(newlevel ? newlevel : runlevel, RC_LEVEL_SHUTDOWN) != 0 &&
	    strcmp(newlevel ? newlevel : runlevel, RC_LEVEL_SYSINIT) != 0)
	{
		tmplist = rc_services_in_runlevel(RC_LEVEL_SYSINIT);
		TAILQ_CONCAT(main_start_services, tmplist, entries);
		free(tmplist);
		/* If we are NOT headed for the single-user runlevel... */
		if (strcmp(newlevel ? newlevel : runlevel,
			RC_LEVEL_SINGLE) != 0)
		{
			/* If we are NOT headed for the boot runlevel... */
			if (strcmp(newlevel ? newlevel : runlevel,
				bootlevel) != 0)
			{
				tmplist = rc_services_in_runlevel(bootlevel);
				TAILQ_CONCAT(main_start_services, tmplist, entries);
				free(tmplist);
			}
			if (main_hotplugged_services) {
				TAILQ_FOREACH(service, main_hotplugged_services,
				    entries)
				    rc_stringlist_addu(main_start_services,
					service->value);
			}
		}
	}

	parallel = rc_conf_yesno("rc_parallel");

	/* Now stop the services that shouldn't be running */
	if (main_stop_services && !nostop)
		do_stop_services(main_types_nw, main_start_services, main_stop_services, main_deptree, newlevel, parallel, going_down);

	/* Wait for our services to finish */
	wait_for_services();

	/* Notify the plugins we have finished */
	rc_plugin_run(RC_HOOK_RUNLEVEL_STOP_OUT,
	    going_down ? newlevel : runlevel);
	hook_out = 0;

	rmdir(RC_STOPPING);

	/* Store the new runlevel */
	if (newlevel) {
		rc_runlevel_set(newlevel);
		free(runlevel);
		runlevel = xstrdup(newlevel);
		setenv("RC_RUNLEVEL", runlevel, 1);
	}

#ifdef __linux__
	/* We can't log beyond this point as the shutdown runlevel
	 * will mount / readonly. */
	if (strcmp(runlevel, RC_LEVEL_SHUTDOWN) == 0)
		rc_logger_close();
#endif

	mkdir(RC_STARTING, 0755);
	rc_plugin_run(RC_HOOK_RUNLEVEL_START_IN, runlevel);
	hook_out = RC_HOOK_RUNLEVEL_START_OUT;

	/* Re-add our hotplugged services if they stopped */
	if (main_hotplugged_services)
		TAILQ_FOREACH(service, main_hotplugged_services, entries)
		    rc_service_mark(service->value, RC_SERVICE_HOTPLUGGED);

#ifdef __linux__
	/* If the "noinit" parameter was passed on the kernel command line then
	 * mark the specified services as started so they will not be started
	 * by us. */
	proc = p = rc_proc_getent("noinit");
	if (proc) {
		while ((token = strsep(&p, ",")))
			rc_service_mark(token, RC_SERVICE_STARTED);
		free(proc);
	}
#endif

	/* If we have a list of services to start then... */
	if (main_start_services) {
		/* Get a list of the chained runlevels which compose the target runlevel */
		RC_STRINGLIST *runlevel_chain = rc_runlevel_stacks(runlevel);

		/* Loop through them in reverse order. */
		RC_STRING *rlevel;
		TAILQ_FOREACH_REVERSE(rlevel, runlevel_chain, rc_stringlist, entries)
		{
			/* Get a list of all the services in that runlevel */
			RC_STRINGLIST *run_services = rc_services_in_runlevel(rlevel->value);

			/* Start those services. */
			rc_stringlist_sort(&run_services);
			deporder = rc_deptree_depends(main_deptree, main_types_nwua, run_services, rlevel->value, depoptions | RC_DEP_START);
			rc_stringlist_free(run_services);
			run_services = deporder;
			do_start_services(run_services, parallel);

			/* Wait for our services to finish */
			wait_for_services();

			/* Free the list of services, we're done with it. */
			rc_stringlist_free(run_services);
		}
		rc_stringlist_free(runlevel_chain);
	}

#ifdef __linux__
	/* If the "noinit" parameter was passed on the kernel command line then
	 * mark the specified services as stopped so that our records reflect
	 * reality.	 */
	proc = p = rc_proc_getent("noinit");
	if (proc) {
		while ((token = strsep(&p, ",")))
			rc_service_mark(token, RC_SERVICE_STOPPED);
		free(proc);
	}

#endif

	rc_plugin_run(RC_HOOK_RUNLEVEL_START_OUT, runlevel);
	hook_out = 0;

	/* If we're in the boot runlevel and we regenerated our dependencies
	 * we need to delete them so that they are regenerated again in the
	 * default runlevel as they may depend on things that are now
	 * available */
	if (regen && strcmp(runlevel, bootlevel) == 0)
		unlink(RC_DEPTREE_CACHE);

	return EXIT_SUCCESS;
}
