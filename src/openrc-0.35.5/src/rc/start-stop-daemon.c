/*
  start-stop-daemon
 * Starts, stops, tests and signals daemons
 *
 * This is essentially a ground up re-write of Debians
 * start-stop-daemon for cleaner code and to integrate into our RC
 * system so we can monitor daemons a little.
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

#define ONE_MS           1000000

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sys/syscall.h> /* For io priority */
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_PAM
#include <security/pam_appl.h>

/* We are not supporting authentication conversations */
static struct pam_conv conv = { NULL, NULL};
#endif

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-misc.h"
#include "rc-schedules.h"
#include "_usage.h"
#include "helpers.h"

const char *applet = NULL;
const char *extraopts = NULL;
const char *getoptstring = "I:KN:PR:Sa:bc:d:e:g:ik:mn:op:s:tu:r:w:x:1:2:" \
	getoptstring_COMMON;
const struct option longopts[] = {
	{ "ionice",       1, NULL, 'I'},
	{ "stop",         0, NULL, 'K'},
	{ "nicelevel",    1, NULL, 'N'},
	{ "retry",        1, NULL, 'R'},
	{ "start",        0, NULL, 'S'},
	{ "startas",      1, NULL, 'a'},
	{ "background",   0, NULL, 'b'},
	{ "chuid",        1, NULL, 'c'},
	{ "chdir",        1, NULL, 'd'},
	{ "env",          1, NULL, 'e'},
	{ "umask",        1, NULL, 'k'},
	{ "group",        1, NULL, 'g'},
	{ "interpreted",  0, NULL, 'i'},
	{ "make-pidfile", 0, NULL, 'm'},
	{ "name",         1, NULL, 'n'},
	{ "oknodo",       0, NULL, 'o'},
	{ "pidfile",      1, NULL, 'p'},
	{ "signal",       1, NULL, 's'},
	{ "test",         0, NULL, 't'},
	{ "user",         1, NULL, 'u'},
	{ "chroot",       1, NULL, 'r'},
	{ "wait",         1, NULL, 'w'},
	{ "exec",         1, NULL, 'x'},
	{ "stdout",       1, NULL, '1'},
	{ "stderr",       1, NULL, '2'},
	{ "progress",     0, NULL, 'P'},
	longopts_COMMON
};
const char * const longopts_help[] = {
	"Set an ionice class:data when starting",
	"Stop daemon",
	"Set a nicelevel when starting",
	"Retry schedule to use when stopping",
	"Start daemon",
	"deprecated, use --exec or --name",
	"Force daemon to background",
	"deprecated, use --user",
	"Change the PWD",
	"Set an environment string",
	"Set the umask for the daemon",
	"Change the process group",
	"Match process name by interpreter",
	"Create a pidfile",
	"Match process name",
	"deprecated",
	"Match pid found in this file",
	"Send a different signal",
	"Test actions, don't do them",
	"Change the process user",
	"Chroot to this directory",
	"Milliseconds to wait for daemon start",
	"Binary to start/stop",
	"Redirect stdout to file",
	"Redirect stderr to file",
	"Print dots each second while waiting",
	longopts_help_COMMON
};
const char *usagestring = NULL;

static char **nav;

static char *changeuser, *ch_root, *ch_dir;

extern char **environ;

#if !defined(SYS_ioprio_set) && defined(__NR_ioprio_set)
# define SYS_ioprio_set __NR_ioprio_set
#endif
#if !defined(__DragonFly__)
static inline int ioprio_set(int which _unused,
			     int who _unused,
			     int ioprio _unused)
{
#ifdef SYS_ioprio_set
	return syscall(SYS_ioprio_set, which, who, ioprio);
#else
	return 0;
#endif
}
#endif

static void
cleanup(void)
{
	free(changeuser);
	free(nav);
	free_schedulelist();
}

static void
handle_signal(int sig)
{
	int status;
	int serrno = errno;
	char signame[10] = { '\0' };

	switch (sig) {
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

	case SIGCHLD:
		for (;;) {
			if (waitpid(-1, &status, WNOHANG) < 0) {
				if (errno != ECHILD)
					eerror("%s: waitpid: %s",
					    applet, strerror(errno));
				break;
			}
		}
		break;

	default:
		eerror("%s: caught unknown signal %d", applet, sig);
	}

	/* Restore errno */
	errno = serrno;
}

static char *
expand_home(const char *home, const char *path)
{
	char *opath, *ppath, *p, *nh;
	size_t len;
	struct passwd *pw;

	if (!path || *path != '~')
		return xstrdup(path);

	opath = ppath = xstrdup(path);
	if (ppath[1] != '/' && ppath[1] != '\0') {
		p = strchr(ppath + 1, '/');
		if (p)
			*p = '\0';
		pw = getpwnam(ppath + 1);
		if (pw) {
			home = pw->pw_dir;
			ppath = p;
			if (ppath)
				*ppath = '/';
		} else
			home = NULL;
	} else
		ppath++;

	if (!home) {
	free(opath);
		return xstrdup(path);
	}
	if (!ppath) {
		free(opath);
		return xstrdup(home);
	}

	len = strlen(ppath) + strlen(home) + 1;
	nh = xmalloc(len);
	snprintf(nh, len, "%s%s", home, ppath);
	free(opath);
	return nh;
}

int main(int argc, char **argv)
{
	int devnull_fd = -1;
#ifdef TIOCNOTTY
	int tty_fd = -1;
#endif

#ifdef HAVE_PAM
	pam_handle_t *pamh = NULL;
	int pamr;
	const char *const *pamenv = NULL;
#endif

	int opt;
	size_t size = 0;
	bool start = false;
	bool stop = false;
	bool oknodo = false;
	bool test = false;
	char *exec = NULL;
	char *startas = NULL;
	char *name = NULL;
	char *pidfile = NULL;
	char *retry = NULL;
	int sig = -1;
	int nicelevel = 0, ionicec = -1, ioniced = 0;
	bool background = false;
	bool makepidfile = false;
	bool interpreted = false;
	bool progress = false;
	uid_t uid = 0;
	gid_t gid = 0;
	char *home = NULL;
	int tid = 0;
	char *redirect_stderr = NULL;
	char *redirect_stdout = NULL;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
	pid_t pid, spid;
	RC_PIDLIST *pids;
	int i;
	char *svcname = getenv("RC_SVCNAME");
	RC_STRINGLIST *env_list;
	RC_STRING *env;
	char *tmp, *newpath, *np;
	char *p;
	char *token;
	char *exec_file = NULL;
	struct passwd *pw;
	struct group *gr;
	char *line = NULL;
	FILE *fp;
	size_t len;
	mode_t numask = 022;
	char **margv;
	unsigned int start_wait = 0;

	applet = basename_c(argv[0]);
	atexit(cleanup);

	signal_setup(SIGINT, handle_signal);
	signal_setup(SIGQUIT, handle_signal);
	signal_setup(SIGTERM, handle_signal);

	if ((tmp = getenv("SSD_NICELEVEL")))
		if (sscanf(tmp, "%d", &nicelevel) != 1)
			eerror("%s: invalid nice level `%s' (SSD_NICELEVEL)",
			    applet, tmp);
	if ((tmp = getenv("SSD_IONICELEVEL"))) {
		int n = sscanf(tmp, "%d:%d", &ionicec, &ioniced);
		if (n != 1 && n != 2)
			eerror("%s: invalid ionice level `%s' (SSD_IONICELEVEL)",
			    applet, tmp);
		if (ionicec == 0)
			ioniced = 0;
		else if (ionicec == 3)
			ioniced = 7;
		ionicec <<= 13; /* class shift */
	}

	/* Get our user name and initial dir */
	p = getenv("USER");
	home = getenv("HOME");
	if (home == NULL || p == NULL) {
		pw = getpwuid(getuid());
		if (pw != NULL) {
			if (p == NULL)
				setenv("USER", pw->pw_name, 1);
			if (home == NULL) {
				setenv("HOME", pw->pw_dir, 1);
				home = pw->pw_dir;
			}
		}
	}

	while ((opt = getopt_long(argc, argv, getoptstring, longopts,
		    (int *) 0)) != -1)
		switch (opt) {
		case 'I': /* --ionice */
			if (sscanf(optarg, "%d:%d", &ionicec, &ioniced) == 0)
				eerrorx("%s: invalid ionice `%s'",
				    applet, optarg);
			if (ionicec == 0)
				ioniced = 0;
			else if (ionicec == 3)
				ioniced = 7;
			ionicec <<= 13; /* class shift */
			break;

		case 'K':  /* --stop */
			stop = true;
			break;

		case 'N':  /* --nice */
			if (sscanf(optarg, "%d", &nicelevel) != 1)
				eerrorx("%s: invalid nice level `%s'",
				    applet, optarg);
			break;

		case 'P':  /* --progress */
			progress = true;
			break;

		case 'R':  /* --retry <schedule>|<timeout> */
			retry = optarg;
			break;

		case 'S':  /* --start */
			start = true;
			break;

		case 'b':  /* --background */
			background = true;
			break;

		case 'c':  /* --chuid <username>|<uid> */
			/* DEPRECATED */
			ewarn("WARNING: -c/--chuid is deprecated and will be removed in the future, please use -u/--user instead");
		case 'u':  /* --user <username>|<uid> */
		{
			p = optarg;
			tmp = strsep(&p, ":");
			changeuser = xstrdup(tmp);
			if (sscanf(tmp, "%d", &tid) != 1)
				pw = getpwnam(tmp);
			else
				pw = getpwuid((uid_t)tid);

			if (pw == NULL)
				eerrorx("%s: user `%s' not found",
				    applet, tmp);
			uid = pw->pw_uid;
			home = pw->pw_dir;
			unsetenv("HOME");
			if (pw->pw_dir)
				setenv("HOME", pw->pw_dir, 1);
			unsetenv("USER");
			if (pw->pw_name)
				setenv("USER", pw->pw_name, 1);
			if (gid == 0)
				gid = pw->pw_gid;

			if (p) {
				tmp = strsep (&p, ":");
				if (sscanf(tmp, "%d", &tid) != 1)
					gr = getgrnam(tmp);
				else
					gr = getgrgid((gid_t) tid);

				if (gr == NULL)
					eerrorx("%s: group `%s'"
					    " not found",
					    applet, tmp);
				gid = gr->gr_gid;
			}
		}
		break;

		case 'd':  /* --chdir /new/dir */
			ch_dir = optarg;
			break;

		case 'e': /* --env */
			putenv(optarg);
			break;

		case 'g':  /* --group <group>|<gid> */
			if (sscanf(optarg, "%d", &tid) != 1)
				gr = getgrnam(optarg);
			else
				gr = getgrgid((gid_t)tid);
			if (gr == NULL)
				eerrorx("%s: group `%s' not found",
				    applet, optarg);
			gid = gr->gr_gid;
			break;

		case 'i': /* --interpreted */
			interpreted = true;
			break;

		case 'k':
			if (parse_mode(&numask, optarg))
				eerrorx("%s: invalid mode `%s'",
				    applet, optarg);
			break;

		case 'm':  /* --make-pidfile */
			makepidfile = true;
			break;

		case 'n':  /* --name <process-name> */
			name = optarg;
			break;

		case 'o':  /* --oknodo */
			/* DEPRECATED */
			ewarn("WARNING: -o/--oknodo is deprecated and will be removed in the future");
			oknodo = true;
			break;

		case 'p':  /* --pidfile <pid-file> */
			pidfile = optarg;
			break;

		case 's':  /* --signal <signal> */
			sig = parse_signal(applet, optarg);
			break;

		case 't':  /* --test */
			test = true;
			break;

		case 'r':  /* --chroot /new/root */
			ch_root = optarg;
			break;

		case 'a': /* --startas <name> */
			/* DEPRECATED */
			ewarn("WARNING: -a/--startas is deprecated and will be removed in the future, please use -x/--exec or -n/--name instead");
			startas = optarg;
			break;
		case 'w':
			if (sscanf(optarg, "%d", &start_wait) != 1)
				eerrorx("%s: `%s' not a number",
				    applet, optarg);
			break;
		case 'x':  /* --exec <executable> */
			exec = optarg;
			break;

		case '1':   /* --stdout /path/to/stdout.lgfile */
			redirect_stdout = optarg;
			break;

		case '2':  /* --stderr /path/to/stderr.logfile */
			redirect_stderr = optarg;
			break;

		case_RC_COMMON_GETOPT
		}

	endpwent();
	argc -= optind;
	argv += optind;

	/* Allow start-stop-daemon --signal HUP --exec /usr/sbin/dnsmasq
	 * instead of forcing --stop --oknodo as well */
	if (!start &&
	    !stop &&
	    sig != SIGINT &&
	    sig != SIGTERM &&
	    sig != SIGQUIT &&
	    sig != SIGKILL)
		oknodo = true;

	if (!exec)
		exec = startas;
	else if (!name)
		name = startas;

	if (!exec) {
		exec = *argv;
		if (!exec)
			exec = name;
		if (name && start)
			*argv = name;
	} else if (name) {
		*--argv = name;
		++argc;
    } else if (exec) {
		*--argv = exec;
		++argc;
	};

	if (stop || sig != -1) {
		if (sig == -1)
			sig = SIGTERM;
		if (!*argv && !pidfile && !name && !uid)
			eerrorx("%s: --stop needs --exec, --pidfile,"
			    " --name or --user", applet);
		if (background)
			eerrorx("%s: --background is only relevant with"
			    " --start", applet);
		if (makepidfile)
			eerrorx("%s: --make-pidfile is only relevant with"
			    " --start", applet);
		if (redirect_stdout || redirect_stderr)
			eerrorx("%s: --stdout and --stderr are only relevant"
			    " with --start", applet);
		if (start_wait)
			ewarn("using --wait with --stop has no effect,"
			    " use --retry instead");
	} else {
		if (!exec)
			eerrorx("%s: nothing to start", applet);
		if (makepidfile && !pidfile)
			eerrorx("%s: --make-pidfile is only relevant with"
			    " --pidfile", applet);
		if ((redirect_stdout || redirect_stderr) && !background)
			eerrorx("%s: --stdout and --stderr are only relevant"
			    " with --background", applet);
	}

	/* Expand ~ */
	if (ch_dir && *ch_dir == '~')
		ch_dir = expand_home(home, ch_dir);
	if (ch_root && *ch_root == '~')
		ch_root = expand_home(home, ch_root);
	if (exec) {
		if (*exec == '~')
			exec = expand_home(home, exec);

		/* Validate that the binary exists if we are starting */
		if (*exec == '/' || *exec == '.') {
			/* Full or relative path */
			if (ch_root)
				xasprintf(&exec_file, "%s/%s", ch_root, exec);
			else
				xasprintf(&exec_file, "%s", exec);
		} else {
			/* Something in $PATH */
			p = tmp = xstrdup(getenv("PATH"));
			exec_file = NULL;
			while ((token = strsep(&p, ":"))) {
				if (ch_root)
					xasprintf(&exec_file, "%s/%s/%s", ch_root, token, exec);
				else
					xasprintf(&exec_file, "%s/%s", token, exec);
				if (exec_file && exists(exec_file))
					break;
				free(exec_file);
				exec_file = NULL;
			}
			free(tmp);
		}
	}
	if (start && !exists(exec_file)) {
		eerror("%s: %s does not exist", applet,
		    *exec_file ? exec_file : exec);
		free(exec_file);
		exit(EXIT_FAILURE);

	}
	if (start && retry)
		ewarn("using --retry with --start has no effect,"
		    " use --wait instead");

	/* If we don't have a pidfile we should check if it's interpreted
	 * or not. If it we, we need to pass the interpreter through
	 * to our daemon calls to find it correctly. */
	if (interpreted && !pidfile) {
		fp = fopen(exec_file, "r");
		if (fp) {
			line = NULL;
			if (getline(&line, &size, fp) == -1)
				eerrorx("%s: %s", applet, strerror(errno));
			p = line;
			fclose(fp);
			if (p != NULL && line[0] == '#' && line[1] == '!') {
				p = line + 2;
				/* Strip leading spaces */
				while (*p == ' ' || *p == '\t')
					p++;
				/* Remove the trailing newline */
				len = strlen(p) - 1;
				if (p[len] == '\n')
					p[len] = '\0';
				token = strsep(&p, " ");
				free(exec_file);
				xasprintf(&exec_file, "%s", token);
				opt = 0;
				for (nav = argv; *nav; nav++)
					opt++;
				nav = xmalloc(sizeof(char *) * (opt + 3));
				nav[0] = exec_file;
				len = 1;
				if (p)
					nav[len++] = p;
				for (i = 0; i < opt; i++)
					nav[i + len] = argv[i];
				nav[i + len] = '\0';
			}
		}
	}
	margv = nav ? nav : argv;

	if (stop || sig != -1) {
		if (sig == -1)
			sig = SIGTERM;
		if (!stop)
			oknodo = true;
		if (retry)
			parse_schedule(applet, retry, sig);
		else if (test || oknodo)
			parse_schedule(applet, "0", sig);
		else
			parse_schedule(applet, NULL, sig);
		if (pidfile) {
			pid = get_pid(applet, pidfile);
			if (pid == -1)
				exit(EXIT_FAILURE);
		} else {
			pid = 0;
		}
		i = run_stop_schedule(applet, exec, (const char *const *)margv,
		    pid, uid, test, progress, false);

		if (i < 0)
			/* We failed to stop something */
			exit(EXIT_FAILURE);
		if (test || oknodo)
			return i > 0 ? EXIT_SUCCESS : EXIT_FAILURE;

		/* Even if we have not actually killed anything, we should
		 * remove information about it as it may have unexpectedly
		 * crashed out. We should also return success as the end
		 * result would be the same. */
		if (pidfile && exists(pidfile))
			unlink(pidfile);
		if (svcname)
			rc_service_daemon_set(svcname, exec,
			    (const char *const *)argv,
			    pidfile, false);
		exit(EXIT_SUCCESS);
	}

	if (pidfile)
		pid = get_pid(applet, pidfile);
	else
		pid = 0;

	if (pid)
		pids = rc_find_pids(NULL, NULL, 0, pid);
	else
		pids = rc_find_pids(exec, (const char * const *) argv, uid, 0);
	if (pids)
		eerrorx("%s: %s is already running", applet, exec);

	free(pids);
	if (test) {
		if (rc_yesno(getenv("EINFO_QUIET")))
			exit (EXIT_SUCCESS);

		einfon("Would start");
		while (argc-- > 0)
			printf(" %s", *argv++);
		printf("\n");
		eindent();
		if (uid != 0)
			einfo("as user id %d", uid);
		if (gid != 0)
			einfo("as group id %d", gid);
		if (ch_root)
			einfo("in root `%s'", ch_root);
		if (ch_dir)
			einfo("in dir `%s'", ch_dir);
		if (nicelevel != 0)
			einfo("with a priority of %d", nicelevel);
		if (name)
			einfo ("with a process name of %s", name);
		eoutdent();
		exit(EXIT_SUCCESS);
	}

	ebeginv("Detaching to start `%s'", exec);
	eindentv();

	/* Remove existing pidfile */
	if (pidfile)
		unlink(pidfile);

	if (background)
		signal_setup(SIGCHLD, handle_signal);

	if ((pid = fork()) == -1)
		eerrorx("%s: fork: %s", applet, strerror(errno));

	/* Child process - lets go! */
	if (pid == 0) {
		pid_t mypid = getpid();
		umask(numask);

#ifdef TIOCNOTTY
		tty_fd = open("/dev/tty", O_RDWR);
#endif

		devnull_fd = open("/dev/null", O_RDWR);

		if (nicelevel) {
			if (setpriority(PRIO_PROCESS, mypid, nicelevel) == -1)
				eerrorx("%s: setpritory %d: %s",
				    applet, nicelevel,
				    strerror(errno));
		}

		if (ionicec != -1 &&
		    ioprio_set(1, mypid, ionicec | ioniced) == -1)
			eerrorx("%s: ioprio_set %d %d: %s", applet,
			    ionicec, ioniced, strerror(errno));

		if (ch_root && chroot(ch_root) < 0)
			eerrorx("%s: chroot `%s': %s",
			    applet, ch_root, strerror(errno));

		if (ch_dir && chdir(ch_dir) < 0)
			eerrorx("%s: chdir `%s': %s",
			    applet, ch_dir, strerror(errno));

		if (makepidfile && pidfile) {
			fp = fopen(pidfile, "w");
			if (! fp)
				eerrorx("%s: fopen `%s': %s", applet, pidfile,
				    strerror(errno));
			fprintf(fp, "%d\n", mypid);
			fclose(fp);
		}

#ifdef HAVE_PAM
		if (changeuser != NULL) {
			pamr = pam_start("start-stop-daemon",
			    changeuser, &conv, &pamh);

			if (pamr == PAM_SUCCESS)
				pamr = pam_acct_mgmt(pamh, PAM_SILENT);
			if (pamr == PAM_SUCCESS)
				pamr = pam_open_session(pamh, PAM_SILENT);
			if (pamr != PAM_SUCCESS)
				eerrorx("%s: pam error: %s",
					applet, pam_strerror(pamh, pamr));
		}
#endif

		if (gid && setgid(gid))
			eerrorx("%s: unable to set groupid to %d",
			    applet, gid);
		if (changeuser && initgroups(changeuser, gid))
			eerrorx("%s: initgroups (%s, %d)",
			    applet, changeuser, gid);
		if (uid && setuid(uid))
			eerrorx ("%s: unable to set userid to %d",
			    applet, uid);

		/* Close any fd's to the passwd database */
		endpwent();

#ifdef TIOCNOTTY
		ioctl(tty_fd, TIOCNOTTY, 0);
		close(tty_fd);
#endif

		/* Clean the environment of any RC_ variables */
		env_list = rc_stringlist_new();
		i = 0;
		while (environ[i])
			rc_stringlist_add(env_list, environ[i++]);

#ifdef HAVE_PAM
		if (changeuser != NULL) {
			pamenv = (const char *const *)pam_getenvlist(pamh);
			if (pamenv) {
				while (*pamenv) {
					/* Don't add strings unless they set a var */
					if (strchr(*pamenv, '='))
						putenv(xstrdup(*pamenv));
					else
						unsetenv(*pamenv);
					pamenv++;
				}
			}
		}
#endif

		TAILQ_FOREACH(env, env_list, entries) {
			if ((strncmp(env->value, "RC_", 3) == 0 &&
				strncmp(env->value, "RC_SERVICE=", 10) != 0 &&
				strncmp(env->value, "RC_SVCNAME=", 10) != 0) ||
				strncmp(env->value, "SSD_NICELEVEL=", 14) == 0 ||
				strncmp(env->value, "SSD_IONICELEVEL=", 16) == 0)
			{
				p = strchr(env->value, '=');
				*p = '\0';
				unsetenv(env->value);
				continue;
			}
		}
		rc_stringlist_free(env_list);

		/* For the path, remove the rcscript bin dir from it */
		if ((token = getenv("PATH"))) {
			len = strlen(token);
			newpath = np = xmalloc(len + 1);
			while (token && *token) {
				p = strchr(token, ':');
				if (p) {
					*p++ = '\0';
					while (*p == ':')
						p++;
				}
				if (strcmp(token, RC_LIBEXECDIR "/bin") != 0 &&
				    strcmp(token, RC_LIBEXECDIR "/sbin") != 0)
				{
					len = strlen(token);
					if (np != newpath)
						*np++ = ':';
					memcpy(np, token, len);
					np += len;
				}
				token = p;
			}
			*np = '\0';
			unsetenv("PATH");
			setenv("PATH", newpath, 1);
		}

		stdin_fd = devnull_fd;
		stdout_fd = devnull_fd;
		stderr_fd = devnull_fd;
		if (redirect_stdout) {
			if ((stdout_fd = open(redirect_stdout,
				    O_WRONLY | O_CREAT | O_APPEND,
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1)
				eerrorx("%s: unable to open the logfile"
				    " for stdout `%s': %s",
				    applet, redirect_stdout, strerror(errno));
		}
		if (redirect_stderr) {
			if ((stderr_fd = open(redirect_stderr,
				    O_WRONLY | O_CREAT | O_APPEND,
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1)
				eerrorx("%s: unable to open the logfile"
				    " for stderr `%s': %s",
				    applet, redirect_stderr, strerror(errno));
		}

		if (background)
			dup2(stdin_fd, STDIN_FILENO);
		if (background || redirect_stdout || rc_yesno(getenv("EINFO_QUIET")))
			dup2(stdout_fd, STDOUT_FILENO);
		if (background || redirect_stderr || rc_yesno(getenv("EINFO_QUIET")))
			dup2(stderr_fd, STDERR_FILENO);

		for (i = getdtablesize() - 1; i >= 3; --i)
			close(i);

		setsid();
		execvp(exec, argv);
#ifdef HAVE_PAM
		if (changeuser != NULL && pamr == PAM_SUCCESS)
			pam_close_session(pamh, PAM_SILENT);
#endif
		eerrorx("%s: failed to exec `%s': %s",
		    applet, exec,strerror(errno));
	}

	/* Parent process */
	if (!background) {
		/* As we're not backgrounding the process, wait for our pid
		 * to return */
		i = 0;
		spid = pid;

		do {
			pid = waitpid(spid, &i, 0);
			if (pid < 1) {
				eerror("waitpid %d: %s",
				    spid, strerror(errno));
				return -1;
			}
		} while (!WIFEXITED(i) && !WIFSIGNALED(i));
		if (!WIFEXITED(i) || WEXITSTATUS(i) != 0) {
			eerror("%s: failed to start `%s'", applet, exec);
			exit(EXIT_FAILURE);
		}
		pid = spid;
	}

	/* Wait a little bit and check that process is still running
	   We do this as some badly written daemons fork and then barf */
	if (start_wait == 0 &&
	    ((p = getenv("SSD_STARTWAIT")) ||
		(p = rc_conf_value("rc_start_wait"))))
	{
		if (sscanf(p, "%u", &start_wait) != 1)
			start_wait = 0;
	}

	if (start_wait > 0) {
		struct timespec ts;
		bool alive = false;

		ts.tv_sec = start_wait / 1000;
		ts.tv_nsec = (start_wait % 1000) * ONE_MS;
		if (nanosleep(&ts, NULL) == -1) {
			if (errno == EINTR)
				eerror("%s: caught an interrupt", applet);
			else {
				eerror("%s: nanosleep: %s",
				    applet, strerror(errno));
				return 0;
			}
		}
		if (background) {
			if (kill(pid, 0) == 0)
				alive = true;
		} else {
			if (pidfile) {
				pid = get_pid(applet, pidfile);
				if (pid == -1) {
					eerrorx("%s: did not "
					    "create a valid"
					    " pid in `%s'",
					    applet, pidfile);
				}
			} else
				pid = 0;
			if (do_stop(applet, exec, (const char *const *)margv,
				pid, uid, 0, test, false) > 0)
				alive = true;
		}

		if (!alive)
			eerrorx("%s: %s died", applet, exec);
	}

	if (svcname)
		rc_service_daemon_set(svcname, exec,
		    (const char *const *)margv, pidfile, true);

	exit(EXIT_SUCCESS);
	/* NOTREACHED */
}
