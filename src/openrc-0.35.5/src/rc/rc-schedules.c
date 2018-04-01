/*
 * The functions in this file control the stopping of daemons by
 * start-stop-daemon and supervise-daemon.
 */

/*
 * Copyright (c) 2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

/* nano seconds */
#define POLL_INTERVAL   20000000
#define WAIT_PIDFILE   500000000
#define ONE_SECOND    1000000000
#define ONE_MS           1000000

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-misc.h"
#include "rc-schedules.h"
#include "helpers.h"

typedef struct scheduleitem {
	enum {
		SC_TIMEOUT,
		SC_SIGNAL,
		SC_GOTO,
		SC_FOREVER,
	} type;
	int value;
	struct scheduleitem *gotoitem;
	TAILQ_ENTRY(scheduleitem) entries;
} SCHEDULEITEM;

static TAILQ_HEAD(, scheduleitem) schedule;

void free_schedulelist(void)
{
	SCHEDULEITEM *s1 = TAILQ_FIRST(&schedule);
	SCHEDULEITEM *s2;

	while (s1) {
		s2 = TAILQ_NEXT(s1, entries);
		free(s1);
		s1 = s2;
	}
	TAILQ_INIT(&schedule);
}

int parse_signal(const char *applet, const char *sig)
{
	typedef struct signalpair
	{
		const char *name;
		int signal;
	} SIGNALPAIR;

#define signalpair_item(name) { #name, SIG##name },

	static const SIGNALPAIR signallist[] = {
		signalpair_item(HUP)
		signalpair_item(INT)
		signalpair_item(QUIT)
		signalpair_item(ILL)
		signalpair_item(TRAP)
		signalpair_item(ABRT)
		signalpair_item(BUS)
		signalpair_item(FPE)
		signalpair_item(KILL)
		signalpair_item(USR1)
		signalpair_item(SEGV)
		signalpair_item(USR2)
		signalpair_item(PIPE)
		signalpair_item(ALRM)
		signalpair_item(TERM)
		signalpair_item(CHLD)
		signalpair_item(CONT)
		signalpair_item(STOP)
		signalpair_item(TSTP)
		signalpair_item(TTIN)
		signalpair_item(TTOU)
		signalpair_item(URG)
		signalpair_item(XCPU)
		signalpair_item(XFSZ)
		signalpair_item(VTALRM)
		signalpair_item(PROF)
#ifdef SIGWINCH
		signalpair_item(WINCH)
#endif
#ifdef SIGIO
		signalpair_item(IO)
#endif
#ifdef SIGPWR
		signalpair_item(PWR)
#endif
		signalpair_item(SYS)
		{ "NULL",	0 },
	};

	unsigned int i = 0;
	const char *s;

	if (!sig || *sig == '\0')
		return -1;

	if (sscanf(sig, "%u", &i) == 1) {
		if (i < NSIG)
			return i;
		eerrorx("%s: `%s' is not a valid signal", applet, sig);
	}

	if (strncmp(sig, "SIG", 3) == 0)
		s = sig + 3;
	else
		s = NULL;

	for (i = 0; i < ARRAY_SIZE(signallist); ++i)
		if (strcmp(sig, signallist[i].name) == 0 ||
		    (s && strcmp(s, signallist[i].name) == 0))
			return signallist[i].signal;

	eerrorx("%s: `%s' is not a valid signal", applet, sig);
	/* NOTREACHED */
}

static SCHEDULEITEM *parse_schedule_item(const char *applet, const char *string)
{
	const char *after_hyph;
	int sig;
	SCHEDULEITEM *item = xmalloc(sizeof(*item));

	item->value = 0;
	item->gotoitem = NULL;
	if (strcmp(string,"forever") == 0)
		item->type = SC_FOREVER;
	else if (isdigit((unsigned char)string[0])) {
		item->type = SC_TIMEOUT;
		errno = 0;
		if (sscanf(string, "%d", &item->value) != 1)
			eerrorx("%s: invalid timeout value in schedule `%s'",
			    applet, string);
	} else if ((after_hyph = string + (string[0] == '-')) &&
	    ((sig = parse_signal(applet, after_hyph)) != -1))
	{
		item->type = SC_SIGNAL;
		item->value = (int)sig;
	} else
		eerrorx("%s: invalid schedule item `%s'", applet, string);

	return item;
}

void parse_schedule(const char *applet, const char *string, int timeout)
{
	char buffer[20];
	const char *slash;
	int count = 0;
	SCHEDULEITEM *repeatat = NULL;
	size_t len;
	SCHEDULEITEM *item;

	TAILQ_INIT(&schedule);
	if (string)
		for (slash = string; *slash; slash++)
			if (*slash == '/')
				count++;

	free_schedulelist();

	if (count == 0) {
		item = xmalloc(sizeof(*item));
		item->type = SC_SIGNAL;
		item->value = timeout;
		item->gotoitem = NULL;
		TAILQ_INSERT_TAIL(&schedule, item, entries);

		item = xmalloc(sizeof(*item));
		item->type = SC_TIMEOUT;
		item->gotoitem = NULL;
		TAILQ_INSERT_TAIL(&schedule, item, entries);
		if (string) {
			if (sscanf(string, "%d", &item->value) != 1)
				eerrorx("%s: invalid timeout in schedule",
				    applet);
		} else
			item->value = 5;

		return;
	}

	while (string != NULL) {
		if ((slash = strchr(string, '/')))
			len = slash - string;
		else
			len = strlen(string);

		if (len >= (ptrdiff_t)sizeof(buffer))
			eerrorx("%s: invalid schedule item, far too long",
			    applet);

		memcpy(buffer, string, len);
		buffer[len] = 0;
		string = slash ? slash + 1 : NULL;

		item = parse_schedule_item(applet, buffer);
		TAILQ_INSERT_TAIL(&schedule, item, entries);
		if (item->type == SC_FOREVER) {
			if (repeatat)
				eerrorx("%s: invalid schedule, `forever' "
				    "appears more than once", applet);

			repeatat = item;
			continue;
		}
	}

	if (repeatat) {
		item = xmalloc(sizeof(*item));
		item->type = SC_GOTO;
		item->value = 0;
		item->gotoitem = repeatat;
		TAILQ_INSERT_TAIL(&schedule, item, entries);
	}

	return;
}

/* return number of processes killed, -1 on error */
int do_stop(const char *applet, const char *exec, const char *const *argv,
    pid_t pid, uid_t uid,int sig, bool test, bool quiet)
{
	RC_PIDLIST *pids;
	RC_PID *pi;
	RC_PID *np;
	bool killed;
	int nkilled = 0;

	if (pid > 0)
		pids = rc_find_pids(NULL, NULL, 0, pid);
	else
		pids = rc_find_pids(exec, argv, uid, 0);

	if (!pids)
		return 0;

	LIST_FOREACH_SAFE(pi, pids, entries, np) {
		if (test) {
			einfo("Would send signal %d to PID %d", sig, pi->pid);
			nkilled++;
		} else {
			if (!quiet)
				ebeginv("Sending signal %d to PID %d", sig, pi->pid);
			errno = 0;
			killed = (kill(pi->pid, sig) == 0 ||
			    errno == ESRCH ? true : false);
			if (! quiet)
				eendv(killed ? 0 : 1,
				"%s: failed to send signal %d to PID %d: %s",
				applet, sig, pi->pid, strerror(errno));
			if (!killed) {
				nkilled = -1;
			} else {
				if (nkilled != -1)
					nkilled++;
			}
		}
		free(pi);
	}

	free(pids);
	return nkilled;
}

int run_stop_schedule(const char *applet,
		const char *exec, const char *const *argv,
		pid_t pid, uid_t uid,
    bool test, bool progress, bool quiet)
{
	SCHEDULEITEM *item = TAILQ_FIRST(&schedule);
	int nkilled = 0;
	int tkilled = 0;
	int nrunning = 0;
	long nloops, nsecs;
	struct timespec ts;
	const char *const *p;
	bool progressed = false;

	if (!(pid > 0 || exec || uid || (argv && *argv)))
		return 0;

	if (exec)
		einfov("Will stop %s", exec);
	if (pid > 0)
		einfov("Will stop PID %d", pid);
	if (uid)
		einfov("Will stop processes owned by UID %d", uid);
	if (argv && *argv) {
		einfovn("Will stop processes of `");
		if (rc_yesno(getenv("EINFO_VERBOSE"))) {
			for (p = argv; p && *p; p++) {
				if (p != argv)
					printf(" ");
				printf("%s", *p);
			}
			printf("'\n");
		}
	}

	while (item) {
		switch (item->type) {
		case SC_GOTO:
			item = item->gotoitem;
			continue;

		case SC_SIGNAL:
			nrunning = 0;
			nkilled = do_stop(applet, exec, argv, pid, uid, item->value, test,
					quiet);
			if (nkilled == 0) {
				if (tkilled == 0) {
					if (progressed)
						printf("\n");
					eerror("%s: no matching processes found", applet);
				}
				return tkilled;
			}
			else if (nkilled == -1)
				return 0;

			tkilled += nkilled;
			break;
		case SC_TIMEOUT:
			if (item->value < 1) {
				item = NULL;
				break;
			}

			ts.tv_sec = 0;
			ts.tv_nsec = POLL_INTERVAL;

			for (nsecs = 0; nsecs < item->value; nsecs++) {
				for (nloops = 0;
				     nloops < ONE_SECOND / POLL_INTERVAL;
				     nloops++)
				{
					if ((nrunning = do_stop(applet, exec, argv,
						    pid, uid, 0, test, quiet)) == 0)
						return 0;


					if (nanosleep(&ts, NULL) == -1) {
						if (progressed) {
							printf("\n");
							progressed = false;
						}
						if (errno == EINTR)
							eerror("%s: caught an"
							    " interrupt", applet);
						else {
							eerror("%s: nanosleep: %s",
							    applet, strerror(errno));
							return 0;
						}
					}
				}
				if (progress) {
					printf(".");
					fflush(stdout);
					progressed = true;
				}
			}
			break;
		default:
			if (progressed) {
				printf("\n");
				progressed = false;
			}
			eerror("%s: invalid schedule item `%d'",
			    applet, item->type);
			return 0;
		}

		if (item)
			item = TAILQ_NEXT(item, entries);
	}

	if (test || (tkilled > 0 && nrunning == 0))
		return nkilled;

	if (progressed)
		printf("\n");
	if (! quiet) {
		if (nrunning == 1)
			eerror("%s: %d process refused to stop", applet, nrunning);
		else
			eerror("%s: %d process(es) refused to stop", applet, nrunning);
	}

	return -nrunning;
}
