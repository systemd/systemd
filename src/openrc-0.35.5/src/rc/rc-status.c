/*
 * rc-status.c
 * Display the status of the services in runlevels
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "einfo.h"
#include "queue.h"
#include "rc.h"
#include "rc-misc.h"
#include "_usage.h"

const char *applet = NULL;
const char *extraopts = NULL;
const char *getoptstring = "aclmrsu" getoptstring_COMMON;
const struct option longopts[] = {
	{"all",         0, NULL, 'a'},
	{"crashed",     0, NULL, 'c'},
	{"list",        0, NULL, 'l'},
	{"manual",        0, NULL, 'm'},
	{"runlevel",    0, NULL, 'r'},
	{"servicelist", 0, NULL, 's'},
	{"unused",      0, NULL, 'u'},
	longopts_COMMON
};
const char * const longopts_help[] = {
	"Show services from all run levels",
	"Show crashed services",
	"Show list of run levels",
	"Show manually started services",
	"Show the name of the current runlevel",
	"Show service list",
	"Show services not assigned to any runlevel",
	longopts_help_COMMON
};
const char *usagestring = ""						\
	"Usage: rc-status [options] <runlevel>...\n"		\
	"   or: rc-status [options] [-a | -c | -l | -m | -r | -s | -u]";

static bool test_crashed = false;
static RC_DEPTREE *deptree;
static RC_STRINGLIST *types;

static RC_STRINGLIST *levels, *services, *tmp, *alist;
static RC_STRINGLIST *sservices, *nservices, *needsme;

static void
print_level(const char *prefix, const char *level)
{
	if (prefix)
		printf("%s ", prefix);
	printf ("Runlevel: ");
	if (isatty(fileno(stdout)))
		printf("%s%s%s\n",
		       ecolor(ECOLOR_HILITE),
		       level,
		       ecolor(ECOLOR_NORMAL));
	else
		printf("%s\n", level);
}

static void get_uptime(const char *service, char *uptime, int uptime_size)
{
	RC_SERVICE state = rc_service_state(service);
	char *start_count;
	time_t now;
	char *start_time_string;
	time_t start_time;
	time_t time_diff;
	time_t diff_days = (time_t) 0;
	time_t diff_hours = (time_t) 0;
	time_t diff_mins = (time_t) 0;
	time_t diff_secs = (time_t) 0;

	uptime[0] = '\0';
	if (state & RC_SERVICE_STARTED) {
		start_count = rc_service_value_get(service, "start_count");
		start_time_string = rc_service_value_get(service, "start_time");
		if (start_count && start_time_string) {
			start_time = to_time_t(start_time_string);
			now = time(NULL);
			time_diff = (time_t) difftime(now, start_time);
			diff_secs = time_diff;
			if (diff_secs > (time_t) 86400) {
				diff_days = diff_secs / (time_t) 86400;
				diff_secs %= diff_days * (time_t) 86400;
			}
			if (diff_secs > (time_t) 3600) {
				diff_hours = diff_secs / (time_t) 3600;
				diff_secs %= diff_hours * (time_t) 3600;
			}
			if (diff_secs > (time_t) 60) {
				diff_mins = diff_secs / (time_t) 60;
				diff_secs %= diff_mins * (time_t) 60;
			}
			if (diff_days > 0)
				snprintf(uptime, uptime_size,
						"%ld day(s) %02ld:%02ld:%02ld (%s)",
						diff_days, diff_hours, diff_mins, diff_secs,
						start_count);
			else
				snprintf(uptime, uptime_size,
						"%02ld:%02ld:%02ld (%s)",
						diff_hours, diff_mins, diff_secs, start_count);
		}
	}
}

static void
print_service(const char *service)
{
	char status[60];
	char uptime [40];
	char *child_pid = NULL;
	char *start_time = NULL;
	int cols =  printf(" %s", service);
	const char *c = ecolor(ECOLOR_GOOD);
	RC_SERVICE state = rc_service_state(service);
	ECOLOR color = ECOLOR_BAD;

	if (state & RC_SERVICE_STOPPING)
		snprintf(status, sizeof(status), "stopping ");
	else if (state & RC_SERVICE_STARTING) {
		snprintf(status, sizeof(status), "starting ");
		color = ECOLOR_WARN;
	} else if (state & RC_SERVICE_INACTIVE) {
		snprintf(status, sizeof(status), "inactive ");
		color = ECOLOR_WARN;
	} else if (state & RC_SERVICE_STARTED) {
		errno = 0;
		if (test_crashed &&
		    rc_service_daemons_crashed(service) &&
		    errno != EACCES)
		{
			child_pid = rc_service_value_get(service, "child_pid");
			start_time = rc_service_value_get(service, "start_time");
			if (start_time && child_pid)
				snprintf(status, sizeof(status), " unsupervised ");
			else
				snprintf(status, sizeof(status), " crashed ");
			free(child_pid);
			free(start_time);
		} else {
			get_uptime(service, uptime, 40);
			snprintf(status, sizeof(status), " started %s", uptime);
			color = ECOLOR_GOOD;
		}
	} else if (state & RC_SERVICE_SCHEDULED) {
		snprintf(status, sizeof(status), "scheduled");
		color = ECOLOR_WARN;
	} else
		snprintf(status, sizeof(status), " stopped ");

	errno = 0;
	if (c && *c && isatty(fileno(stdout)))
		printf("\n");
	ebracket(cols, color, status);
}

static void
print_services(const char *runlevel, RC_STRINGLIST *svcs)
{
	RC_STRINGLIST *l = NULL;
	RC_STRING *s;
	char *r = NULL;

	if (!svcs)
		return;
	if (!deptree)
		deptree = _rc_deptree_load(0, NULL);
	if (!deptree) {
		TAILQ_FOREACH(s, svcs, entries)
			if (!runlevel ||
			    rc_service_in_runlevel(s->value, runlevel))
				print_service(s->value);
		return;
	}
	if (!types) {
		types = rc_stringlist_new();
		rc_stringlist_add(types, "ineed");
		rc_stringlist_add(types, "iuse");
		rc_stringlist_add(types, "iafter");
	}
	if (!runlevel)
		r = rc_runlevel_get();
	l = rc_deptree_depends(deptree, types, svcs, r ? r : runlevel,
			       RC_DEP_STRICT | RC_DEP_TRACE | RC_DEP_START);
	free(r);
	if (!l)
		return;
	TAILQ_FOREACH(s, l, entries) {
		if (!rc_stringlist_find(svcs, s->value))
			continue;
		if (!runlevel || rc_service_in_runlevel(s->value, runlevel))
			print_service(s->value);
	}
	rc_stringlist_free(l);
}

static void
print_stacked_services(const char *runlevel)
{
	RC_STRINGLIST *stackedlevels, *servicelist;
	RC_STRING *stackedlevel;

	stackedlevels = rc_runlevel_stacks(runlevel);
	TAILQ_FOREACH(stackedlevel, stackedlevels, entries) {
		if (rc_stringlist_find(levels, stackedlevel->value) != NULL)
			continue;
		print_level("Stacked", stackedlevel->value);
		servicelist = rc_services_in_runlevel(stackedlevel->value);
		print_services(stackedlevel->value, servicelist);
		rc_stringlist_free(servicelist);
	}
	rc_stringlist_free(stackedlevels);
	stackedlevels = NULL;
}

int main(int argc, char **argv)
{
    RC_STRING *s, *l, *t, *level;
	bool show_all = false;
	char *p, *runlevel = NULL;
	int opt, retval = 0;

	test_crashed = _rc_can_find_pids();

	applet = basename_c(argv[0]);
	while ((opt = getopt_long(argc, argv, getoptstring, longopts,
				  (int *) 0)) != -1)
		switch (opt) {
		case 'a':
			show_all = true;
			levels = rc_runlevel_list();
			break;
		case 'c':
			services = rc_services_in_state(RC_SERVICE_STARTED);
			retval = 1;
			TAILQ_FOREACH(s, services, entries)
				if (rc_service_daemons_crashed(s->value)) {
					printf("%s\n", s->value);
					retval = 0;
				}
			goto exit;
			/* NOTREACHED */
		case 'l':
			levels = rc_runlevel_list();
			TAILQ_FOREACH(l, levels, entries)
				printf("%s\n", l->value);
			goto exit;
		case 'm':
			services = rc_services_in_runlevel(NULL);
			levels = rc_runlevel_list();
			TAILQ_FOREACH_SAFE(s, services, entries, t) {
				TAILQ_FOREACH(l, levels, entries)
					if (rc_service_in_runlevel(s->value, l->value)) {
						TAILQ_REMOVE(services, s, entries);
						free(s->value);
						free(s);
						break;
					}
			}
			TAILQ_FOREACH_SAFE(s, services, entries, t)
				if (rc_service_state(s->value) &
					(RC_SERVICE_STOPPED | RC_SERVICE_HOTPLUGGED)) {
					TAILQ_REMOVE(services, s, entries);
					free(s->value);
					free(s);
				}
			print_services(NULL, services);
			goto exit;
		case 'r':
			runlevel = rc_runlevel_get();
			printf("%s\n", runlevel);
			goto exit;
			/* NOTREACHED */
		case 's':
			services = rc_services_in_runlevel(NULL);
			print_services(NULL, services);
			goto exit;
			/* NOTREACHED */
		case 'u':
			services = rc_services_in_runlevel(NULL);
			levels = rc_runlevel_list();
			TAILQ_FOREACH_SAFE(s, services, entries, t) {
				TAILQ_FOREACH(l, levels, entries)
					if (rc_service_in_runlevel(s->value, l->value)) {
						TAILQ_REMOVE(services, s, entries);
						free(s->value);
						free(s);
						break;
					}
			}
			print_services(NULL, services);
			goto exit;
			/* NOTREACHED */

		case_RC_COMMON_GETOPT
		}

	if (!levels)
		levels = rc_stringlist_new();
	opt = (optind < argc) ? 0 : 1;
	while (optind < argc) {
		if (rc_runlevel_exists(argv[optind])) {
			rc_stringlist_add(levels, argv[optind++]);
			opt++;
		} else
			eerror("runlevel `%s' does not exist", argv[optind++]);
	}
	if (opt == 0)
		exit(EXIT_FAILURE);
	if (!TAILQ_FIRST(levels)) {
		runlevel = rc_runlevel_get();
		rc_stringlist_add(levels, runlevel);
	}

	/* Output the services in the order in which they would start */
	deptree = _rc_deptree_load(0, NULL);

	TAILQ_FOREACH(l, levels, entries) {
		print_level(NULL, l->value);
		services = rc_services_in_runlevel(l->value);
		print_services(l->value, services);
		print_stacked_services(l->value);
		rc_stringlist_free(nservices);
		nservices = NULL;
		rc_stringlist_free(services);
		services = NULL;
	}

	if (show_all || argc < 2) {
		/* Show hotplugged services */
		print_level("Dynamic", "hotplugged");
		services = rc_services_in_state(RC_SERVICE_HOTPLUGGED);
		print_services(NULL, services);
		rc_stringlist_free(services);
		services = NULL;

		/* Show manually started and unassigned depended services */
		if (show_all) {
			rc_stringlist_free(levels);
			levels = rc_stringlist_new();
			if (!runlevel)
				runlevel = rc_runlevel_get();
			rc_stringlist_add(levels, runlevel);
		}
		rc_stringlist_add(levels, RC_LEVEL_SYSINIT);
		rc_stringlist_add(levels, RC_LEVEL_BOOT);
		services = rc_services_in_runlevel(NULL);
		sservices = rc_stringlist_new();
		TAILQ_FOREACH(l, levels, entries) {
			nservices = rc_services_in_runlevel_stacked(l->value);
			TAILQ_CONCAT(sservices, nservices, entries);
			free(nservices);
		}
		TAILQ_FOREACH_SAFE(s, services, entries, t) {
			if ((rc_stringlist_find(sservices, s->value) ||
			    (rc_service_state(s->value) & ( RC_SERVICE_STOPPED | RC_SERVICE_HOTPLUGGED)))) {
				TAILQ_REMOVE(services, s, entries);
				free(s->value);
				free(s);
			}
		}
		needsme = rc_stringlist_new();
		rc_stringlist_add(needsme, "needsme");
		rc_stringlist_add(needsme, "wantsme");
		nservices = rc_stringlist_new();
		alist = rc_stringlist_new();
		l = rc_stringlist_add(alist, "");
		p = l->value;
		TAILQ_FOREACH(level, levels, entries) {
			TAILQ_FOREACH_SAFE(s, services, entries, t) {
				l->value = s->value;
				setenv("RC_SVCNAME", l->value, 1);
				tmp = rc_deptree_depends(deptree, needsme, alist, level->value, RC_DEP_TRACE);
				if (TAILQ_FIRST(tmp)) {
					TAILQ_REMOVE(services, s, entries);
					TAILQ_INSERT_TAIL(nservices, s, entries);
				}
				rc_stringlist_free(tmp);
			}
		}
		l->value = p;
		/*
		 * we are unsetting RC_SVCNAME because last loaded service will not
		 * be added to the list
		 */
		unsetenv("RC_SVCNAME");
		print_level("Dynamic", "needed/wanted");
		print_services(NULL, nservices);
		print_level("Dynamic", "manual");
		print_services(NULL, services);
	}

exit:
	free(runlevel);
	rc_stringlist_free(alist);
	rc_stringlist_free(needsme);
	rc_stringlist_free(sservices);
	rc_stringlist_free(nservices);
	rc_stringlist_free(services);
	rc_stringlist_free(types);
	rc_stringlist_free(levels);
	rc_deptree_free(deptree);

	return retval;
}
