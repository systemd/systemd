/*
 * rc-misc.h
 * This is private to us and not for user consumption
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

#ifndef __RC_MISC_H__
#define __RC_MISC_H__

#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "helpers.h"

#define RC_LEVEL_BOOT           "boot"
#define RC_LEVEL_DEFAULT        "default"

#define RC_DEPTREE_CACHE        RC_SVCDIR "/deptree"
#define RC_DEPTREE_SKEWED	RC_SVCDIR "/clock-skewed"
#define RC_KRUNLEVEL            RC_SVCDIR "/krunlevel"
#define RC_STARTING             RC_SVCDIR "/rc.starting"
#define RC_STOPPING             RC_SVCDIR "/rc.stopping"

#define RC_SVCDIR_STARTING      RC_SVCDIR "/starting"
#define RC_SVCDIR_INACTIVE      RC_SVCDIR "/inactive"
#define RC_SVCDIR_STARTED       RC_SVCDIR "/started"
#define RC_SVCDIR_COLDPLUGGED	RC_SVCDIR "/coldplugged"

char *rc_conf_value(const char *var);
bool rc_conf_yesno(const char *var);
void env_filter(void);
void env_config(void);
int signal_setup(int sig, void (*handler)(int));
int signal_setup_restart(int sig, void (*handler)(int));
int svc_lock(const char *);
int svc_unlock(const char *, int);
pid_t exec_service(const char *, const char *);

/*
 * Check whether path is writable or not,
 * this also works properly with read-only filesystems
 */
int is_writable(const char *);

#define service_start(service) exec_service(service, "start");
#define service_stop(service)  exec_service(service, "stop");

int parse_mode(mode_t *, char *);

/* Handy function so we can wrap einfo around our deptree */
RC_DEPTREE *_rc_deptree_load (int, int *);

/* Test to see if we can see pid 1 or not */
bool _rc_can_find_pids(void);

RC_SERVICE lookup_service_state(const char *service);
void from_time_t(char *time_string, time_t tv);
time_t to_time_t(char *timestring);
pid_t get_pid(const char *applet, const char *pidfile);

#endif
