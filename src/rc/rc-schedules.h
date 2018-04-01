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

#ifndef __RC_SCHEDULES_H
#define __RC_SCHEDULES_H

void free_schedulelist(void);
int parse_signal(const char *applet, const char *sig);
void parse_schedule(const char *applet, const char *string, int timeout);
int do_stop(const char *applet, const char *exec, const char *const *argv,
		pid_t pid, uid_t uid,int sig, bool test, bool quiet);
int run_stop_schedule(const char *applet,
		const char *exec, const char *const *argv,
		pid_t pid, uid_t uid,
		bool test, bool progress, bool quiet);

#endif
