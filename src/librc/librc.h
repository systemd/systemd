/*
 * librc.h
 * Internal header file to setup build env for files in librc.so
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

#ifndef _LIBRC_H_
#define _LIBRC_H_

#define _IN_LIBRC

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <paths.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#if defined(BSD) && !defined(__GNU__)
#include <sys/param.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <kvm.h>
#else
#include <sys/param.h>
#endif

#include "rc.h"
#include "rc-misc.h"

#include "hidden-visibility.h"
#define librc_hidden_proto(x) hidden_proto(x)
#define librc_hidden_def(x) hidden_def(x)

librc_hidden_proto(rc_conf_value)
librc_hidden_proto(rc_config_list)
librc_hidden_proto(rc_config_load)
librc_hidden_proto(rc_config_value)
librc_hidden_proto(rc_deptree_depend)
librc_hidden_proto(rc_deptree_depends)
librc_hidden_proto(rc_deptree_free)
librc_hidden_proto(rc_deptree_load)
librc_hidden_proto(rc_deptree_load_file)
librc_hidden_proto(rc_deptree_order)
librc_hidden_proto(rc_deptree_update)
librc_hidden_proto(rc_deptree_update_needed)
librc_hidden_proto(rc_find_pids)
librc_hidden_proto(rc_getfile)
librc_hidden_proto(rc_getline)
librc_hidden_proto(rc_newer_than)
librc_hidden_proto(rc_proc_getent)
librc_hidden_proto(rc_older_than)
librc_hidden_proto(rc_runlevel_exists)
librc_hidden_proto(rc_runlevel_get)
librc_hidden_proto(rc_runlevel_list)
librc_hidden_proto(rc_runlevel_set)
librc_hidden_proto(rc_runlevel_stack)
librc_hidden_proto(rc_runlevel_stacks)
librc_hidden_proto(rc_runlevel_starting)
librc_hidden_proto(rc_runlevel_stopping)
librc_hidden_proto(rc_runlevel_unstack)
librc_hidden_proto(rc_service_add)
librc_hidden_proto(rc_service_daemons_crashed)
librc_hidden_proto(rc_service_daemon_set)
librc_hidden_proto(rc_service_delete)
librc_hidden_proto(rc_service_description)
librc_hidden_proto(rc_service_exists)
librc_hidden_proto(rc_service_extra_commands)
librc_hidden_proto(rc_service_in_runlevel)
librc_hidden_proto(rc_service_mark)
librc_hidden_proto(rc_service_resolve)
librc_hidden_proto(rc_service_schedule_clear)
librc_hidden_proto(rc_service_schedule_start)
librc_hidden_proto(rc_services_in_runlevel)
librc_hidden_proto(rc_services_in_runlevel_stacked)
librc_hidden_proto(rc_services_in_state)
librc_hidden_proto(rc_services_scheduled)
librc_hidden_proto(rc_services_scheduled_by)
librc_hidden_proto(rc_service_started_daemon)
librc_hidden_proto(rc_service_state)
librc_hidden_proto(rc_service_value_get)
librc_hidden_proto(rc_service_value_set)
librc_hidden_proto(rc_stringlist_add)
librc_hidden_proto(rc_stringlist_addu)
librc_hidden_proto(rc_stringlist_delete)
librc_hidden_proto(rc_stringlist_find)
librc_hidden_proto(rc_stringlist_free)
librc_hidden_proto(rc_stringlist_new)
librc_hidden_proto(rc_stringlist_split)
librc_hidden_proto(rc_stringlist_sort)
librc_hidden_proto(rc_sys)
librc_hidden_proto(rc_yesno)

#endif
