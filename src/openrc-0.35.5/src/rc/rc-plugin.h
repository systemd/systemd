/*
 * rc-plugin.h
 * Private instructions to use plugins
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

#ifndef __LIBRC_PLUGIN_H__
#define __LIBRC_PLUGIN_H__

/* A simple flag to say if we're in a plugin proccess or not.
 * Mainly used in atexit code. */
extern bool rc_in_plugin;

int rc_waitpid(pid_t pid);
void rc_plugin_load(void);
void rc_plugin_unload(void);
void rc_plugin_run(RC_HOOK, const char *value);

/* dlfunc defines needed to avoid ISO errors. FreeBSD has this right :) */
#if !defined(__FreeBSD__) && !defined(__DragonFly__)
struct __dlfunc_arg {
	int	__dlfunc_dummy;
};

typedef	void (*dlfunc_t)(struct __dlfunc_arg);

dlfunc_t dlfunc (void * __restrict handle, const char * __restrict symbol);
#endif

#endif
