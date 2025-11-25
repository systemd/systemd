/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"

int dm_deferred_remove_cancel(const char *name);

#if HAVE_LIBDEVMAPPER
#include <libdevmapper.h> /* IWYU pragma: export */

extern DLSYM_PROTOTYPE(dm_task_create);
extern DLSYM_PROTOTYPE(dm_task_destroy);
extern DLSYM_PROTOTYPE(dm_task_set_name);
extern DLSYM_PROTOTYPE(dm_task_add_target);
extern DLSYM_PROTOTYPE(dm_task_set_cookie);
extern DLSYM_PROTOTYPE(dm_task_run);
extern DLSYM_PROTOTYPE(dm_udev_wait);
extern DLSYM_PROTOTYPE(dm_task_set_sector);
extern DLSYM_PROTOTYPE(dm_task_set_message);

int dlopen_libdevmapper(void);
#endif
