/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"

int dm_deferred_remove_cancel(const char *name);

#if HAVE_LIBDEVMAPPER
#include <libdevmapper.h> /* IWYU pragma: export */

//extern DLSYM_PROTOTYPE(dm_backend_init);
extern DLSYM_PROTOTYPE(dm_task_set_name);
extern DLSYM_PROTOTYPE(dm_task_create);

int dlopen_libdevmapper(void);
#endif
