/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_SYS_SDT_H
#define SDT_USE_VARIADIC
#include <sys/sdt.h>

#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "forward.h"

/* Each trace point can have different number of additional arguments. Note that when the macro is used only
 * additional arguments are listed in the macro invocation!
 *
 * Default arguments for each trace point are as follows:
 *   - arg0 - action
 *   - arg1 - sysname
 *   - arg2 - syspath
 *   - arg3 - subsystem
 */
#define DEVICE_TRACE_POINT(name, dev, ...)                                                                 \
        do {                                                                                               \
                PROTECT_ERRNO;                                                                             \
                const char *_n = NULL, *_p = NULL, *_s = NULL;                                             \
                sd_device *_d = (dev);                                                                     \
                sd_device_action_t _a = _SD_DEVICE_ACTION_INVALID;                                         \
                (void) sd_device_get_action(_d, &_a);                                                      \
                (void) sd_device_get_sysname(_d, &_n);                                                     \
                (void) sd_device_get_syspath(_d, &_p);                                                     \
                (void) sd_device_get_subsystem(_d, &_s);                                                   \
                STAP_PROBEV(udev, name, device_action_to_string(_a), _n, _p, _s __VA_OPT__(,) __VA_ARGS__);\
        } while (false);
#else
#define DEVICE_TRACE_POINT(name, dev, ...) ((void) 0)
#endif
