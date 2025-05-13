/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum FactoryResetMode {
        FACTORY_RESET_UNSUPPORTED,    /* feature not available on this OS */
        FACTORY_RESET_UNSPECIFIED,    /* not specified on the kernel cmdline, nor via EFI variable */
        FACTORY_RESET_OFF,            /* explicitly turned off on kernel cmdline */
        FACTORY_RESET_ON,             /* turned on via kernel cmdline or EFI variable */
        FACTORY_RESET_COMPLETE,       /* turned on via kernel cmdline or EFI variable, but marked as complete now */
        FACTORY_RESET_PENDING,        /* marked for next boot via EFI variable, but not in effect on this boot */
        _FACTORY_RESET_MODE_MAX,
        _FACTORY_RESET_MODE_INVALID = -EINVAL,
        _FACTORY_RESET_MODE_ERRNO_MAX = -ERRNO_MAX,
} FactoryResetMode;

FactoryResetMode factory_reset_mode(void);

const char* factory_reset_mode_to_string(FactoryResetMode) _const_;
FactoryResetMode factory_reset_mode_from_string(const char *s) _pure_;
