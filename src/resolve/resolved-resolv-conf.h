/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

int manager_check_resolv_conf(const Manager *m);
int manager_read_resolv_conf(Manager *m);
int manager_write_resolv_conf(Manager *m);

typedef enum ResolvConfMode {
        RESOLV_CONF_UPLINK,
        RESOLV_CONF_STUB,
        RESOLV_CONF_STATIC,
        RESOLV_CONF_FOREIGN,
        RESOLV_CONF_MISSING,
        _RESOLV_CONF_MODE_MAX,
        _RESOLV_CONF_MODE_INVALID = -EINVAL,
} ResolvConfMode;

int resolv_conf_mode(void);

DECLARE_STRING_TABLE_LOOKUP(resolv_conf_mode, ResolvConfMode);
