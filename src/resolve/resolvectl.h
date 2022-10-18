/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <in-addr-util.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum ExecutionMode {
        MODE_RESOLVE_HOST,
        MODE_RESOLVE_RECORD,
        MODE_RESOLVE_SERVICE,
        MODE_RESOLVE_OPENPGP,
        MODE_RESOLVE_TLSA,
        MODE_STATISTICS,
        MODE_RESET_STATISTICS,
        MODE_FLUSH_CACHES,
        MODE_RESET_SERVER_FEATURES,
        MODE_STATUS,
        MODE_SET_LINK,
        MODE_REVERT_LINK,
        _MODE_INVALID = -EINVAL,
} ExecutionMode;

extern ExecutionMode arg_mode;
extern char **arg_set_dns;
extern char **arg_set_domain;
extern bool arg_ifindex_permissive;

int ifname_mangle_full(const char *s, bool drop_protocol_specifier);
static inline int ifname_mangle(const char *s) {
        return ifname_mangle_full(s, false);
}
static inline int ifname_resolvconf_mangle(const char *s) {
        return ifname_mangle_full(s, true);
}
