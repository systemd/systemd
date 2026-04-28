/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "in-addr-util.h"
#include "shared-forward.h"

typedef struct ResolvedAddress {
        int ifindex;
        int family;
        union in_addr_union in_addr;
} ResolvedAddress;

ResolvedAddress* resolved_address_free(ResolvedAddress *address);
DEFINE_TRIVIAL_CLEANUP_FUNC(ResolvedAddress*, resolved_address_free);

typedef struct ResolveHostnameReply {
        char *name;
        uint64_t flags;
        OrderedSet *addresses;
} ResolveHostnameReply;

ResolveHostnameReply* resolve_hostname_reply_free(ResolveHostnameReply *reply);
DEFINE_TRIVIAL_CLEANUP_FUNC(ResolveHostnameReply*, resolve_hostname_reply_free);

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
