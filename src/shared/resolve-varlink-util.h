/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "shared-forward.h"

typedef struct ResolvedAddress {
        int ifindex;
        int family;
        union in_addr_union in_addr;
} ResolvedAddress;

typedef struct ResolveHostnameReply {
        char *name;
        uint64_t flags;
        ResolvedAddress *addresses;
        size_t n_addresses;
} ResolveHostnameReply;

void resolve_hostname_reply_done(ResolveHostnameReply *reply);

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
