/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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

typedef struct ResolvedName {
        int ifindex;
        char *name;
} ResolvedName;

ResolvedName* resolved_name_free(ResolvedName *name);
DEFINE_TRIVIAL_CLEANUP_FUNC(ResolvedName*, resolved_name_free);

typedef struct ResolveAddressReply {
        uint64_t flags;
        OrderedSet *names;
} ResolveAddressReply;

ResolveAddressReply* resolve_address_reply_free(ResolveAddressReply *reply);
DEFINE_TRIVIAL_CLEANUP_FUNC(ResolveAddressReply*, resolve_address_reply_free);

int dispatch_resolve_address_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
