/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"
#include "shared-forward.h"

typedef struct ResolveError {
        int rcode;
        int ede_rcode;
        char *ede_msg;
        char *query_string;
} ResolveError;

void resolve_error_done(ResolveError *error);

int dispatch_resolve_error(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedAddress {
        int ifindex;
        int family;
        struct in_addr_data in_addr;
} ResolvedAddress;

typedef struct ResolveHostnameReply {
        char *name;
        uint64_t flags;
        ResolvedAddress *addresses;
        size_t n_addresses;
} ResolveHostnameReply;

void resolve_hostname_reply_done(ResolveHostnameReply *reply);

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedName {
        int ifindex;
        char *name;
} ResolvedName;

typedef struct ResolveAddressReply {
        uint64_t flags;
        ResolvedName *names;
        size_t n_names;
} ResolveAddressReply;

void resolve_address_reply_done(ResolveAddressReply *reply);

int dispatch_resolve_address_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
