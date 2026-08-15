/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"
#include "in-addr-util.h"

typedef struct ResolveError {
        int rcode;
        int ede_rcode;
        char *ede_msg;
        char *query_string;
        char *result;
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

typedef struct ResolvedRecord {
        int ifindex;
        struct iovec raw;
} ResolvedRecord;

typedef struct ResolveRecordReply {
        uint64_t flags;
        ResolvedRecord *records;
        size_t n_records;
} ResolveRecordReply;

void resolve_record_reply_done(ResolveRecordReply *reply);

int dispatch_resolve_record_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct ResolvedService {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char *hostname;
        char *canonical_name;
        ResolvedAddress *addresses;
        size_t n_addresses;
} ResolvedService;

typedef struct ResolvedCanonical {
        char *name;
        char *type;
        char *domain;
} ResolvedCanonical;

typedef struct ResolveServiceReply {
        ResolvedService *services;
        size_t n_services;
        char **txt;
        ResolvedCanonical canonical;
        uint64_t flags;
} ResolveServiceReply;

void resolve_service_reply_done(ResolveServiceReply *reply);

int dispatch_resolve_service_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
