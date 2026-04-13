/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "resolved-forward.h"

#define DELEGATE_SEARCH_DOMAINS_MAX 1024
#define DELEGATE_DNS_SERVERS_MAX 256

/* A DnsDelegate object is used to manage additional, explicitly configured unicast DNS lookup scopes,
 * independent from any network link and from the global scope. */

typedef struct DnsDelegate {
        Manager *manager;
        char *id;

        LIST_HEAD(DnsServer, dns_servers);
        unsigned n_dns_servers;
        DnsServer *current_dns_server;

        LIST_HEAD(DnsSearchDomain, search_domains);
        unsigned n_search_domains;

        int default_route;

        uint32_t fwmark;

        DnsScope *scope;

        LIST_FIELDS(DnsDelegate, delegates);
} DnsDelegate;

int dns_delegate_new(Manager *m, const char *id, DnsDelegate **ret);
DnsDelegate *dns_delegate_free(DnsDelegate *d);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsDelegate*, dns_delegate_free);

DnsServer* dns_delegate_set_dns_server(DnsDelegate *d, DnsServer *s);
DnsServer *dns_delegate_get_dns_server(DnsDelegate *d);
void dns_delegate_next_dns_server(DnsDelegate *d, DnsServer *if_current);

int manager_load_delegates(Manager *m);

const struct ConfigPerfItem* resolved_dns_delegate_gperf_lookup(const char *str, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_delegate_dns_servers);
CONFIG_PARSER_PROTOTYPE(config_parse_delegate_domains);
