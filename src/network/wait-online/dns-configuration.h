/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "in-addr-util.h"
#include "macro-fundamental.h"
#include "set.h"

typedef struct DNSServer DNSServer;
typedef struct DNSConfiguration DNSConfiguration;

struct DNSServer {
        union in_addr_union addr;
        int family;
        uint16_t port;
        int ifindex;
        char *server_name;
        bool accessible;
};

DNSServer *dns_server_free(DNSServer *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSServer*, dns_server_free);

struct DNSConfiguration {
        char *ifname;
        int ifindex;
        DNSServer *current_dns_server;
        Set *dns_servers;
        char **search_domains;
};

int dns_configuration_from_json(sd_json_variant *variant, DNSConfiguration **ret);
bool dns_is_accessible(DNSConfiguration *c);

DNSConfiguration *dns_configuration_free(DNSConfiguration *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSConfiguration*, dns_configuration_free);
