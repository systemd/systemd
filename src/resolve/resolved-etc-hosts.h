/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-manager.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"

typedef struct EtcHostsItem {
        struct in_addr_data address;

        char **names;
        size_t n_names;
} EtcHostsItem;

typedef struct EtcHostsItemByName {
        char *name;

        struct in_addr_data **addresses;
        size_t n_addresses;
} EtcHostsItemByName;

int etc_hosts_parse(EtcHosts *hosts, FILE *f);
void etc_hosts_free(EtcHosts *hosts);

void manager_etc_hosts_flush(Manager *m);
int manager_etc_hosts_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer);
