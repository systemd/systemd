/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-manager.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"

typedef struct EtcHostsItemByAddress {
        struct in_addr_data address;
        Set *names;
        const char *canonical_name;
} EtcHostsItemByAddress;

typedef struct EtcHostsItemByName {
        char *name;
        Set *addresses;
} EtcHostsItemByName;

int etc_hosts_parse(EtcHosts *hosts, FILE *f);
void etc_hosts_clear(EtcHosts *hosts);

void manager_etc_hosts_flush(Manager *m);
int manager_etc_hosts_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer);
