/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

enum DnsProtocol : int;
typedef enum DnsProtocol DnsProtocol;

typedef struct DnsAnswer DnsAnswer;
typedef struct DnsQuestion DnsQuestion;
typedef struct Manager Manager;

int dns_synthesize_family(uint64_t flags);
DnsProtocol dns_synthesize_protocol(uint64_t flags);

int dns_synthesize_answer(Manager *m, DnsQuestion *q, int ifindex, DnsAnswer **ret);

bool shall_synthesize_own_hostname_rrs(void);
