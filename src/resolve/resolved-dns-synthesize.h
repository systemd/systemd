/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-manager.h"

int dns_synthesize_ifindex(int ifindex);
int dns_synthesize_family(uint64_t flags);
DnsProtocol dns_synthesize_protocol(uint64_t flags);

int dns_synthesize_answer(Manager *m, DnsQuestion *q, int ifindex, DnsAnswer **ret);
