/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-manager.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"

void manager_etc_hosts_flush(Manager *m);
int manager_etc_hosts_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer);
