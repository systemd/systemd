/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-manager.h"

int dns_stub_extra_new(DNSStubListenerExtra **ret);

void manager_dns_stub_stop(Manager *m);
void manager_dns_stub_stop_extra(Manager *m);
int manager_dns_stub_start(Manager *m);
