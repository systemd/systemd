/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-manager.h"

int dns_stub_listener_extra_new(DnsStubListenerExtra **ret);
DnsStubListenerExtra *dns_stub_listener_extra_free(DnsStubListenerExtra *p);

void manager_dns_stub_stop(Manager *m);
int manager_dns_stub_start(Manager *m);
