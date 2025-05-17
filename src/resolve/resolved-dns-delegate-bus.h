/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct BusObjectImplementation BusObjectImplementation;
typedef struct DnsDelegate DnsDelegate;

extern const BusObjectImplementation dns_delegate_object;

char* dns_delegate_bus_path(const DnsDelegate *d);
