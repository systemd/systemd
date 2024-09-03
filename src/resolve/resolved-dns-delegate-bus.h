/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-object.h"
#include "bus-util.h"
#include "resolved-dns-delegate.h"

extern const BusObjectImplementation dns_delegate_object;

char* dns_delegate_bus_path(const DnsDelegate *d);
