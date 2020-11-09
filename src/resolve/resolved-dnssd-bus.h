/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "sd-bus.h"

#include "bus-object.h"

extern const BusObjectImplementation dnssd_object;

int bus_dnssd_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error);
