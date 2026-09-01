/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

extern const BusObjectImplementation dns_service_browser_object;

int bus_method_browse_services(sd_bus_message *message, void *userdata, sd_bus_error *error);
