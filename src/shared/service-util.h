/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-object.h"

int service_parse_argv(
                const char *service,
                const char *description,
                const BusObjectImplementation* const* bus_objects,
                int argc, char *argv[]);
