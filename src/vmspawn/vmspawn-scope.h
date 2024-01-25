/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

int start_transient_scope(sd_bus *bus, const char *machine_name, bool allow_pidfd, char **ret_scope);
int attach_command_to_socket_in_scope(sd_bus *bus, const char *scope, const char *unit_name, const char *socket_path,
                                      int socket_type, char **cmdline, char **cleanup_cmdline, char **extra_properties);
