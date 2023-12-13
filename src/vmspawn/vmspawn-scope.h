/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

int start_transient_scope(sd_bus *bus, const char *machine_name, char **ret_scope);
int run_command_bound_to_scope(sd_bus *bus, const char *scope, const char *service_name, char **cmdline,
                               char **cleanup_cmdline, char **extra_properties);
int attach_command_to_socket_in_scope(sd_bus *bus, const char *scope, const char *unit_name, const char *socket_path,
                                      int socket_type, char **cmdline, char **cleanup_cmdline, char **extra_properties);
