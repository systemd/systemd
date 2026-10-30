/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Each service links report-server.c (entry point and server lifecycle) with one provider implementation
 * (e.g. report-basic.c), which defines COMMAND() with .option_namespace = "common", since the command
 * line is parsed with common_parse_argv(), and the two symbols below. */

/* See report-example.c for a minimal provider. */

/* Provider-defined flags passed to varlink_server_new(); access restrictions apply to all interfaces. */
extern const sd_varlink_server_flags_t report_server_flags;

/* Provider-defined initialization and interface registration, called before the event loop.
 * Borrows the server; returns zero or a negative errno. */
int report_server_setup(sd_varlink_server *server);

/* Shared registration helpers for report_server_setup(); a provider may use either or both. */
int report_server_add_metrics_interface(sd_varlink_server *server, sd_varlink_method_t list, sd_varlink_method_t describe);
int report_server_add_signer_interface(sd_varlink_server *server, sd_varlink_method_t sign);
