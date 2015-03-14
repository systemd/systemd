/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include <stdarg.h>
#include <microhttpd.h>

#include "macro.h"

void microhttpd_logger(void *arg, const char *fmt, va_list ap) _printf_(2, 0);

/* respond_oom() must be usable with return, hence this form. */
#define respond_oom(connection) log_oom(), mhd_respond_oom(connection)

int mhd_respondf(struct MHD_Connection *connection,
                 unsigned code,
                 const char *format, ...) _printf_(3,4);

int mhd_respond(struct MHD_Connection *connection,
                unsigned code,
                const char *message);

int mhd_respond_oom(struct MHD_Connection *connection);

int check_permissions(struct MHD_Connection *connection, int *code, char **hostname);

/* Set gnutls internal logging function to a callback which uses our
 * own logging framework.
 *
 * gnutls categories are additionally filtered by our internal log
 * level, so it should be set fairly high to capture all potentially
 * interesting events without overwhelming detail.
 */
int setup_gnutls_logger(char **categories);
