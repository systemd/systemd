#pragma once

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

#include <microhttpd.h>
#include <stdarg.h>

#include "macro.h"

/* Those defines are added when options are renamed, hence the check for the *old* name. */

/* Compatiblity with libmicrohttpd < 0.9.38 */
#ifndef MHD_HTTP_NOT_ACCEPTABLE
#  define MHD_HTTP_NOT_ACCEPTABLE MHD_HTTP_METHOD_NOT_ACCEPTABLE
#endif

/* Renamed in µhttpd 0.9.51 */
#ifndef MHD_USE_PIPE_FOR_SHUTDOWN
#  define MHD_USE_ITC MHD_USE_PIPE_FOR_SHUTDOWN
#endif

/* Renamed in µhttpd 0.9.52 */
#ifndef MHD_USE_EPOLL_LINUX_ONLY
#  define MHD_USE_EPOLL MHD_USE_EPOLL_LINUX_ONLY
#endif

/* Both the old and new names are defines, check for the new one. */

/* Renamed in µhttpd 0.9.53 */
#ifndef MHD_HTTP_PAYLOAD_TOO_LARGE
#  define MHD_HTTP_PAYLOAD_TOO_LARGE MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
#endif

#if MHD_VERSION < 0x00094203
#  define MHD_create_response_from_fd_at_offset64 MHD_create_response_from_fd_at_offset
#endif

void microhttpd_logger(void *arg, const char *fmt, va_list ap) _printf_(2, 0);

/* respond_oom() must be usable with return, hence this form. */
#define respond_oom(connection) log_oom(), mhd_respond_oom(connection)

int mhd_respondf(struct MHD_Connection *connection,
                 int error,
                 unsigned code,
                 const char *format, ...) _printf_(4,5);

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
