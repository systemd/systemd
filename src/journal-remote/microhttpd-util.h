/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_MICROHTTPD

#include <microhttpd.h>

#include "forward.h"

/* Those defines are added when options are renamed. If the old names
 * are not '#define'd, then they are not deprecated yet and there are
 * enum elements with the same name. Hence let's check for the *old* name,
 * and define the new name by the value of the old name. */

/* Renamed in μhttpd 0.9.51 */
#ifndef MHD_USE_PIPE_FOR_SHUTDOWN
#  define MHD_USE_ITC MHD_USE_PIPE_FOR_SHUTDOWN
#endif

/* Renamed in μhttpd 0.9.52 */
#ifndef MHD_USE_EPOLL_LINUX_ONLY
#  define MHD_USE_EPOLL MHD_USE_EPOLL_LINUX_ONLY
#endif

/* Renamed in μhttpd 0.9.52 */
#ifndef MHD_USE_SSL
#  define MHD_USE_TLS MHD_USE_SSL
#endif

/* Renamed in μhttpd 0.9.53 */
#ifndef MHD_USE_POLL_INTERNALLY
#  define MHD_USE_POLL_INTERNAL_THREAD MHD_USE_POLL_INTERNALLY
#endif

/* Both the old and new names are defines, check for the new one. */

/* Compatibility with libmicrohttpd < 0.9.38 */
#ifndef MHD_HTTP_NOT_ACCEPTABLE
#  define MHD_HTTP_NOT_ACCEPTABLE MHD_HTTP_METHOD_NOT_ACCEPTABLE
#endif

/* Renamed in μhttpd 0.9.74 (8c644fc1f4d498ea489add8d40a68f5d3e5899fa) */
#ifndef MHD_HTTP_CONTENT_TOO_LARGE
#  ifdef MHD_HTTP_PAYLOAD_TOO_LARGE
#    define MHD_HTTP_CONTENT_TOO_LARGE MHD_HTTP_PAYLOAD_TOO_LARGE /* 0.9.53 or newer */
#  else
#    define MHD_HTTP_CONTENT_TOO_LARGE MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
#  endif
#endif

#if MHD_VERSION < 0x00094203
#  define MHD_create_response_from_fd_at_offset64 MHD_create_response_from_fd_at_offset
#endif

#if MHD_VERSION >= 0x00097002
#  define mhd_result enum MHD_Result
#else
#  define mhd_result int
#endif

void microhttpd_logger(void *arg, const char *fmt, va_list ap) _printf_(2, 0);

/* respond_oom() must be usable with return, hence this form. */
#define respond_oom(connection) log_oom(), mhd_respond_oom(connection)

int mhd_respond_internal(
                struct MHD_Connection *connection,
                enum MHD_RequestTerminationCode code,
                const char *encoding,
                const char *buffer,
                size_t size,
                enum MHD_ResponseMemoryMode mode);

#define mhd_respond_with_encoding(connection, code, encoding, message)   \
        mhd_respond_internal(                                            \
             (connection), (code), (encoding),                           \
             message "\n",                                               \
             strlen(message) + 1,                                        \
             MHD_RESPMEM_PERSISTENT)

#define mhd_respond(connection, code, message)                     \
        mhd_respond_with_encoding(connection, code, NULL, message) \

int mhd_respond_oom(struct MHD_Connection *connection);

int mhd_respondf_internal(
                struct MHD_Connection *connection,
                int error,
                enum MHD_RequestTerminationCode code,
                const char *encoding,
                const char *format, ...) _printf_(5,6);

#define mhd_respondf(connection, error, code, format, ...)   \
        mhd_respondf_internal(                               \
                connection, error, code, NULL,               \
                format "\n",                                 \
                ##__VA_ARGS__)

int check_permissions(struct MHD_Connection *connection, int *code, char **hostname);

/* Set gnutls internal logging function to a callback which uses our
 * own logging framework.
 *
 * gnutls categories are additionally filtered by our internal log
 * level, so it should be set fairly high to capture all potentially
 * interesting events without overwhelming detail.
 */
int setup_gnutls_logger(char **categories);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct MHD_Daemon*, MHD_stop_daemon, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct MHD_Response*, MHD_destroy_response, NULL);

#endif
