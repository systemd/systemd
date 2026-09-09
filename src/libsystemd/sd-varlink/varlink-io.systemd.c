/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.h"

static SD_VARLINK_DEFINE_METHOD(
                GetServerCredentials,
                SD_VARLINK_FIELD_COMMENT("The UID of the server process."),
                SD_VARLINK_DEFINE_OUTPUT(uid, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The GID of the server process."),
                SD_VARLINK_DEFINE_OUTPUT(gid, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Index into the file descriptor array identifying a PIDFD of the server process, if file descriptor passing is enabled on the connection."),
                SD_VARLINK_DEFINE_OUTPUT(pidfdIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The PID of the server process."),
                SD_VARLINK_DEFINE_OUTPUT(pid, SD_VARLINK_INT, 0));

/* These are local errors that never cross the wire, and are our own invention */
static SD_VARLINK_DEFINE_ERROR(Disconnected);
static SD_VARLINK_DEFINE_ERROR(TimedOut);
static SD_VARLINK_DEFINE_ERROR(Protocol);

/* This one we invented, and use for generically propagating system errors (errno) to clients */
static SD_VARLINK_DEFINE_ERROR(
                System,
                SD_VARLINK_FIELD_COMMENT("The origin of this system error, typically 'linux' to indicate Linux error numbers."),
                SD_VARLINK_DEFINE_FIELD(origin, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Linux error name, i.e. ENOENT, EHWPOISON or similar."),
                SD_VARLINK_DEFINE_FIELD(errnoName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The numeric Linux error number. Typically the name is preferable, if specified."),
                SD_VARLINK_DEFINE_FIELD(errno, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd,
                "io.systemd",
                SD_VARLINK_SYMBOL_COMMENT("Returns credentials of the server process handling this connection."),
                &vl_method_GetServerCredentials,
                SD_VARLINK_SYMBOL_COMMENT("Local error if a Varlink connection is disconnected (this never crosses the wire and is synthesized locally only)."),
                &vl_error_Disconnected,
                SD_VARLINK_SYMBOL_COMMENT("A method call time-out has been reached (also synthesized locally, does not cross wire)"),
                &vl_error_TimedOut,
                SD_VARLINK_SYMBOL_COMMENT("Some form of protocol error (also synthesized locally, does not cross wire)"),
                &vl_error_Protocol,
                SD_VARLINK_SYMBOL_COMMENT("A generic Linux system error (\"errno\"s)."),
                &vl_error_System);
