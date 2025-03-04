/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-idl-common.h"
#include "varlink-io.systemd.Login.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                SessionType,
                SD_VARLINK_DEFINE_ENUM_VALUE(unspecified),
                SD_VARLINK_DEFINE_ENUM_VALUE(tty),
                SD_VARLINK_DEFINE_ENUM_VALUE(x11),
                SD_VARLINK_DEFINE_ENUM_VALUE(wayland),
                SD_VARLINK_DEFINE_ENUM_VALUE(mir),
                SD_VARLINK_DEFINE_ENUM_VALUE(web));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                SessionClass,
                SD_VARLINK_FIELD_COMMENT("Regular user sessions"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user),
                SD_VARLINK_FIELD_COMMENT("Session of the root user that shall be open for login from earliest moment on, and not be delayed for /run/nologin"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user_early),
                SD_VARLINK_FIELD_COMMENT("Regular user session whose home directory is not available right now, but will be later, at which point the session class can be upgraded to 'user'"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user_incomplete),
                SD_VARLINK_FIELD_COMMENT("A user session that doesn't pull in the per-user service manager"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user_light),
                SD_VARLINK_FIELD_COMMENT("The combination of user_early and user_light"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user_early_light),
                SD_VARLINK_FIELD_COMMENT("Display manager greeter screen used for login"),
                SD_VARLINK_DEFINE_ENUM_VALUE(greeter),
                SD_VARLINK_FIELD_COMMENT("Similar, but a a lock screen"),
                SD_VARLINK_DEFINE_ENUM_VALUE(lock_screen),
                SD_VARLINK_FIELD_COMMENT("Background session (that has no TTY, VT, Seat)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(background),
                SD_VARLINK_FIELD_COMMENT("Similar, but for which no service manager is invoked"),
                SD_VARLINK_DEFINE_ENUM_VALUE(background_light),
                SD_VARLINK_FIELD_COMMENT("The special session of the service manager"),
                SD_VARLINK_DEFINE_ENUM_VALUE(manager),
                SD_VARLINK_FIELD_COMMENT("The special session of the service manager for the root user"),
                SD_VARLINK_DEFINE_ENUM_VALUE(manager_early));

static SD_VARLINK_DEFINE_METHOD(
                CreateSession,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID of the user this session shall be owned by"),
                SD_VARLINK_DEFINE_INPUT(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Process that shall become the leader of the session. If null defaults to the IPC client."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(PID, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("PAM service name of the program requesting the session"),
                SD_VARLINK_DEFINE_INPUT(Service, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of the session"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(Type, SessionType, 0),
                SD_VARLINK_FIELD_COMMENT("The class of the session"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(Class, SessionClass, 0),
                SD_VARLINK_FIELD_COMMENT("An identifier for the chosen desktop"),
                SD_VARLINK_DEFINE_INPUT(Desktop, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The name of the seat to assign this session to"),
                SD_VARLINK_DEFINE_INPUT(Seat, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The virtual terminal number to assign this session to"),
                SD_VARLINK_DEFINE_INPUT(VTNr, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The TTY device to assign this session to, if applicable"),
                SD_VARLINK_DEFINE_INPUT(TTY, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The X11 display for this session"),
                SD_VARLINK_DEFINE_INPUT(Display, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true this is a remote session"),
                SD_VARLINK_DEFINE_INPUT(Remote, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("User name on the remote site, if known"),
                SD_VARLINK_DEFINE_INPUT(RemoteUser, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Host name of the remote host"),
                SD_VARLINK_DEFINE_INPUT(RemoteHost, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session of the user."),
                SD_VARLINK_DEFINE_OUTPUT(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The runtime path ($XDG_RUNTIME_DIR) of the user."),
                SD_VARLINK_DEFINE_OUTPUT(RuntimePath, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Index into the file descriptor table of this reply with the session tracking fd for this session."),
                SD_VARLINK_DEFINE_OUTPUT(SessionFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The original UID of this session."),
                SD_VARLINK_DEFINE_OUTPUT(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The seat this session has been assigned to"),
                SD_VARLINK_DEFINE_OUTPUT(Seat, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The virtual terminal number the session has been assigned to"),
                SD_VARLINK_DEFINE_OUTPUT(VTNr, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The assigned session type"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Type, SessionType, 0),
                SD_VARLINK_FIELD_COMMENT("The assigned session class"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Class, SessionClass, 0));

static SD_VARLINK_DEFINE_METHOD(
                ReleaseSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session to release. If unspecified or 'self', will return the callers session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchSession);
static SD_VARLINK_DEFINE_ERROR(NoSuchSeat);
static SD_VARLINK_DEFINE_ERROR(AlreadySessionMember);
static SD_VARLINK_DEFINE_ERROR(VirtualTerminalAlreadyTaken);
static SD_VARLINK_DEFINE_ERROR(TooManySessions);
static SD_VARLINK_DEFINE_ERROR(UnitAllocationFailed);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Login,
                "io.systemd.Login",
                SD_VARLINK_INTERFACE_COMMENT("APIs for managing login sessions."),
                SD_VARLINK_SYMBOL_COMMENT("Process identifier"),
                &vl_type_ProcessId,
                SD_VARLINK_SYMBOL_COMMENT("Various types of sessions"),
                &vl_type_SessionType,
                SD_VARLINK_SYMBOL_COMMENT("Various classes of sessions"),
                &vl_type_SessionClass,
                SD_VARLINK_SYMBOL_COMMENT("Allocates a new session."),
                &vl_method_CreateSession,
                SD_VARLINK_SYMBOL_COMMENT("Releases an existing session. Currently, will be refuses unless originating from the session to release itself."),
                &vl_method_ReleaseSession,
                SD_VARLINK_SYMBOL_COMMENT("No session by this name found"),
                &vl_error_NoSuchSession,
                SD_VARLINK_SYMBOL_COMMENT("No seat by this name found"),
                &vl_error_NoSuchSeat,
                SD_VARLINK_SYMBOL_COMMENT("Process already member of a session"),
                &vl_error_AlreadySessionMember,
                SD_VARLINK_SYMBOL_COMMENT("The specified virtual terminal (VT) is already taken by another session"),
                &vl_error_VirtualTerminalAlreadyTaken,
                SD_VARLINK_SYMBOL_COMMENT("Maximum number of sessions reached"),
                &vl_error_TooManySessions,
                SD_VARLINK_SYMBOL_COMMENT("Failed to allocate a unit for the session"),
                &vl_error_UnitAllocationFailed);
