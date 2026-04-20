/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
                SD_VARLINK_FIELD_COMMENT("List of additional hardware devices that this session is granted access to."
                                         "For every $ID in the list, this adds access for all devices tagged with \"xaccess-$ID\" in udev."),
                SD_VARLINK_DEFINE_INPUT(ExtraDeviceAccess, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session of the user."),
                SD_VARLINK_DEFINE_OUTPUT(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The runtime path ($XDG_RUNTIME_DIR) of the user."),
                SD_VARLINK_DEFINE_OUTPUT(RuntimePath, SD_VARLINK_STRING, 0),
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

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SessionUser,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("User name"),
                SD_VARLINK_DEFINE_FIELD(Name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SessionInfo,
                SD_VARLINK_FIELD_COMMENT("The session identifier"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The user owning this session"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(User, SessionUser, 0),
                SD_VARLINK_FIELD_COMMENT("The session timestamps"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Virtual terminal number of the session, if applicable"),
                SD_VARLINK_DEFINE_FIELD(VTNr, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Seat this session is assigned to"),
                SD_VARLINK_DEFINE_FIELD(Seat, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("TTY device of the session"),
                SD_VARLINK_DEFINE_FIELD(TTY, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("X11 display of the session"),
                SD_VARLINK_DEFINE_FIELD(Display, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether this is a remote session"),
                SD_VARLINK_DEFINE_FIELD(Remote, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Remote host, if this is a remote session"),
                SD_VARLINK_DEFINE_FIELD(RemoteHost, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Remote user, if this is a remote session"),
                SD_VARLINK_DEFINE_FIELD(RemoteUser, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("PAM service name"),
                SD_VARLINK_DEFINE_FIELD(Service, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Desktop identifier"),
                SD_VARLINK_DEFINE_FIELD(Desktop, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("systemd scope unit name"),
                SD_VARLINK_DEFINE_FIELD(Scope, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Device paths this session has special access to"),
                SD_VARLINK_DEFINE_FIELD(ExtraDeviceAccess, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("PID of the session leader"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Leader, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Audit session ID"),
                SD_VARLINK_DEFINE_FIELD(Audit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of the session"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Type, SessionType, 0),
                SD_VARLINK_FIELD_COMMENT("The class of the session"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Class, SessionClass, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the session is active (i.e. in the foreground)"),
                SD_VARLINK_DEFINE_FIELD(Active, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Current state of the session"),
                SD_VARLINK_DEFINE_FIELD(State, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the session is idle"),
                SD_VARLINK_DEFINE_FIELD(IdleHint, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Realtime timestamp when the session went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHint, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Monotonic timestamp when the session went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHintMonotonic, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether this session class supports idle tracking"),
                SD_VARLINK_DEFINE_FIELD(CanIdle, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether this session class supports locking"),
                SD_VARLINK_DEFINE_FIELD(CanLock, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the session is currently locked"),
                SD_VARLINK_DEFINE_FIELD(LockedHint, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                DescribeSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self'/'auto', returns the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The session information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Session, SessionInfo, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListSessions,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The session information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Session, SessionInfo, 0));

static SD_VARLINK_DEFINE_METHOD(
                ReleaseSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session to release. If unspecified or 'self', will return the callers session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ActivateSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self'/'auto', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                LockSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified, locks all sessions."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                UnlockSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified, unlocks all sessions."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                TerminateSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                KillWhom,
                SD_VARLINK_DEFINE_ENUM_VALUE(leader),
                SD_VARLINK_DEFINE_ENUM_VALUE(all));

static SD_VARLINK_DEFINE_METHOD(
                KillSession,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whom to kill in the session. If unspecified, defaults to 'all'."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(Whom, KillWhom, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX signal to send."),
                SD_VARLINK_DEFINE_INPUT(Signal, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetIdleHint,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the session is idle."),
                SD_VARLINK_DEFINE_INPUT(IdleHint, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLockedHint,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the session is locked."),
                SD_VARLINK_DEFINE_INPUT(LockedHint, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                TakeControl,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, take control even if another controller is active."),
                SD_VARLINK_DEFINE_INPUT(Force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Device event notifications will be sent as replies to this call."),
                SD_VARLINK_DEFINE_OUTPUT(Type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Major, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Minor, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ReleaseControl,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                TakeDevice,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Major device number."),
                SD_VARLINK_DEFINE_INPUT(Major, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Minor device number."),
                SD_VARLINK_DEFINE_INPUT(Minor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the device is currently inactive."),
                SD_VARLINK_DEFINE_OUTPUT(Inactive, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                ReleaseDevice,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Major device number."),
                SD_VARLINK_DEFINE_INPUT(Major, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Minor device number."),
                SD_VARLINK_DEFINE_INPUT(Minor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                PauseDeviceComplete,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Major device number."),
                SD_VARLINK_DEFINE_INPUT(Major, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Minor device number."),
                SD_VARLINK_DEFINE_INPUT(Minor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetType,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The session type to set."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(Type, SessionType, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetDisplay,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The display to set."),
                SD_VARLINK_DEFINE_INPUT(Display, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetClass,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The session class to set. Currently only 'user' is allowed (upgrading from 'user-incomplete')."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(Class, SessionClass, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetBrightness,
                SD_VARLINK_FIELD_COMMENT("The device subsystem, either 'backlight' or 'leds'."),
                SD_VARLINK_DEFINE_INPUT(Subsystem, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The device sysfs name."),
                SD_VARLINK_DEFINE_INPUT(Name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The brightness value to set."),
                SD_VARLINK_DEFINE_INPUT(Brightness, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(NotInControl);
static SD_VARLINK_DEFINE_ERROR(DeviceIsTaken);
static SD_VARLINK_DEFINE_ERROR(DeviceNotTaken);

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SessionRef,
                SD_VARLINK_FIELD_COMMENT("The session identifier"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                UserInfo,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX GID"),
                SD_VARLINK_DEFINE_FIELD(GID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("User name"),
                SD_VARLINK_DEFINE_FIELD(Name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The user timestamps"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to the user's runtime directory"),
                SD_VARLINK_DEFINE_FIELD(RuntimePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Service manager unit name"),
                SD_VARLINK_DEFINE_FIELD(Service, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("User slice unit name"),
                SD_VARLINK_DEFINE_FIELD(Slice, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Display session identifier"),
                SD_VARLINK_DEFINE_FIELD(Display, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Current state of the user"),
                SD_VARLINK_DEFINE_FIELD(State, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("List of session references belonging to this user"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Sessions, SessionRef, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether the user is idle"),
                SD_VARLINK_DEFINE_FIELD(IdleHint, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Realtime timestamp when the user went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHint, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Monotonic timestamp when the user went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHintMonotonic, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether lingering is enabled for this user"),
                SD_VARLINK_DEFINE_FIELD(Linger, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                DescribeUser,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID of the user. If unspecified, returns the caller's user."),
                SD_VARLINK_DEFINE_INPUT(UID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The user information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(User, UserInfo, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListUsers,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The user information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(User, UserInfo, 0));

static SD_VARLINK_DEFINE_METHOD(
                TerminateUser,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID of the user to terminate."),
                SD_VARLINK_DEFINE_INPUT(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                KillUser,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID of the user."),
                SD_VARLINK_DEFINE_INPUT(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The UNIX signal to send."),
                SD_VARLINK_DEFINE_INPUT(Signal, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetUserLinger,
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX UID of the user. If unspecified, targets the caller's user."),
                SD_VARLINK_DEFINE_INPUT(UID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to enable or disable lingering."),
                SD_VARLINK_DEFINE_INPUT(Enable, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SeatInfo,
                SD_VARLINK_FIELD_COMMENT("The seat identifier"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The currently active session on this seat, if any"),
                SD_VARLINK_DEFINE_FIELD(ActiveSession, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("List of session references assigned to this seat"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Sessions, SessionRef, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether this seat supports text terminal sessions"),
                SD_VARLINK_DEFINE_FIELD(CanTTY, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether this seat supports graphical sessions"),
                SD_VARLINK_DEFINE_FIELD(CanGraphical, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the seat is idle"),
                SD_VARLINK_DEFINE_FIELD(IdleHint, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Realtime timestamp when the seat went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHint, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Monotonic timestamp when the seat went idle"),
                SD_VARLINK_DEFINE_FIELD(IdleSinceHintMonotonic, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                DescribeSeat,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the seat. If unspecified or 'self'/'auto', returns the caller's seat."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The seat information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Seat, SeatInfo, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListSeats,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The seat information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Seat, SeatInfo, 0));

static SD_VARLINK_DEFINE_METHOD(
                TerminateSeat,
                SD_VARLINK_FIELD_COMMENT("The seat identifier."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ActivateSessionOnSeat,
                SD_VARLINK_FIELD_COMMENT("The session identifier."),
                SD_VARLINK_DEFINE_INPUT(SessionId, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The seat identifier."),
                SD_VARLINK_DEFINE_INPUT(SeatId, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SwitchTo,
                SD_VARLINK_FIELD_COMMENT("The seat identifier. If unspecified or 'self'/'auto', targets the caller's seat."),
                SD_VARLINK_DEFINE_INPUT(SeatId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The virtual terminal number to switch to."),
                SD_VARLINK_DEFINE_INPUT(VTNr, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SwitchToNext,
                SD_VARLINK_FIELD_COMMENT("The seat identifier. If unspecified or 'self'/'auto', targets the caller's seat."),
                SD_VARLINK_DEFINE_INPUT(SeatId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SwitchToPrevious,
                SD_VARLINK_FIELD_COMMENT("The seat identifier. If unspecified or 'self'/'auto', targets the caller's seat."),
                SD_VARLINK_DEFINE_INPUT(SeatId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                PowerOff,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Reboot,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Halt,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Suspend,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Hibernate,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                HybridSleep,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SuspendThenHibernate,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Sleep,
                SD_VARLINK_FIELD_COMMENT("Optional flags for the operation."),
                SD_VARLINK_DEFINE_INPUT(Flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CanPowerOff,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanReboot,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanHalt,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanSuspend,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanHibernate,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanHybridSleep,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanSuspendThenHibernate,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                CanSleep,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ScheduleShutdown,
                SD_VARLINK_FIELD_COMMENT("The type of shutdown, e.g. 'poweroff', 'reboot', 'halt'."),
                SD_VARLINK_DEFINE_INPUT(Type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The time at which to shut down, in microseconds since the epoch. Use UINT64_MAX for the next maintenance window."),
                SD_VARLINK_DEFINE_INPUT(USec, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CancelScheduledShutdown,
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether a scheduled shutdown was actually cancelled."),
                SD_VARLINK_DEFINE_OUTPUT(Cancelled, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                Inhibit,
                SD_VARLINK_FIELD_COMMENT("What to inhibit, a colon-separated list of: shutdown, sleep, idle, handle-power-key, handle-suspend-key, handle-hibernate-key, handle-lid-switch, handle-reboot-key"),
                SD_VARLINK_DEFINE_INPUT(What, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A human-readable descriptive string of who is taking the inhibition"),
                SD_VARLINK_DEFINE_INPUT(Who, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A human-readable descriptive string of why the inhibition is taken"),
                SD_VARLINK_DEFINE_INPUT(Why, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The inhibition mode: block, block-weak, or delay"),
                SD_VARLINK_DEFINE_INPUT(Mode, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetRebootParameter,
                SD_VARLINK_FIELD_COMMENT("The reboot parameter string."),
                SD_VARLINK_DEFINE_INPUT(Parameter, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CanRebootParameter,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetWallMessage,
                SD_VARLINK_FIELD_COMMENT("The wall message text."),
                SD_VARLINK_DEFINE_INPUT(WallMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to enable wall messages."),
                SD_VARLINK_DEFINE_INPUT(Enable, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetRebootToFirmwareSetup,
                SD_VARLINK_FIELD_COMMENT("Whether to boot into firmware setup on next reboot."),
                SD_VARLINK_DEFINE_INPUT(Enable, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CanRebootToFirmwareSetup,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetRebootToBootLoaderMenu,
                SD_VARLINK_FIELD_COMMENT("Timeout in microseconds to show the boot loader menu. Use UINT64_MAX to disable."),
                SD_VARLINK_DEFINE_INPUT(Timeout, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CanRebootToBootLoaderMenu,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetRebootToBootLoaderEntry,
                SD_VARLINK_FIELD_COMMENT("The boot loader entry to select on next reboot. Empty string to disable."),
                SD_VARLINK_DEFINE_INPUT(Entry, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                CanRebootToBootLoaderEntry,
                SD_VARLINK_DEFINE_OUTPUT(Result, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                AttachDevice,
                SD_VARLINK_FIELD_COMMENT("The seat to attach the device to."),
                SD_VARLINK_DEFINE_INPUT(SeatId, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The sysfs path of the device."),
                SD_VARLINK_DEFINE_INPUT(SysfsPath, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                FlushDevices,
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                DescribeManager,
                SD_VARLINK_FIELD_COMMENT("The manager state as a JSON object."),
                SD_VARLINK_DEFINE_OUTPUT(Manager, SD_VARLINK_OBJECT, 0));

static SD_VARLINK_DEFINE_METHOD(
                SubscribeManagerEvents,
                SD_VARLINK_FIELD_COMMENT("The event type (SessionNew, SessionRemoved, UserNew, UserRemoved, SeatNew, SeatRemoved, PrepareForShutdown, PrepareForSleep)."),
                SD_VARLINK_DEFINE_OUTPUT(Event, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Event-specific data."),
                SD_VARLINK_DEFINE_OUTPUT(Data, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Sent once when the subscription is established."),
                SD_VARLINK_DEFINE_OUTPUT(Ready, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SubscribeSessionEvents,
                SD_VARLINK_FIELD_COMMENT("The identifier string of the session. If unspecified or 'self'/'auto', targets the caller's session."),
                SD_VARLINK_DEFINE_INPUT(Id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The event type (Lock, Unlock)."),
                SD_VARLINK_DEFINE_OUTPUT(Event, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Sent once when the subscription is established."),
                SD_VARLINK_DEFINE_OUTPUT(Ready, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                InhibitorInfo,
                SD_VARLINK_FIELD_COMMENT("The inhibitor identifier"),
                SD_VARLINK_DEFINE_FIELD(Id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("What is being inhibited, a colon-separated list of shutdown, sleep, idle, handle-power-key, handle-suspend-key, handle-hibernate-key, handle-lid-switch, handle-reboot-key"),
                SD_VARLINK_DEFINE_FIELD(What, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A human-readable descriptive string of who is taking the inhibition"),
                SD_VARLINK_DEFINE_FIELD(Who, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A human-readable descriptive string of why the inhibition is taken"),
                SD_VARLINK_DEFINE_FIELD(Why, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The inhibition mode, one of block, block-weak, or delay"),
                SD_VARLINK_DEFINE_FIELD(Mode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The UID of the user taking the inhibition"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The PID of the process taking the inhibition"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PID, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The inhibitor timestamps"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Since, Timestamp, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListInhibitors,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The inhibitor information"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Inhibitor, InhibitorInfo, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchSession);
static SD_VARLINK_DEFINE_ERROR(NoSuchUser);
static SD_VARLINK_DEFINE_ERROR(NoSuchSeat);
static SD_VARLINK_DEFINE_ERROR(NoSuchInhibitor);
static SD_VARLINK_DEFINE_ERROR(AlreadySessionMember);
static SD_VARLINK_DEFINE_ERROR(VirtualTerminalAlreadyTaken);
static SD_VARLINK_DEFINE_ERROR(TooManySessions);
static SD_VARLINK_DEFINE_ERROR(UnitAllocationFailed);
static SD_VARLINK_DEFINE_ERROR(NoSessionPIDFD);
static SD_VARLINK_DEFINE_ERROR(NotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Login,
                "io.systemd.Login",
                SD_VARLINK_INTERFACE_COMMENT("APIs for managing login sessions."),
                SD_VARLINK_SYMBOL_COMMENT("Process identifier"),
                &vl_type_ProcessId,
                SD_VARLINK_SYMBOL_COMMENT("Dual timestamp"),
                &vl_type_Timestamp,
                SD_VARLINK_SYMBOL_COMMENT("Various types of sessions"),
                &vl_type_SessionType,
                SD_VARLINK_SYMBOL_COMMENT("Various classes of sessions"),
                &vl_type_SessionClass,
                SD_VARLINK_SYMBOL_COMMENT("User owning a session"),
                &vl_type_SessionUser,
                SD_VARLINK_SYMBOL_COMMENT("Information about a session"),
                &vl_type_SessionInfo,
                SD_VARLINK_SYMBOL_COMMENT("Allocates a new session."),
                &vl_method_CreateSession,
                SD_VARLINK_SYMBOL_COMMENT("Releases an existing session. Currently, will be refused unless originating from the session to release itself."),
                &vl_method_ReleaseSession,
                SD_VARLINK_SYMBOL_COMMENT("Describes a specific session."),
                &vl_method_DescribeSession,
                SD_VARLINK_SYMBOL_COMMENT("Lists all current sessions."),
                &vl_method_ListSessions,
                SD_VARLINK_SYMBOL_COMMENT("Reference to a session by identifier"),
                &vl_type_SessionRef,
                SD_VARLINK_SYMBOL_COMMENT("Activates a session, i.e. brings it to the foreground."),
                &vl_method_ActivateSession,
                SD_VARLINK_SYMBOL_COMMENT("Locks a session or all sessions."),
                &vl_method_LockSession,
                SD_VARLINK_SYMBOL_COMMENT("Unlocks a session or all sessions."),
                &vl_method_UnlockSession,
                SD_VARLINK_SYMBOL_COMMENT("Terminates a session."),
                &vl_method_TerminateSession,
                SD_VARLINK_SYMBOL_COMMENT("Whom to kill in a session"),
                &vl_type_KillWhom,
                SD_VARLINK_SYMBOL_COMMENT("Sends a signal to a session's processes."),
                &vl_method_KillSession,
                SD_VARLINK_SYMBOL_COMMENT("Sets the idle hint for a session."),
                &vl_method_SetIdleHint,
                SD_VARLINK_SYMBOL_COMMENT("Sets the locked hint for a session."),
                &vl_method_SetLockedHint,
                SD_VARLINK_SYMBOL_COMMENT("Takes exclusive control of a session's devices. Device events are streamed back as replies."),
                &vl_method_TakeControl,
                SD_VARLINK_SYMBOL_COMMENT("Releases exclusive control of a session's devices."),
                &vl_method_ReleaseControl,
                SD_VARLINK_SYMBOL_COMMENT("Takes a device for the controlled session. Returns the device FD."),
                &vl_method_TakeDevice,
                SD_VARLINK_SYMBOL_COMMENT("Releases a previously taken device."),
                &vl_method_ReleaseDevice,
                SD_VARLINK_SYMBOL_COMMENT("Acknowledges a device pause."),
                &vl_method_PauseDeviceComplete,
                SD_VARLINK_SYMBOL_COMMENT("Sets the session type. Requires session control."),
                &vl_method_SetType,
                SD_VARLINK_SYMBOL_COMMENT("Sets the display for a graphical session. Requires session control."),
                &vl_method_SetDisplay,
                SD_VARLINK_SYMBOL_COMMENT("Sets the session class. Currently only upgrades from user-incomplete to user."),
                &vl_method_SetClass,
                SD_VARLINK_SYMBOL_COMMENT("Sets the brightness of a display device."),
                &vl_method_SetBrightness,
                SD_VARLINK_SYMBOL_COMMENT("Caller is not the session controller"),
                &vl_error_NotInControl,
                SD_VARLINK_SYMBOL_COMMENT("Device is already taken"),
                &vl_error_DeviceIsTaken,
                SD_VARLINK_SYMBOL_COMMENT("Device has not been taken"),
                &vl_error_DeviceNotTaken,
                SD_VARLINK_SYMBOL_COMMENT("Information about a user"),
                &vl_type_UserInfo,
                SD_VARLINK_SYMBOL_COMMENT("Describes a specific user."),
                &vl_method_DescribeUser,
                SD_VARLINK_SYMBOL_COMMENT("Lists all current users."),
                &vl_method_ListUsers,
                SD_VARLINK_SYMBOL_COMMENT("Terminates all sessions of a user."),
                &vl_method_TerminateUser,
                SD_VARLINK_SYMBOL_COMMENT("Sends a signal to all processes of a user."),
                &vl_method_KillUser,
                SD_VARLINK_SYMBOL_COMMENT("Enables or disables user lingering."),
                &vl_method_SetUserLinger,
                SD_VARLINK_SYMBOL_COMMENT("Information about a seat"),
                &vl_type_SeatInfo,
                SD_VARLINK_SYMBOL_COMMENT("Describes a specific seat."),
                &vl_method_DescribeSeat,
                SD_VARLINK_SYMBOL_COMMENT("Lists all current seats."),
                &vl_method_ListSeats,
                SD_VARLINK_SYMBOL_COMMENT("Terminates all sessions on a seat."),
                &vl_method_TerminateSeat,
                SD_VARLINK_SYMBOL_COMMENT("Activates a session on a specific seat."),
                &vl_method_ActivateSessionOnSeat,
                SD_VARLINK_SYMBOL_COMMENT("Switches to a specific virtual terminal on a seat."),
                &vl_method_SwitchTo,
                SD_VARLINK_SYMBOL_COMMENT("Switches to the next virtual terminal on a seat."),
                &vl_method_SwitchToNext,
                SD_VARLINK_SYMBOL_COMMENT("Switches to the previous virtual terminal on a seat."),
                &vl_method_SwitchToPrevious,
                SD_VARLINK_SYMBOL_COMMENT("Powers off the machine."),
                &vl_method_PowerOff,
                SD_VARLINK_SYMBOL_COMMENT("Reboots the machine."),
                &vl_method_Reboot,
                SD_VARLINK_SYMBOL_COMMENT("Halts the machine."),
                &vl_method_Halt,
                SD_VARLINK_SYMBOL_COMMENT("Suspends the machine."),
                &vl_method_Suspend,
                SD_VARLINK_SYMBOL_COMMENT("Hibernates the machine."),
                &vl_method_Hibernate,
                SD_VARLINK_SYMBOL_COMMENT("Hybrid-sleeps the machine."),
                &vl_method_HybridSleep,
                SD_VARLINK_SYMBOL_COMMENT("Suspends, then hibernates the machine."),
                &vl_method_SuspendThenHibernate,
                SD_VARLINK_SYMBOL_COMMENT("Puts the machine to sleep using the best available method."),
                &vl_method_Sleep,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to power off."),
                &vl_method_CanPowerOff,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to reboot."),
                &vl_method_CanReboot,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to halt."),
                &vl_method_CanHalt,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to suspend."),
                &vl_method_CanSuspend,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to hibernate."),
                &vl_method_CanHibernate,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to hybrid-sleep."),
                &vl_method_CanHybridSleep,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to suspend-then-hibernate."),
                &vl_method_CanSuspendThenHibernate,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller is allowed to sleep."),
                &vl_method_CanSleep,
                SD_VARLINK_SYMBOL_COMMENT("Schedules a shutdown at a specific time."),
                &vl_method_ScheduleShutdown,
                SD_VARLINK_SYMBOL_COMMENT("Cancels a previously scheduled shutdown."),
                &vl_method_CancelScheduledShutdown,
                SD_VARLINK_SYMBOL_COMMENT("Takes an inhibition lock. Returns the inhibition FIFO FD."),
                &vl_method_Inhibit,
                SD_VARLINK_SYMBOL_COMMENT("Sets the reboot parameter."),
                &vl_method_SetRebootParameter,
                SD_VARLINK_SYMBOL_COMMENT("Checks if the caller can set the reboot parameter."),
                &vl_method_CanRebootParameter,
                SD_VARLINK_SYMBOL_COMMENT("Sets the wall message for upcoming shutdown."),
                &vl_method_SetWallMessage,
                SD_VARLINK_SYMBOL_COMMENT("Sets whether to boot into firmware setup on next reboot."),
                &vl_method_SetRebootToFirmwareSetup,
                SD_VARLINK_SYMBOL_COMMENT("Checks if booting into firmware setup is supported."),
                &vl_method_CanRebootToFirmwareSetup,
                SD_VARLINK_SYMBOL_COMMENT("Sets the boot loader menu timeout for the next reboot."),
                &vl_method_SetRebootToBootLoaderMenu,
                SD_VARLINK_SYMBOL_COMMENT("Checks if setting the boot loader menu timeout is supported."),
                &vl_method_CanRebootToBootLoaderMenu,
                SD_VARLINK_SYMBOL_COMMENT("Sets the boot loader entry to select on next reboot."),
                &vl_method_SetRebootToBootLoaderEntry,
                SD_VARLINK_SYMBOL_COMMENT("Checks if selecting a boot loader entry is supported."),
                &vl_method_CanRebootToBootLoaderEntry,
                SD_VARLINK_SYMBOL_COMMENT("Attaches a device to a seat."),
                &vl_method_AttachDevice,
                SD_VARLINK_SYMBOL_COMMENT("Removes all explicit device-to-seat assignments."),
                &vl_method_FlushDevices,
                SD_VARLINK_SYMBOL_COMMENT("Describes the manager state."),
                &vl_method_DescribeManager,
                SD_VARLINK_SYMBOL_COMMENT("Subscribes to manager events (session/user/seat changes, shutdown/sleep preparation)."),
                &vl_method_SubscribeManagerEvents,
                SD_VARLINK_SYMBOL_COMMENT("Subscribes to per-session events (Lock, Unlock)."),
                &vl_method_SubscribeSessionEvents,
                SD_VARLINK_SYMBOL_COMMENT("Information about an inhibitor"),
                &vl_type_InhibitorInfo,
                SD_VARLINK_SYMBOL_COMMENT("Lists all current inhibitors."),
                &vl_method_ListInhibitors,
                SD_VARLINK_SYMBOL_COMMENT("No session by this name found"),
                &vl_error_NoSuchSession,
                SD_VARLINK_SYMBOL_COMMENT("No seat by this name found"),
                &vl_error_NoSuchSeat,
                SD_VARLINK_SYMBOL_COMMENT("No user by this UID found"),
                &vl_error_NoSuchUser,
                SD_VARLINK_SYMBOL_COMMENT("No inhibitor found"),
                &vl_error_NoSuchInhibitor,
                SD_VARLINK_SYMBOL_COMMENT("Process already member of a session"),
                &vl_error_AlreadySessionMember,
                SD_VARLINK_SYMBOL_COMMENT("The specified virtual terminal (VT) is already taken by another session"),
                &vl_error_VirtualTerminalAlreadyTaken,
                SD_VARLINK_SYMBOL_COMMENT("Maximum number of sessions reached"),
                &vl_error_TooManySessions,
                SD_VARLINK_SYMBOL_COMMENT("Failed to allocate a unit for the session"),
                &vl_error_UnitAllocationFailed,
                SD_VARLINK_SYMBOL_COMMENT("The session leader process does not have a pidfd"),
                &vl_error_NoSessionPIDFD,
                SD_VARLINK_SYMBOL_COMMENT("The requested operation is not supported for this session (e.g. class or type mismatch)"),
                &vl_error_NotSupported);
