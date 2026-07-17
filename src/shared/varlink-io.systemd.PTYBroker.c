/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "bus-polkit.h"
#include "varlink-io.systemd.PTYBroker.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                FrontendType,
                SD_VARLINK_FIELD_COMMENT("Return the file descriptor of the frontend side of the pty to the caller, do not keep a duplicate."),
                SD_VARLINK_DEFINE_ENUM_VALUE(take),
                SD_VARLINK_FIELD_COMMENT("Read any data received from the backend and send it to monitors, afterwards discard it"),
                SD_VARLINK_DEFINE_ENUM_VALUE(null),
                SD_VARLINK_FIELD_COMMENT("Read any data received from the backend and write it to monitors and the logs"),
                SD_VARLINK_DEFINE_ENUM_VALUE(log));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BackendType,
                SD_VARLINK_FIELD_COMMENT("Return the file descriptor of the backend side of the pty to the caller, do not keep a duplicate."),
                SD_VARLINK_DEFINE_ENUM_VALUE(take),
                SD_VARLINK_FIELD_COMMENT("Invoke a shell on the backend side."),
                SD_VARLINK_DEFINE_ENUM_VALUE(shell),
                SD_VARLINK_FIELD_COMMENT("Invoke a login prompt on the backend side."),
                SD_VARLINK_DEFINE_ENUM_VALUE(login));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TerminalSettings,
                SD_VARLINK_FIELD_COMMENT("Terminal type ($TERM)"),
                SD_VARLINK_DEFINE_FIELD(dollarTERM, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Terminal type ($COLORTERM)"),
                SD_VARLINK_DEFINE_FIELD(dollarCOLORTERM, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether $NO_COLOR is set to a non-empty value, i.e. color output shall be suppressed (see no-color.org)"),
                SD_VARLINK_DEFINE_FIELD(dollarNO_COLOR, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Width (in character cell columns) for the pty"),
                SD_VARLINK_DEFINE_FIELD(columns, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Height (in character cell lines) for the pty"),
                SD_VARLINK_DEFINE_FIELD(lines, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                AcquirePty,
                SD_VARLINK_SUPPORTS_UPGRADE,

                SD_VARLINK_FIELD_COMMENT("What to do with the 'frontend' of the pty, also known as the pty 'master'"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(frontendType, FrontendType, 0),
                SD_VARLINK_FIELD_COMMENT("What to do with the 'backend' of the pty, also known the pty 'slave'"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(backendType, BackendType, 0),
                SD_VARLINK_FIELD_COMMENT("A unique name to identify the pty allocation with"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A descriptive string to identify the pty allocation with (doesn't have to be unique)"),
                SD_VARLINK_DEFINE_INPUT(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The syslog 'tag' to use for this pseudo TTY output when connected to logging"),
                SD_VARLINK_DEFINE_INPUT(tag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For shell backend: user to run the shell as"),
                SD_VARLINK_DEFINE_INPUT(user, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For shell backend: group to run the shell as"),
                SD_VARLINK_DEFINE_INPUT(group, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For shell backend: initial directory for the shell"),
                SD_VARLINK_DEFINE_INPUT(workingDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For shell and login backend: environment"),
                SD_VARLINK_DEFINE_INPUT(environment, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For shell backend: whether to allocate a 'lightweight' session"),
                SD_VARLINK_DEFINE_INPUT(lightweight, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Convert the connection into a monitor connection once done"),
                SD_VARLINK_DEFINE_INPUT(monitor, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, hang up the pty once this monitor connection is disconnected. If null defaults to false."),
                SD_VARLINK_DEFINE_INPUT(hangUpOnDisconnect, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Initial settings for the terminal"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,

                SD_VARLINK_FIELD_COMMENT("Selected name for the pty allocation"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The index of the PTY frontend (i.e. 'master')"),
                SD_VARLINK_DEFINE_OUTPUT(frontendFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The index of the PTY backend (i.e. 'slave')"),
                SD_VARLINK_DEFINE_OUTPUT(backendFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The name of the transient service unit that runs the shell or login on the PTY backend side."),
                SD_VARLINK_DEFINE_OUTPUT(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The TTY path name of the allocate pseudo TTY"),
                SD_VARLINK_DEFINE_OUTPUT(backendPath, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Settled settings for the terminal"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                EnrollPty,
                SD_VARLINK_SUPPORTS_UPGRADE,

                SD_VARLINK_FIELD_COMMENT("The index of the PTY frontend (i.e. 'master')"),
                SD_VARLINK_DEFINE_INPUT(frontendFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("What to do with the 'frontend' of the pty, also known as the pty 'master'"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(frontendType, FrontendType, 0),
                SD_VARLINK_FIELD_COMMENT("The TTY path name of the pre-allocated pseudo TTY, if known and meaningful to the broker. Leave unset if the path only makes sense within the caller's namespace."),
                SD_VARLINK_DEFINE_INPUT(backendPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A unique name to identify the pty allocation with"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A descriptive string to identify the pty allocation with (doesn't have to be unique)"),
                SD_VARLINK_DEFINE_INPUT(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The syslog 'tag' to use for this pseudo TTY output when connected to logging"),
                SD_VARLINK_DEFINE_INPUT(tag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Convert the connection into a monitor connection once done"),
                SD_VARLINK_DEFINE_INPUT(monitor, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, hang up the pty once this monitor connection is disconnected. If null defaults to false."),
                SD_VARLINK_DEFINE_INPUT(hangUpOnDisconnect, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Initial settings for the terminal"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,

                SD_VARLINK_FIELD_COMMENT("Selected name for the pty allocation"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Settled settings for the terminal"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE));


static SD_VARLINK_DEFINE_METHOD_FULL(
                MonitorPty,
                SD_VARLINK_REQUIRES_UPGRADE,

                SD_VARLINK_FIELD_COMMENT("The name of the PTY allocation to connect to."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("How many lines of track buffer to return. If null defaults to 0."),
                SD_VARLINK_DEFINE_INPUT(trackBufferLines, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, hang up the pty once this monitor connection is disconnected. If null defaults to false."),
                SD_VARLINK_DEFINE_INPUT(hangUpOnDisconnect, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("New settings for the terminal (not that the environment based settings will not be propagated to the backend processes)"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,

                SD_VARLINK_FIELD_COMMENT("Current contents of the track buffer, line by line."),
                SD_VARLINK_DEFINE_OUTPUT(trackBuffer, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The TTY path name of the allocate pseudo TTY"),
                SD_VARLINK_DEFINE_OUTPUT(backendPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Settings for the terminal"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ConfigurePty,
                SD_VARLINK_FIELD_COMMENT("The name of the PTY allocation to reconfigure to."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("New settings for the terminal (not that the environment based settings will not be propagated to the backend processes)"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,

                SD_VARLINK_FIELD_COMMENT("Complete configured settings"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(terminalSettings, TerminalSettings, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListPty,
                SD_VARLINK_SUPPORTS_MORE,

                SD_VARLINK_FIELD_COMMENT("The name of the PTY allocation to list."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("Name of the allocated PTY"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A descriptive string to identify the pty allocation with (doesn't have to be unique)"),
                SD_VARLINK_DEFINE_OUTPUT(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The syslog 'tag' to use for this pseudo TTY output when connected to logging"),
                SD_VARLINK_DEFINE_OUTPUT(tag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The frontend type for this PTY"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(frontendType, FrontendType, 0),
                SD_VARLINK_FIELD_COMMENT("The backend type for this PTY"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(backendType, BackendType, 0),
                SD_VARLINK_FIELD_COMMENT("The backend path for this PTY"),
                SD_VARLINK_DEFINE_OUTPUT(backendPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                HangUpPty,
                SD_VARLINK_FIELD_COMMENT("Name of the allocated PTY to hang up"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchPty);
static SD_VARLINK_DEFINE_ERROR(PtyExists);
static SD_VARLINK_DEFINE_ERROR(TrackingNotEnabled);
static SD_VARLINK_DEFINE_ERROR(TooManyPtys);
static SD_VARLINK_DEFINE_ERROR(TooManyMonitors);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PTYBroker,
                "io.systemd.PTYBroker",
                SD_VARLINK_INTERFACE_COMMENT("An API for acquiring a pseudo-terminal"),
                SD_VARLINK_SYMBOL_COMMENT("Allocates a PTY pair, and configures what to do with each side."),
                &vl_method_AcquirePty,
                SD_VARLINK_SYMBOL_COMMENT("Enrolls a pre-allocated PTY frontend (i.e. the master)."),
                &vl_method_EnrollPty,
                SD_VARLINK_SYMBOL_COMMENT("Monitor frontend side of the pty."),
                &vl_method_MonitorPty,
                SD_VARLINK_SYMBOL_COMMENT("Reconfigure pseudo terminal"),
                &vl_method_ConfigurePty,
                SD_VARLINK_SYMBOL_COMMENT("List allocated pseudo-terminals"),
                &vl_method_ListPty,
                SD_VARLINK_SYMBOL_COMMENT("Hang up pseudo terminal"),
                &vl_method_HangUpPty,
                SD_VARLINK_SYMBOL_COMMENT("What to do with the PTY frontend."),
                &vl_type_FrontendType,
                SD_VARLINK_SYMBOL_COMMENT("What to do with the PTY backend."),
                &vl_type_BackendType,
                SD_VARLINK_SYMBOL_COMMENT("Details about terminal settings."),
                &vl_type_TerminalSettings,
                SD_VARLINK_SYMBOL_COMMENT("No PTY by the given name known"),
                &vl_error_NoSuchPty,
                SD_VARLINK_SYMBOL_COMMENT("A PTY by the given name already exists."),
                &vl_error_PtyExists,
                SD_VARLINK_SYMBOL_COMMENT("Limit on number of PTYs reached."),
                &vl_error_TooManyPtys,
                SD_VARLINK_SYMBOL_COMMENT("Limit on number of monitors of a PTY reached."),
                &vl_error_TooManyMonitors,
                SD_VARLINK_SYMBOL_COMMENT("Tracking of PTY state not enabled for specified PTY."),
                &vl_error_TrackingNotEnabled);
