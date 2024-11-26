/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "bus-polkit.h"
#include "varlink-idl-common.h"
#include "varlink-io.systemd.Machine.h"

#define VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS                                                                                  \
        SD_VARLINK_FIELD_COMMENT("If non-null the name of a machine."),                                                                        \
        SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),                                                                 \
        SD_VARLINK_FIELD_COMMENT("If non-null the PID of a machine. Special value 0 means to take pid of the machine the caller is part of."), \
        SD_VARLINK_DEFINE_INPUT_BY_TYPE(pid, ProcessId, SD_VARLINK_NULLABLE),                                                                  \
        VARLINK_DEFINE_POLKIT_INPUT

static SD_VARLINK_DEFINE_ENUM_TYPE(
                AcquireMetadata,
                SD_VARLINK_FIELD_COMMENT("Do not include metadata in the output"),
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_FIELD_COMMENT("Include metadata in the output"),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_FIELD_COMMENT("Include metadata in the output, but gracefully eat up errors"),
                SD_VARLINK_DEFINE_ENUM_VALUE(graceful));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Address,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                Register,
                SD_VARLINK_DEFINE_INPUT(name,              SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(id,                SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(service,           SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(class,             SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(leader,    ProcessId,         SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(rootDirectory,     SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(ifIndices,         SD_VARLINK_INT,    SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(vSockCid,          SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(sshAddress,        SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(sshPrivateKeyPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Controls whether to allocate a scope unit for the machine to register. If false, the client already took care of that and registered a service/scope specific to the machine."),
                SD_VARLINK_DEFINE_INPUT(allocateUnit,      SD_VARLINK_BOOL,   SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Unregister,
                VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS);

static SD_VARLINK_DEFINE_METHOD(
                Terminate,
                VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS);

static SD_VARLINK_DEFINE_METHOD(
                Kill,
                VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS,
                SD_VARLINK_FIELD_COMMENT("Identifier that specifies what precisely to send the signal to (either 'leader' or 'all')."),
                SD_VARLINK_DEFINE_INPUT(whom, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Numeric UNIX signal integer."),
                SD_VARLINK_DEFINE_INPUT(signal, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_SUPPORTS_MORE,
                VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS,
                SD_VARLINK_FIELD_COMMENT("If 'yes' the output will include machine metadata fields such as 'Addresses', 'OSRelease', and 'UIDShift'. If 'graceful' it's equal to true but gracefully eats up errors"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(acquireMetadata, AcquireMetadata, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Name of the machine"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("128bit ID identifying this machine, formatted in hexadecimal"),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Name of the software that registered this machine"),
                SD_VARLINK_DEFINE_OUTPUT(service, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The class of this machine"),
                SD_VARLINK_DEFINE_OUTPUT(class, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Leader process PID of this machine"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(leader, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Root directory of this machine, if known, relative to host file system"),
                SD_VARLINK_DEFINE_OUTPUT(rootDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The service manager unit this machine resides in"),
                SD_VARLINK_DEFINE_OUTPUT(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the machine was activated"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(timestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("AF_VSOCK CID of the machine if known and applicable"),
                SD_VARLINK_DEFINE_OUTPUT(vSockCid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("SSH address to connect to"),
                SD_VARLINK_DEFINE_OUTPUT(sshAddress, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to private SSH key"),
                SD_VARLINK_DEFINE_OUTPUT(sshPrivateKeyPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("List of addresses of the machine"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(addresses, Address, SD_VARLINK_ARRAY | SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("OS release information of the machine. It contains an array of key value pairs read from the os-release(5) file in the image."),
                SD_VARLINK_DEFINE_OUTPUT(OSRelease, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Return the base UID/GID of the machine"),
                SD_VARLINK_DEFINE_OUTPUT(UIDShift, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                MachineOpenMode,
                SD_VARLINK_FIELD_COMMENT("This mode allocates a pseudo TTY in the container and returns a file descriptor and its path. This is equivalent to transitioning into the container and invoking posix_openpt(3)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(tty),
                SD_VARLINK_FIELD_COMMENT("This mode allocates a pseudo TTY in the container and ensures that a getty login prompt of the container is running on the other end. It returns the file descriptor of the PTY and the PTY path. This is useful for acquiring a pty with a login prompt from the container."),
                SD_VARLINK_DEFINE_ENUM_VALUE(login),
                SD_VARLINK_FIELD_COMMENT("This mode allocates a pseudo TTY in the container, as the specified user, and invokes the executable at the specified path with a list of arguments (starting from argv[0]) and an environment block. It then returns the file descriptor of the PTY and the PTY path."),
                SD_VARLINK_DEFINE_ENUM_VALUE(shell));

static SD_VARLINK_DEFINE_METHOD(
                Open,
                VARLINK_DEFINE_MACHINE_LOOKUP_AND_POLKIT_INPUT_FIELDS,
                SD_VARLINK_FIELD_COMMENT("There are three possible values: 'tty', 'login', and 'shell'. Please see description for each of the modes."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, MachineOpenMode, 0),
                SD_VARLINK_FIELD_COMMENT("See description of mode='shell'. Valid only when mode='shell'"),
                SD_VARLINK_DEFINE_INPUT(user, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("See description of mode='shell'. Valid only when mode='shell'"),
                SD_VARLINK_DEFINE_INPUT(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("See description of mode='shell'. Valid only when mode='shell'"),
                SD_VARLINK_DEFINE_INPUT(args, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("See description of mode='shell'. Valid only when mode='shell'"),
                SD_VARLINK_DEFINE_INPUT(environment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("File descriptor of the allocated pseudo TTY"),
                SD_VARLINK_DEFINE_OUTPUT(ptyFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Path to the allocated pseudo TTY"),
                SD_VARLINK_DEFINE_OUTPUT(ptyPath, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchMachine);
static SD_VARLINK_DEFINE_ERROR(MachineExists);
static SD_VARLINK_DEFINE_ERROR(NoPrivateNetworking);
static SD_VARLINK_DEFINE_ERROR(NoOSReleaseInformation);
static SD_VARLINK_DEFINE_ERROR(NoUIDShift);
static SD_VARLINK_DEFINE_ERROR(NotAvailable);
static SD_VARLINK_DEFINE_ERROR(NotSupported);
static SD_VARLINK_DEFINE_ERROR(NoIPC);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Machine,
                "io.systemd.Machine",
                SD_VARLINK_SYMBOL_COMMENT("An object for referencing UNIX processes"),
                &vl_type_ProcessId,
                SD_VARLINK_SYMBOL_COMMENT("A timestamp object consisting of both CLOCK_REALTIME and CLOCK_MONOTONIC timestamps"),
                &vl_type_Timestamp,
                SD_VARLINK_SYMBOL_COMMENT("A enum field allowing to gracefully get metadata"),
                &vl_type_AcquireMetadata,
                SD_VARLINK_SYMBOL_COMMENT("An address object"),
                &vl_type_Address,
                &vl_method_Register,
                &vl_method_Unregister,
                SD_VARLINK_SYMBOL_COMMENT("Terminate machine, killing its processes"),
                &vl_method_Terminate,
                SD_VARLINK_SYMBOL_COMMENT("Send a UNIX signal to the machine's processes"),
                &vl_method_Kill,
                SD_VARLINK_SYMBOL_COMMENT("List running machines"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("A enum field which defines way to open TTY for a machine"),
                &vl_type_MachineOpenMode,
                SD_VARLINK_SYMBOL_COMMENT("Allocates a pseudo TTY in the container in various modes"),
                &vl_method_Open,
                SD_VARLINK_SYMBOL_COMMENT("No matching machine currently running"),
                &vl_error_NoSuchMachine,
                &vl_error_MachineExists,
                SD_VARLINK_SYMBOL_COMMENT("Machine does not use private networking"),
                &vl_error_NoPrivateNetworking,
                SD_VARLINK_SYMBOL_COMMENT("Machine does not contain OS release information"),
                &vl_error_NoOSReleaseInformation,
                SD_VARLINK_SYMBOL_COMMENT("Machine uses a complex UID/GID mapping, cannot determine shift"),
                &vl_error_NoUIDShift,
                SD_VARLINK_SYMBOL_COMMENT("Requested information is not available"),
                &vl_error_NotAvailable,
                SD_VARLINK_SYMBOL_COMMENT("Requested operation is not supported"),
                &vl_error_NotSupported,
                SD_VARLINK_SYMBOL_COMMENT("There is no IPC service (such as system bus or varlink) in the container"),
                &vl_error_NoIPC);
