/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-idl.h"
#include "varlink-io.systemd.Machine.h"

static VARLINK_DEFINE_METHOD(
                Register,
                VARLINK_DEFINE_INPUT(name,              VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(id,                VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(service,           VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(class,             VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(leader,            VARLINK_INT,    VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(rootDirectory,     VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(ifIndices,         VARLINK_INT,    VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(vSockCid,          VARLINK_INT,    VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(sshAddress,        VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(sshPrivateKeyPath, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_STRUCT_TYPE(
                Timestamp,
                VARLINK_FIELD_COMMENT("Timestamp in µs in the CLOCK_REALTIME clock (wallclock)"),
                VARLINK_DEFINE_FIELD(realtime, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Timestamp in µs in the CLOCK_MONOTONIC clock"),
                VARLINK_DEFINE_FIELD(monotonic, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                List,
                VARLINK_FIELD_COMMENT("If non-null the name of a running machine to report details on. If null/unspecified enumerates all running machines."),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Name of the machine"),
                VARLINK_DEFINE_OUTPUT(name, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("128bit ID identifying this machine, formatted in hexadecimal"),
                VARLINK_DEFINE_OUTPUT(id, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Name of the software that registered this machine"),
                VARLINK_DEFINE_OUTPUT(service, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The class of this machine"),
                VARLINK_DEFINE_OUTPUT(class, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("Leader process PID of this machine"),
                VARLINK_DEFINE_OUTPUT(leader, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Root directory of this machine, if known, relative to host file system"),
                VARLINK_DEFINE_OUTPUT(rootDirectory, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The service manager unit this machine resides in"),
                VARLINK_DEFINE_OUTPUT(unit, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Timestamp when the machine was activated"),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(timestamp, Timestamp, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("AF_VSOCK CID of the machine if known and applicable"),
                VARLINK_DEFINE_OUTPUT(vSockCid, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("SSH address to connect to"),
                VARLINK_DEFINE_OUTPUT(sshAddress, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(NoSuchMachine);
static VARLINK_DEFINE_ERROR(MachineExists);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Machine,
                "io.systemd.Machine",
                VARLINK_SYMBOL_COMMENT("A timestamp object consisting of both CLOCK_REALTIME and CLOCK_MONOTONIC timestamps"),
                &vl_type_Timestamp,
                &vl_method_Register,
                VARLINK_SYMBOL_COMMENT("List running machines"),
                &vl_method_List,
                VARLINK_SYMBOL_COMMENT("No matching machine currently running"),
                &vl_error_NoSuchMachine,
                &vl_error_MachineExists);
