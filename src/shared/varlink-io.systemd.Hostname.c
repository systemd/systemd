/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Credentials.h"

static VARLINK_DEFINE_METHOD(
                Describe,
                VARLINK_DEFINE_OUTPUT(Hostname, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(StaticHostname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(PrettyHostname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(DefaultHostname, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(HostnameSource, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(IconName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(Chassis, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(Deployment, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(Location, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(KernelName, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(KernelRelease, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(KernelVersion, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(OperatingSystemPrettyName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(OperatingSystemCPEName, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(OperatingSystemHomeURL, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(OperatingSystemSupportEnd, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(HardwareVendor, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(HardwareModel, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(HardwareSerial, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(FirmwareVersion, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(FirmwareVendor, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(FirmwareDate, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(MachineID, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(BootID, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(ProductUUID, VARLINK_STRING, VARLINK_NULLABLE));

VARLINK_DEFINE_INTERFACE(
                io_systemd_Hostname,
                "io.systemd.Hostname",
                &vl_method_Describe);
