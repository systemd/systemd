/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Hostname.h"

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT(Hostname, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(StaticHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(PrettyHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(DefaultHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(HostnameSource, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(IconName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Chassis, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An unique identifier of the system chassis."),
                SD_VARLINK_DEFINE_OUTPUT(ChassisAssetTag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Deployment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Location, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(KernelName, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(KernelRelease, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(KernelVersion, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("'Pretty' name of the OS. This is the primary OS identifier that is suitable for presentation to the user. Typically includes a version too, but doesn't have to."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemPrettyName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("'Fancy' name of the OS; may contain non-ASCII Unicode chars, as well as basic ANSI sequences. This is similar to 'OperatingSystemPrettyName', but is preferably used on terminals that support ANSI sequences and full Unicode."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemFancyName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemCPEName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemHomeURL, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemSupportEnd, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemReleaseData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemImageID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemImageVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(MachineInformationData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(HardwareVendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(HardwareModel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(HardwareSerial, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(HardwareSKU, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(HardwareVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareVendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareDate, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(MachineID, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(BootID, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(ProductUUID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(VSockCID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Hostname,
                "io.systemd.Hostname",
                &vl_method_Describe);
