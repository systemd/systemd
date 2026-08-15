/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Hostname.h"

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The current system hostname."),
                SD_VARLINK_DEFINE_OUTPUT(Hostname, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The statically configured hostname, from /etc/hostname. Null if none is configured."),
                SD_VARLINK_DEFINE_OUTPUT(StaticHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The pretty (free-form, UTF-8) hostname. Null if none is configured."),
                SD_VARLINK_DEFINE_OUTPUT(PrettyHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The fallback hostname used when neither a static nor a transient hostname is set."),
                SD_VARLINK_DEFINE_OUTPUT(DefaultHostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates where the current hostname originates from, one of 'static', 'transient' or 'default'."),
                SD_VARLINK_DEFINE_OUTPUT(HostnameSource, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The name of an icon representing this system, following the XDG icon naming spec. Null if none is configured."),
                SD_VARLINK_DEFINE_OUTPUT(IconName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The chassis type of this system, e.g. 'desktop', 'laptop', 'server', 'vm', … Null if unknown."),
                SD_VARLINK_DEFINE_OUTPUT(Chassis, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An unique identifier of the system chassis."),
                SD_VARLINK_DEFINE_OUTPUT(ChassisAssetTag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The deployment environment of this system, e.g. 'production' or 'staging'. Null if none is configured."),
                SD_VARLINK_DEFINE_OUTPUT(Deployment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A human-readable description of the physical location of this system. Null if none is configured."),
                SD_VARLINK_DEFINE_OUTPUT(Location, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The operating system kernel name, as reported by uname(2), e.g. 'Linux'."),
                SD_VARLINK_DEFINE_OUTPUT(KernelName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The kernel release string, as reported by uname(2)."),
                SD_VARLINK_DEFINE_OUTPUT(KernelRelease, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The kernel version string, as reported by uname(2)."),
                SD_VARLINK_DEFINE_OUTPUT(KernelVersion, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("'Pretty' name of the OS. This is the primary OS identifier that is suitable for presentation to the user. Typically includes a version too, but doesn't have to."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemPrettyName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("'Fancy' name of the OS; may contain non-ASCII Unicode chars, as well as basic ANSI sequences. This is similar to 'OperatingSystemPrettyName', but is preferably used on terminals that support ANSI sequences and full Unicode."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemFancyName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The CPE name of the OS, from the CPE_NAME= field of os-release."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemCPEName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The home URL of the OS, from the HOME_URL= field of os-release."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemHomeURL, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The end-of-support time of the OS, in µs since the UNIX epoch. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemSupportEnd, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The full contents of os-release, as an array of 'KEY=VALUE' strings."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemReleaseData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The OS image identifier, from the IMAGE_ID= field of os-release."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemImageID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The OS image version, from the IMAGE_VERSION= field of os-release."),
                SD_VARLINK_DEFINE_OUTPUT(OperatingSystemImageVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The full contents of /etc/machine-info, as an array of 'KEY=VALUE' strings."),
                SD_VARLINK_DEFINE_OUTPUT(MachineInformationData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The hardware vendor of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(HardwareVendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hardware model of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(HardwareModel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hardware serial number of this system. Reading it requires privileges. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(HardwareSerial, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hardware SKU (stock keeping unit) of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(HardwareSKU, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hardware version of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(HardwareVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The firmware version of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The firmware vendor of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareVendor, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The firmware build date, in µs since the UNIX epoch. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(FirmwareDate, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The 128-bit machine ID of this system, formatted as a hexadecimal string."),
                SD_VARLINK_DEFINE_OUTPUT(MachineID, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The 128-bit boot ID of the current boot, formatted as a hexadecimal string."),
                SD_VARLINK_DEFINE_OUTPUT(BootID, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The DMI product UUID of this system. Reading it requires privileges. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(ProductUUID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The AF_VSOCK context ID (CID) of this system. Null if not known."),
                SD_VARLINK_DEFINE_OUTPUT(VSockCID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetHostname,
                SD_VARLINK_FIELD_COMMENT("The transient (runtime) hostname to set. If null the transient hostname is reset, so that the static hostname is used again."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetStaticHostname,
                SD_VARLINK_FIELD_COMMENT("The static hostname to set, stored in /etc/hostname. If null the static hostname is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetPrettyHostname,
                SD_VARLINK_FIELD_COMMENT("The pretty (free-form, UTF-8) hostname to set. If null the pretty hostname is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetIconName,
                SD_VARLINK_FIELD_COMMENT("The icon name to set. If null the icon name is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetChassis,
                SD_VARLINK_FIELD_COMMENT("The chassis type to set. If null the chassis type is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetDeployment,
                SD_VARLINK_FIELD_COMMENT("The deployment environment to set. If null the deployment is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetLocation,
                SD_VARLINK_FIELD_COMMENT("The physical location to set. If null the location is removed."),
                SD_VARLINK_DEFINE_INPUT(newValue, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetTags,
                SD_VARLINK_FIELD_COMMENT("If specified, the machine tag list is first reset to exactly these tags, before the 'add' and 'remove' fields are applied. If null, the current tag list is used as basis instead."),
                SD_VARLINK_DEFINE_INPUT(set, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Machine tags to add to the list."),
                SD_VARLINK_DEFINE_INPUT(add, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Machine tags to remove from the list."),
                SD_VARLINK_DEFINE_INPUT(remove, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                VARLINK_DEFINE_POLKIT_INPUT);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Hostname,
                "io.systemd.Hostname",
                SD_VARLINK_INTERFACE_COMMENT("APIs for querying and changing the system hostname and related machine metadata."),
                SD_VARLINK_SYMBOL_COMMENT("Returns hostname, kernel, OS, hardware, firmware and other machine metadata in one call."),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("Sets the transient (runtime) hostname."),
                &vl_method_SetHostname,
                SD_VARLINK_SYMBOL_COMMENT("Sets the static hostname, stored in /etc/hostname."),
                &vl_method_SetStaticHostname,
                SD_VARLINK_SYMBOL_COMMENT("Sets the pretty (free-form, UTF-8) hostname."),
                &vl_method_SetPrettyHostname,
                SD_VARLINK_SYMBOL_COMMENT("Sets the icon name representing this system."),
                &vl_method_SetIconName,
                SD_VARLINK_SYMBOL_COMMENT("Sets the chassis type of this system."),
                &vl_method_SetChassis,
                SD_VARLINK_SYMBOL_COMMENT("Sets the deployment environment of this system."),
                &vl_method_SetDeployment,
                SD_VARLINK_SYMBOL_COMMENT("Sets the physical location of this system."),
                &vl_method_SetLocation,
                SD_VARLINK_SYMBOL_COMMENT("Edits the machine tag list: optionally resets it to 'set', then adds 'add' and removes 'remove'."),
                &vl_method_SetTags);
