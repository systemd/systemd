/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.BootControl.h"

SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntryType,
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #1 entries (.conf files)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type1),
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #2 entries (UKIs)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type2),
                SD_VARLINK_FIELD_COMMENT("Additional entries reported by boot loader"),
                SD_VARLINK_DEFINE_ENUM_VALUE(loader),
                SD_VARLINK_FIELD_COMMENT("Automatically generated entries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntrySource,
                SD_VARLINK_FIELD_COMMENT("Boot entry found in EFI system partition (ESP)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(esp),
                SD_VARLINK_FIELD_COMMENT("Boot entry found in XBOOTLDR partition"),
                SD_VARLINK_DEFINE_ENUM_VALUE(xbootldr));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                BootEntryAddon,
                SD_VARLINK_FIELD_COMMENT("The location of the global addon."),
                SD_VARLINK_DEFINE_FIELD(globalAddon, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The location of the local addon."),
                SD_VARLINK_DEFINE_FIELD(localAddon, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The command line options by the addon."),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                BootEntry,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(type, BootEntryType, 0),
                SD_VARLINK_FIELD_COMMENT("The source of the entry"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(source, BootEntrySource, 0),
                SD_VARLINK_FIELD_COMMENT("The string identifier of the entry"),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to the primary definition file for the entry"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Directory path of the file system root the entry was found on"),
                SD_VARLINK_DEFINE_FIELD(root, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The entry's title string"),
                SD_VARLINK_DEFINE_FIELD(title, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The possibly mangled/augmented title to show for the entry"),
                SD_VARLINK_DEFINE_FIELD(showTitle, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An explicitly configured sorting key for the enry"),
                SD_VARLINK_DEFINE_FIELD(sortKey, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The version of the entry"),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Machine ID of the OS installation belonging to the entry, if known"),
                SD_VARLINK_DEFINE_FIELD(machineId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("EFI architecture name for this entry"),
                SD_VARLINK_DEFINE_FIELD(architecture, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Command line options to pass to the invoked kernel or EFI binary"),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to the Linux kernel to invoke, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(linux, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to the EFI binary to invoke, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(efi, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to an UKI EFI binary to invoke, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(uki, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An UKI profile index to invoke. If not specified defaults to the first profile."),
                SD_VARLINK_DEFINE_FIELD(profile, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to the initrd image to pass to the invoked kernel, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(initrd, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Devicetree file to pass to the invoked kernel, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(devicetree, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Devicetree overlay file to pass to the invoked kernel, relative to the root directory of the file system containing the entry file"),
                SD_VARLINK_DEFINE_FIELD(devicetreeOverlay, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Indicates whether the boot loader reported this entry on the current boot"),
                SD_VARLINK_DEFINE_FIELD(isReported, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates the number of tries left for this boot entry before it is assumed to be not working."),
                SD_VARLINK_DEFINE_FIELD(triesLeft, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates the number of unsuccessful tries already made for this boot entry."),
                SD_VARLINK_DEFINE_FIELD(triesDone, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates whether this entry is the default entry."),
                SD_VARLINK_DEFINE_FIELD(isDefault, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates whether this entry has been booted."),
                SD_VARLINK_DEFINE_FIELD(isSelected, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Addon images of the entry."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(addons, BootEntryAddon, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Command line options of the entry."),
                SD_VARLINK_DEFINE_FIELD(cmdline, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListBootEntries,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("A boot menu entry structure"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(entry, BootEntry, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetRebootToFirmware,
                SD_VARLINK_FIELD_COMMENT("The new value of the reboot-to-firmware-UI flag"),
                SD_VARLINK_DEFINE_INPUT(state, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                GetRebootToFirmware,
                SD_VARLINK_FIELD_COMMENT("The current state of the reboot-to-firmware-UI flag"),
                SD_VARLINK_DEFINE_OUTPUT(state, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                Operation,
                SD_VARLINK_FIELD_COMMENT("Install the boot loader afresh, creating everything it needs"),
                SD_VARLINK_DEFINE_ENUM_VALUE(new),
                SD_VARLINK_FIELD_COMMENT("Just update existing boot loader binaries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(update));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntryTokenType,
                SD_VARLINK_FIELD_COMMENT("Pick identifiers for type #1 boot entries based on /etc/machine-id"),
                SD_VARLINK_DEFINE_ENUM_VALUE(machine_id),
                SD_VARLINK_FIELD_COMMENT("Pick identifiers for type #1 boot entries based on the IMAGE_ID= field from /etc/os-release"),
                SD_VARLINK_DEFINE_ENUM_VALUE(os_image_id),
                SD_VARLINK_FIELD_COMMENT("Pick identifiers for type #1 boot entries based on the ID= field from /etc/os-release"),
                SD_VARLINK_DEFINE_ENUM_VALUE(os_id),
                SD_VARLINK_FIELD_COMMENT("Pick identifiers for type #1 boot entries based on a manually chosen string"),
                SD_VARLINK_DEFINE_ENUM_VALUE(literal),
                SD_VARLINK_FIELD_COMMENT("Choose automatically how to pick identifiers for type #1 boot entries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_METHOD(
                Install,
                SD_VARLINK_FIELD_COMMENT("Operation, either 'new' or 'update'"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(operation, Operation, 0),
                SD_VARLINK_FIELD_COMMENT("If true, continue on various failures"),
                SD_VARLINK_DEFINE_INPUT(graceful, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Index into array of file descriptors passed along with this message, pointing to file descriptor to root file system to operate on"),
                SD_VARLINK_DEFINE_INPUT(rootFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Root directory to operate relative to. If both this and rootFileDescriptor is specified, this is purely informational. If only this is specified, it is what will be used."),
                SD_VARLINK_DEFINE_INPUT(rootDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Selects how to identify boot entries"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(bootEntryTokenType, BootEntryTokenType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true the boot loader will be registered in an EFI boot entry via EFI variables, otherwise this is omitted"),
                SD_VARLINK_DEFINE_INPUT(touchVariables, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                RebootToFirmwareNotSupported);

static SD_VARLINK_DEFINE_ERROR(
                NoSuchBootEntry);

static SD_VARLINK_DEFINE_ERROR(
                NoESPFound);

static SD_VARLINK_DEFINE_ERROR(
                BootEntryTokenUnavailable);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_BootControl,
                "io.systemd.BootControl",
                SD_VARLINK_INTERFACE_COMMENT("Boot Loader control APIs"),
                SD_VARLINK_SYMBOL_COMMENT("The type of a boot entry"),
                &vl_type_BootEntryType,
                SD_VARLINK_SYMBOL_COMMENT("The source of a boot entry"),
                &vl_type_BootEntrySource,
                SD_VARLINK_SYMBOL_COMMENT("A structure encapsulating an addon of a boot entry"),
                &vl_type_BootEntryAddon,
                SD_VARLINK_SYMBOL_COMMENT("A structure encapsulating a boot entry"),
                &vl_type_BootEntry,
                SD_VARLINK_SYMBOL_COMMENT("The operation to execute"),
                &vl_type_Operation,
                SD_VARLINK_SYMBOL_COMMENT("Enumerates boot entries. Method call must be called with 'more' flag set. Each response returns one entry. If no entries are defined returns the NoSuchBootEntry error."),
                &vl_method_ListBootEntries,
                SD_VARLINK_SYMBOL_COMMENT("Sets the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_SetRebootToFirmware,
                SD_VARLINK_SYMBOL_COMMENT("Gets the current state of the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_GetRebootToFirmware,
                SD_VARLINK_SYMBOL_COMMENT("The boot entry token type to use."),
                &vl_type_BootEntryTokenType,
                SD_VARLINK_SYMBOL_COMMENT("Install the boot loader on the ESP."),
                &vl_method_Install,
                SD_VARLINK_SYMBOL_COMMENT("SetRebootToFirmware() and GetRebootToFirmware() return this if the firmware does not actually support the reboot-to-firmware-UI concept."),
                &vl_error_RebootToFirmwareNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("No boot entry defined."),
                &vl_error_NoSuchBootEntry,
                SD_VARLINK_SYMBOL_COMMENT("No EFI System Partition (ESP) found."),
                &vl_error_NoESPFound,
                SD_VARLINK_SYMBOL_COMMENT("The select boot entry token could not be determined."),
                &vl_error_BootEntryTokenUnavailable);
