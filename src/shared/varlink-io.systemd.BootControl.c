/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.BootControl.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntryType,
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #1 entries (.conf files)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type1),
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #2 entries (UKIs)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type2),
                SD_VARLINK_FIELD_COMMENT("Additional entries reported by boot loader"),
                SD_VARLINK_DEFINE_ENUM_VALUE(loader),
                SD_VARLINK_FIELD_COMMENT("Automatically generated entries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                BootEntry,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(type, BootEntryType, 0),
                SD_VARLINK_FIELD_COMMENT("The string identifier of the entry"),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(root, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(title, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(showTitle, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(sortKey, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(machineId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(architecture, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(linux, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(efi, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(initrd, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(devicetree, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD(isSelected, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

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

static SD_VARLINK_DEFINE_ERROR(
                RebootToFirmwareNotSupported);

static SD_VARLINK_DEFINE_ERROR(
                NoSuchBootEntry);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_BootControl,
                "io.systemd.BootControl",
                SD_VARLINK_INTERFACE_COMMENT("Boot Loader control APIs"),
                SD_VARLINK_SYMBOL_COMMENT("The type of a boot entry"),
                &vl_type_BootEntryType,
                SD_VARLINK_SYMBOL_COMMENT("A structure encapsulating a boot entry"),
                &vl_type_BootEntry,
                SD_VARLINK_SYMBOL_COMMENT("Enumerates boot entries. Method call must be called with 'more' flag set. Each response returns one entry. If no entries are defined returns the NoSuchBootEntry error."),
                &vl_method_ListBootEntries,
                SD_VARLINK_SYMBOL_COMMENT("Sets the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_SetRebootToFirmware,
                SD_VARLINK_SYMBOL_COMMENT("Gets the current state of the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_GetRebootToFirmware,
                SD_VARLINK_SYMBOL_COMMENT("SetRebootToFirmware() and GetRebootToFirmware() return this if the firmware does not actually support the reboot-to-firmware-UI concept."),
                &vl_error_RebootToFirmwareNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("No boot entry defined."),
                &vl_error_NoSuchBootEntry);
