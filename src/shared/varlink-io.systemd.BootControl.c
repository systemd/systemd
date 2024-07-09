/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.BootControl.h"

static VARLINK_DEFINE_ENUM_TYPE(
                BootEntryType,
                VARLINK_FIELD_COMMENT("Boot Loader Specification Type #1 entries (.conf files)"),
                VARLINK_DEFINE_ENUM_VALUE(type1),
                VARLINK_FIELD_COMMENT("Boot Loader Specification Type #2 entries (UKIs)"),
                VARLINK_DEFINE_ENUM_VALUE(type2),
                VARLINK_FIELD_COMMENT("Additional entries reported by boot loader"),
                VARLINK_DEFINE_ENUM_VALUE(loader),
                VARLINK_FIELD_COMMENT("Automatically generated entries"),
                VARLINK_DEFINE_ENUM_VALUE(auto));

static VARLINK_DEFINE_STRUCT_TYPE(
                BootEntry,
                VARLINK_DEFINE_FIELD_BY_TYPE(type, BootEntryType, 0),
                VARLINK_FIELD_COMMENT("The string identifier of the entry"),
                VARLINK_DEFINE_FIELD(id, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(path, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(root, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(title, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(showTitle, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(sortKey, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(version, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(machineId, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(architecture, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(options, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(linux, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(efi, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(initrd, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(devicetree, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(devicetreeOverlay, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_FIELD_COMMENT("Indicates whether the boot loader reported this entry on the current boot"),
                VARLINK_DEFINE_FIELD(isReported, VARLINK_BOOL, 0),
                VARLINK_FIELD_COMMENT("Indicates the number of tries left for this boot entry before it is assumed to be not working."),
                VARLINK_DEFINE_FIELD(triesLeft, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Indicates the number of unsuccessful tries already made for this boot entry."),
                VARLINK_DEFINE_FIELD(triesDone, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Indicates whether this entry is the default entry."),
                VARLINK_DEFINE_FIELD(isDefault, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Indicates whether this entry has been booted."),
                VARLINK_DEFINE_FIELD(isSelected, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                ListBootEntries,
                VARLINK_FIELD_COMMENT("A boot menu entry structure"),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(entry, BootEntry, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                SetRebootToFirmware,
                VARLINK_FIELD_COMMENT("The new value of the reboot-to-firmware-UI flag"),
                VARLINK_DEFINE_INPUT(state, VARLINK_BOOL, 0));

static VARLINK_DEFINE_METHOD(
                GetRebootToFirmware,
                VARLINK_FIELD_COMMENT("The current state of the reboot-to-firmware-UI flag"),
                VARLINK_DEFINE_OUTPUT(state, VARLINK_BOOL, 0));

static VARLINK_DEFINE_ERROR(
                RebootToFirmwareNotSupported);

static VARLINK_DEFINE_ERROR(
                NoSuchBootEntry);

VARLINK_DEFINE_INTERFACE(
                io_systemd_BootControl,
                "io.systemd.BootControl",
                VARLINK_INTERFACE_COMMENT("Boot Loader control APIs"),
                VARLINK_SYMBOL_COMMENT("The type of a boot entry"),
                &vl_type_BootEntryType,
                VARLINK_SYMBOL_COMMENT("A structure encapsulating a boot entry"),
                &vl_type_BootEntry,
                VARLINK_SYMBOL_COMMENT("Enumerates boot entries. Method call must be called with 'more' flag set. Each response returns one entry. If no entries are defined returns the NoSuchBootEntry error."),
                &vl_method_ListBootEntries,
                VARLINK_SYMBOL_COMMENT("Sets the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_SetRebootToFirmware,
                VARLINK_SYMBOL_COMMENT("Gets the current state of the reboot-to-firmware-UI flag of the firmware, if this concept exists. Returns the RebootToFirmwareNotSupported error if not."),
                &vl_method_GetRebootToFirmware,
                VARLINK_SYMBOL_COMMENT("SetRebootToFirmware() and GetRebootToFirmware() return this if the firmware does not actually support the reboot-to-firmware-UI concept."),
                &vl_error_RebootToFirmwareNotSupported,
                VARLINK_SYMBOL_COMMENT("No boot entry defined."),
                &vl_error_NoSuchBootEntry);
