/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.BootControl.h"

static VARLINK_DEFINE_ENUM_TYPE(
                BootEntryType,
                VARLINK_DEFINE_ENUM_VALUE(type1),
                VARLINK_DEFINE_ENUM_VALUE(type2),
                VARLINK_DEFINE_ENUM_VALUE(loader),
                VARLINK_DEFINE_ENUM_VALUE(auto));

static VARLINK_DEFINE_STRUCT_TYPE(
                BootEntry,
                VARLINK_DEFINE_FIELD_BY_TYPE(type, BootEntryType, 0),
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
                VARLINK_DEFINE_FIELD(isReported, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(triesLeft, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(triesDone, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(isDefault, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(isSelected, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                ListBootEntries,
                VARLINK_DEFINE_OUTPUT_BY_TYPE(entry, BootEntry, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                SetRebootToFirmware,
                VARLINK_DEFINE_INPUT(state, VARLINK_BOOL, 0));

static VARLINK_DEFINE_METHOD(
                GetRebootToFirmware,
                VARLINK_DEFINE_OUTPUT(state, VARLINK_BOOL, 0));

static VARLINK_DEFINE_ERROR(
                RebootToFirmwareNotSupported);

VARLINK_DEFINE_INTERFACE(
                io_systemd_BootControl,
                "io.systemd.BootControl",
                &vl_type_BootEntryType,
                &vl_type_BootEntry,
                &vl_method_ListBootEntries,
                &vl_method_SetRebootToFirmware,
                &vl_method_GetRebootToFirmware,
                &vl_error_RebootToFirmwareNotSupported);
