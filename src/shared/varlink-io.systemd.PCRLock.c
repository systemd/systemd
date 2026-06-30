/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRLock.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                ReadEventLog,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_DEFINE_OUTPUT(record, SD_VARLINK_OBJECT, 0));

static SD_VARLINK_DEFINE_METHOD(
                MakePolicy,
                SD_VARLINK_DEFINE_INPUT(force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                RemovePolicy);

static SD_VARLINK_DEFINE_ENUM_TYPE(
                LockCategory,
                SD_VARLINK_FIELD_COMMENT("Firmware code measurements (PCRs 0, 2, 4)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(firmwareCode),
                SD_VARLINK_FIELD_COMMENT("Firmware configuration measurements (PCRs 1, 3, 5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(firmwareConfig),
                SD_VARLINK_FIELD_COMMENT("SecureBoot policy, i.e. the SecureBoot, PK, KEK, db and dbx EFI variables (PCR 7)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootPolicy),
                SD_VARLINK_FIELD_COMMENT("SecureBoot authority measurements, i.e. the certificates used to validate the boot components (PCR 7)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootAuthority));

static SD_VARLINK_DEFINE_METHOD(
                Lock,
                SD_VARLINK_FIELD_COMMENT("The category of measurements to generate or remove a .pcrlock file for."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(category, LockCategory, 0),
                SD_VARLINK_FIELD_COMMENT("If true, remove the .pcrlock file(s) for the selected category instead of generating them. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(unlock, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                NoChange);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRLock,
                "io.systemd.PCRLock",
                &vl_method_ReadEventLog,
                &vl_method_MakePolicy,
                &vl_method_RemovePolicy,
                SD_VARLINK_SYMBOL_COMMENT("The category of measurements a .pcrlock file can be generated for or removed, as used by the Lock() method."),
                &vl_type_LockCategory,
                SD_VARLINK_SYMBOL_COMMENT("Generates or removes the .pcrlock file(s) for the selected category of measurements. Generates (locks) them by default, or removes (unlocks) them if 'unlock' is true."),
                &vl_method_Lock,
                &vl_error_NoChange);
