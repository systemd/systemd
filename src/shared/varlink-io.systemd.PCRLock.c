/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.PCRLock.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                ReadEventLog,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_DEFINE_OUTPUT(record, SD_VARLINK_OBJECT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ComponentVariant,
                SD_VARLINK_FIELD_COMMENT("The identifier of this component variant."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The path of the .pcrlock file that defines this variant."),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListComponents,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The identifier of the component."),
                SD_VARLINK_DEFINE_OUTPUT(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The variants defined for this component, each backed by a .pcrlock file."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(variants, ComponentVariant, SD_VARLINK_ARRAY));

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
                SD_VARLINK_FIELD_COMMENT("If true (the default), generate the .pcrlock file(s) for the selected category; if false, remove them again."),
                SD_VARLINK_DEFINE_INPUT(lock, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                SecureBootVariable,
                SD_VARLINK_FIELD_COMMENT("The platform key."),
                SD_VARLINK_DEFINE_ENUM_VALUE(pk),
                SD_VARLINK_FIELD_COMMENT("The key exchange key database."),
                SD_VARLINK_DEFINE_ENUM_VALUE(kek),
                SD_VARLINK_FIELD_COMMENT("The authorized signature database."),
                SD_VARLINK_DEFINE_ENUM_VALUE(db),
                SD_VARLINK_FIELD_COMMENT("The forbidden signature database."),
                SD_VARLINK_DEFINE_ENUM_VALUE(dbx),
                SD_VARLINK_FIELD_COMMENT("The timestamp signature database."),
                SD_VARLINK_DEFINE_ENUM_VALUE(dbt),
                SD_VARLINK_FIELD_COMMENT("The recovery signature database."),
                SD_VARLINK_DEFINE_ENUM_VALUE(dbr));

static SD_VARLINK_DEFINE_METHOD(
                NotifySecureBootUpdate,
                SD_VARLINK_FIELD_COMMENT("The Secure Boot variable the authenticated update targets."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(variable, SecureBootVariable, 0),
                SD_VARLINK_FIELD_COMMENT("The raw authenticated-variable update bytes, encoded in Base64. Required for db and dbx, limited to 1 MiB; ignored for policy-only variables."),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to regenerate the pcrlock policy after the update. Defaults to true."),
                SD_VARLINK_DEFINE_INPUT(regenerate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                NoChange);

static SD_VARLINK_DEFINE_ERROR(
                UpdateNotApplied);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRLock,
                "io.systemd.PCRLock",
                &vl_method_ReadEventLog,
                SD_VARLINK_SYMBOL_COMMENT("A single variant of a .pcrlock component, i.e. one alternative the component may take, backed by a specific .pcrlock file."),
                &vl_type_ComponentVariant,
                SD_VARLINK_SYMBOL_COMMENT("Lists the defined .pcrlock components, streamed one component per reply. Must be called with the 'more' flag."),
                &vl_method_ListComponents,
                &vl_method_MakePolicy,
                &vl_method_RemovePolicy,
                SD_VARLINK_SYMBOL_COMMENT("The category of measurements a .pcrlock file can be generated for or removed, as used by the Lock() method."),
                &vl_type_LockCategory,
                SD_VARLINK_SYMBOL_COMMENT("Generates or removes the .pcrlock file(s) for the selected category of measurements. Generates (locks) them by default, or removes (unlocks) them if 'lock' is false."),
                &vl_method_Lock,
                SD_VARLINK_SYMBOL_COMMENT("The Secure Boot variable targeted by an authenticated update."),
                &vl_type_SecureBootVariable,
                SD_VARLINK_SYMBOL_COMMENT("Update host-derived PCR policy predictions after an authenticated Secure Boot variable update has been written."),
                &vl_method_NotifySecureBootUpdate,
                &vl_error_NoChange,
                &vl_error_UpdateNotApplied);
