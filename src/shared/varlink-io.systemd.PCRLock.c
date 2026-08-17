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
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootAuthority),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the platform key (PK)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootPk),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the key exchange key database (KEK)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootKek),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the authorized signature database (db)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootDb),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the forbidden signature database (dbx)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootDbx),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the timestamp signature database (dbt)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootDbt),
                SD_VARLINK_FIELD_COMMENT("Predict Secure Boot measurements after an update to the recovery signature database (dbr)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(secureBootDbr));

static SD_VARLINK_DEFINE_METHOD(
                Lock,
                SD_VARLINK_FIELD_COMMENT("The category of measurements to generate or remove a .pcrlock file for, or the Secure Boot variable update to predict."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(category, LockCategory, 0),
                SD_VARLINK_FIELD_COMMENT("If true (the default), generate the .pcrlock file(s) for the selected category; if false, remove them again. Secure Boot variable update categories require true."),
                SD_VARLINK_DEFINE_INPUT(lock, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The .pcrlock filename to generate or remove for measurement categories, defaulting to generated.pcrlock. Firmware categories use it in both early and late component directories. For Secure Boot variable updates, it is appended as a suffix after each prediction's boot ID, transaction ID, and content hash; it is limited to 103 bytes. Must be a filename, not a path."),
                SD_VARLINK_DEFINE_INPUT(filename, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The raw authenticated-variable update bytes, encoded in Base64. Required for secureBootDb and secureBootDbx, limited to 1 MiB; ignored for other Secure Boot variable update categories. Not accepted for the measurement categories."),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to regenerate the pcrlock policy after a Secure Boot variable update. Defaults to true for update categories and is not accepted for measurement categories."),
                SD_VARLINK_DEFINE_INPUT(regenerate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(
                NoChange);

static SD_VARLINK_DEFINE_ERROR(
                UpdateNotApplied);

SD_VARLINK_DEFINE_INTERFACE_FULL(
                io_systemd_PCRLock,
                "io.systemd.PCRLock",
                SD_VARLINK_EXPERIMENTAL,
                &vl_method_ReadEventLog,
                SD_VARLINK_SYMBOL_COMMENT("A single variant of a .pcrlock component, i.e. one alternative the component may take, backed by a specific .pcrlock file."),
                &vl_type_ComponentVariant,
                SD_VARLINK_SYMBOL_COMMENT("Lists the defined .pcrlock components, streamed one component per reply. Must be called with the 'more' flag."),
                &vl_method_ListComponents,
                &vl_method_MakePolicy,
                &vl_method_RemovePolicy,
                SD_VARLINK_SYMBOL_COMMENT("The category of measurements a .pcrlock file can be generated for or removed, as used by the Lock() method."),
                &vl_type_LockCategory,
                SD_VARLINK_SYMBOL_COMMENT("Generates or removes .pcrlock files for a measurement category, or updates host-derived PCR predictions after a Secure Boot variable update has been written."),
                &vl_method_Lock,
                &vl_error_NoChange,
                &vl_error_UpdateNotApplied);
