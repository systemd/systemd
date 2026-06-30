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

static SD_VARLINK_DEFINE_METHOD(
                LockFirmwareCode);

static SD_VARLINK_DEFINE_METHOD(
                LockFirmwareConfig);

static SD_VARLINK_DEFINE_METHOD(
                UnlockFirmwareCode);

static SD_VARLINK_DEFINE_METHOD(
                UnlockFirmwareConfig);

static SD_VARLINK_DEFINE_METHOD(
                LockSecureBootPolicy);

static SD_VARLINK_DEFINE_METHOD(
                UnlockSecureBootPolicy);

static SD_VARLINK_DEFINE_METHOD(
                LockSecureBootAuthority);

static SD_VARLINK_DEFINE_METHOD(
                UnlockSecureBootAuthority);

static SD_VARLINK_DEFINE_ERROR(
                NoChange);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_PCRLock,
                "io.systemd.PCRLock",
                &vl_method_ReadEventLog,
                &vl_method_MakePolicy,
                &vl_method_RemovePolicy,
                SD_VARLINK_SYMBOL_COMMENT("Generates .pcrlock files from the current firmware code measurements (PCRs 0, 2, 4)."),
                &vl_method_LockFirmwareCode,
                SD_VARLINK_SYMBOL_COMMENT("Generates .pcrlock files from the current firmware configuration measurements (PCRs 1, 3, 5)."),
                &vl_method_LockFirmwareConfig,
                SD_VARLINK_SYMBOL_COMMENT("Removes the .pcrlock files previously generated for the firmware code measurements."),
                &vl_method_UnlockFirmwareCode,
                SD_VARLINK_SYMBOL_COMMENT("Removes the .pcrlock files previously generated for the firmware configuration measurements."),
                &vl_method_UnlockFirmwareConfig,
                SD_VARLINK_SYMBOL_COMMENT("Generates a .pcrlock file from the current SecureBoot policy, i.e. the SecureBoot, PK, KEK, db and dbx EFI variables (PCR 7)."),
                &vl_method_LockSecureBootPolicy,
                SD_VARLINK_SYMBOL_COMMENT("Removes the .pcrlock file previously generated for the SecureBoot policy."),
                &vl_method_UnlockSecureBootPolicy,
                SD_VARLINK_SYMBOL_COMMENT("Generates a .pcrlock file from the current SecureBoot authority measurements, i.e. the certificates used to validate the boot components (PCR 7)."),
                &vl_method_LockSecureBootAuthority,
                SD_VARLINK_SYMBOL_COMMENT("Removes the .pcrlock file previously generated for the SecureBoot authority measurements."),
                &vl_method_UnlockSecureBootAuthority,
                &vl_error_NoChange);
