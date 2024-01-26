/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Credentials.h"

#define UNLOCK_FIELDS                                                           \
        VARLINK_DEFINE_INPUT(node, VARLINK_STRING, VARLINK_NULLABLE),           \
        VARLINK_DEFINE_INPUT(unlockPassword, VARLINK_STRING, VARLINK_NULLABLE), \
        VARLINK_DEFINE_INPUT(unlockKey, VARLINK_STRING, VARLINK_NULLABLE),      \
        VARLINK_DEFINE_INPUT(unlockFido2, VARLINK_STRING, VARLINK_NULLABLE)

static VARLINK_DEFINE_ANON_ENUM(
                TokenType,
                VARLINK_DEFINE_ENUM_VALUE(password),
                VARLINK_DEFINE_ENUM_VALUE(recovery),
                VARLINK_DEFINE_ENUM_VALUE(pkcs11),
                VARLINK_DEFINE_ENUM_VALUE(fido2),
                VARLINK_DEFINE_ENUM_VALUE(tpm2));

#define WIPE_FIELDS                                                                     \
        VARLINK_DEFINE_INPUT(wipeAll, VARLINK_BOOL, VARLINK_NULLABLE),                  \
        VARLINK_DEFINE_INPUT(wipeEmpty, VARLINK_BOOL, VARLINK_NULLABLE),                \
        VARLINK_DEFINE_INPUT_ENUM(wipeType, TokenType, VARLINK_ARRAY|VARLINK_NULLABLE), \
        VARLINK_DEFINE_INPUT(wipeSlots, VARLINK_INT, VARLINK_ARRAY|VARLINK_NULLABLE)

static VARLINK_DEFINE_METHOD(
                EnrollCustom,
                VARLINK_DEFINE_INPUT(key, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(token, VARLINK_OBJECT, 0),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                EnrollPassword,
                VARLINK_DEFINE_INPUT(password, VARLINK_STRING, 0),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                EnrollRecoveryKey,
                VARLINK_DEFINE_INPUT(recoveryKey, VARLINK_STRING, VARLINK_NULLABLE),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(recoveryKey, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                EnrollPKCS11,
                VARLINK_DEFINE_INPUT(tokenUri, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(pin, VARLINK_STRING, VARLINK_NULLABLE),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                EnrollFIDO2,
                VARLINK_DEFINE_INPUT(device, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(credentialAlgorithm, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(withClientPin, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(withUserPresence, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(withUserVerification, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(pin, VARLINK_STRING, VARLINK_NULLABLE),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_ANON_STRUCT(
                TpmPcr,
                VARLINK_DEFINE_FIELD(index, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(algorithm, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(value, VARLINK_STRING, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                EnrollTPM2,
                VARLINK_DEFINE_INPUT(device, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(deviceKey, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(sealKeyHandle, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT_STRUCT(pcrs, TpmPcr, VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(withPin, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(publicKey, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(publicKeyPcrs, VARLINK_INT, VARLINK_ARRAY|VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(signature, VARLINK_OBJECT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(pcrlockPolicy, VARLINK_OBJECT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(pin, VARLINK_STRING, VARLINK_NULLABLE),
                UNLOCK_FIELDS,
                WIPE_FIELDS,
                VARLINK_DEFINE_OUTPUT(slot, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(Wipe, UNLOCK_FIELDS, WIPE_FIELDS);

static VARLINK_DEFINE_ERROR(NoDevice);
static VARLINK_DEFINE_ERROR(BadKey);

VARLINK_DEFINE_INTERFACE(
                io_systemd_CryptEnroll,
                "io.systemd.CryptEnroll",
                &vl_method_EnrollCustom,
                &vl_method_EnrollPassword,
                &vl_method_EnrollRecoveryKey,
                &vl_method_EnrollPKCS11,
                &vl_method_EnrollFIDO2,
                &vl_method_EnrollTPM2,
                &vl_method_Wipe,
                &vl_error_NoDevice,
                &vl_error_BadKey);
