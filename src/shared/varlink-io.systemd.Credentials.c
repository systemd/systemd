/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Credentials.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                Scope,
                SD_VARLINK_FIELD_COMMENT("Generate a system-bound credential"),
                SD_VARLINK_DEFINE_ENUM_VALUE(system),
                SD_VARLINK_FIELD_COMMENT("Generate a system and user bound credential"),
                SD_VARLINK_DEFINE_ENUM_VALUE(user));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                WithKey,
                SD_VARLINK_FIELD_COMMENT("Automatically pick the key to bind the credential to"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto),
                SD_VARLINK_FIELD_COMMENT("Automatically pick the key to bind the credential to, but ensure it is accessible in the initrd, thus potentially leaving it unencrypted."),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto_initrd),
                SD_VARLINK_FIELD_COMMENT("Bind to the host key only, i.e. not the TPM"),
                SD_VARLINK_DEFINE_ENUM_VALUE(host),
                SD_VARLINK_FIELD_COMMENT("Bind to the TPM only, not the host key"),
                SD_VARLINK_DEFINE_ENUM_VALUE(tpm2),
                SD_VARLINK_FIELD_COMMENT("Bind to the TPM only (using a public key identifying the UKI), not the host key"),
                SD_VARLINK_DEFINE_ENUM_VALUE(tpm2_with_public_key),
                SD_VARLINK_FIELD_COMMENT("Bind to both the TPM and the host key"),
                SD_VARLINK_DEFINE_ENUM_VALUE(host_tpm2),
                SD_VARLINK_FIELD_COMMENT("Bind to both the TPM (using a public key identifying the UKI) and the host key"),
                SD_VARLINK_DEFINE_ENUM_VALUE(host_tpm2_with_public_key),
                SD_VARLINK_FIELD_COMMENT("Do not bind to either host key nor the TPM, thus using null encryption (this provides no authenticity nor confidentiality guarantees)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(null));

static SD_VARLINK_DEFINE_METHOD(
                Encrypt,
                SD_VARLINK_FIELD_COMMENT("The name for the encrypted credential, a string suitable for inclusion in a file name. If not specified no name is encoded in the credential. Typically, if this credential is stored on disk, this is how the file should be called, and permits authentication of the filename."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Plaintext to encrypt. Suitable only for textual data. Either this field or 'data' (below) must be provided."),
                SD_VARLINK_DEFINE_INPUT(text, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Plaintext to encrypt, encoded in Base64. Suitable for binary data. Either this field or 'text' (above) must be provided."),
                SD_VARLINK_DEFINE_INPUT(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp to store in the credential. In µs since the UNIX epoch, i.e. Jan 1st 1970. If not specified the current time is used."),
                SD_VARLINK_DEFINE_INPUT(timestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when to the credential should be considered invalid. In µs since the UNIX epoch. If not specified, the credential remains valid forever."),
                SD_VARLINK_DEFINE_INPUT(notAfter, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The intended scope for the credential. One of 'system' or 'user'. If not specified defaults to 'system', unless an uid is specified (see below), in which case it default to 'user'."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(scope, Scope, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Selects the type of key to encrypt this with"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(withKey, WithKey, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The numeric UNIX UID of the user the credential shall be scoped to. Only relevant if 'user' scope is selected (see above). If not specified and 'user' scope is selected defaults to the UID of the calling user, if that can be determined."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("Encrypted credential in Base64 encoding. This can be stored in a credential file, for consumption in LoadEncryptedCredential= and similar calls. Note that the Base64 encoding should be retained when copied into a file."),
                SD_VARLINK_DEFINE_OUTPUT(blob, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Decrypt,
                SD_VARLINK_FIELD_COMMENT("The name of the encrypted credential. Must the same string specified when the credential was encrypted, in order to authenticate this. If not specified authentication of the credential name is not done."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The encrypted credential in Base64 encoding. This corresponds of the 'blob' field returned by the 'Encrypt' method."),
                SD_VARLINK_DEFINE_INPUT(blob, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The timestamp to use when validating the credential's time validity range. If not specified the current time is used."),
                SD_VARLINK_DEFINE_INPUT(timestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The scope for this credential. If not specified no restrictions on the credential scope are made."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(scope, Scope, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If the 'user' scope is selected, specifies the numeric UNIX UID of the user the credential is associated with. If not specified this is automatically derived from the UID of the calling user, if that can be determined."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true allows decryption of credentials encrypted with the null key, if false does not allow it, if unset/null the default depends on whether a TPM device exists and SecureBoot is enabled."),
                SD_VARLINK_DEFINE_INPUT(allowNull, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The decrypted plaintext data in Base64 encoding."),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(BadFormat);
static SD_VARLINK_DEFINE_ERROR(NameMismatch);
static SD_VARLINK_DEFINE_ERROR(TimeMismatch);
static SD_VARLINK_DEFINE_ERROR(NoSuchUser);
static SD_VARLINK_DEFINE_ERROR(BadScope);
static SD_VARLINK_DEFINE_ERROR(CantFindPCRSignature);
static SD_VARLINK_DEFINE_ERROR(NullKeyNotAllowed);
static SD_VARLINK_DEFINE_ERROR(KeyBelongsToOtherTPM);
static SD_VARLINK_DEFINE_ERROR(TPMInDictionaryLockout);
static SD_VARLINK_DEFINE_ERROR(UnexpectedPCRState);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Credentials,
                "io.systemd.Credentials",
                SD_VARLINK_INTERFACE_COMMENT("APIs for encrypting and decrypting service credentials."),
                SD_VARLINK_SYMBOL_COMMENT("The intended scope for the credential."),
                &vl_type_Scope,
                SD_VARLINK_SYMBOL_COMMENT("Selects the key(s) to encrypt the credentials with."),
                &vl_type_WithKey,
                SD_VARLINK_SYMBOL_COMMENT("Encrypts some plaintext data, returns an encrypted credential."),
                &vl_method_Encrypt,
                SD_VARLINK_SYMBOL_COMMENT("Decrypts an encrypted credential, returns plaintext data."),
                &vl_method_Decrypt,
                SD_VARLINK_SYMBOL_COMMENT("Indicates that a corrupt and unsupported encrypted credential was provided."),
                &vl_error_BadFormat,
                SD_VARLINK_SYMBOL_COMMENT("The specified name does not match the name stored in the credential."),
                &vl_error_NameMismatch,
                SD_VARLINK_SYMBOL_COMMENT("The credential's is no longer or not yet valid."),
                &vl_error_TimeMismatch,
                SD_VARLINK_SYMBOL_COMMENT("The specified user does not exist."),
                &vl_error_NoSuchUser,
                SD_VARLINK_SYMBOL_COMMENT("The credential does not match the selected scope."),
                &vl_error_BadScope,
                SD_VARLINK_SYMBOL_COMMENT("PCR signature required for decryption, but not found."),
                &vl_error_CantFindPCRSignature,
                SD_VARLINK_SYMBOL_COMMENT("The key was encrypted with a null key, but that's now allowed during decryption."),
                &vl_error_NullKeyNotAllowed,
                SD_VARLINK_SYMBOL_COMMENT("The TPM integrity check for this key failed, key probably belongs to another TPM, or was corrupted."),
                &vl_error_KeyBelongsToOtherTPM,
                SD_VARLINK_SYMBOL_COMMENT("The TPM is in dictionary lockout mode, cannot operate."),
                &vl_error_TPMInDictionaryLockout,
                SD_VARLINK_SYMBOL_COMMENT("Unexpected TPM PCR state of the system."),
                &vl_error_UnexpectedPCRState);
