/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Credentials.h"

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
                SD_VARLINK_DEFINE_INPUT(scope, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_INPUT(scope, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If the 'user' scope is selected, specifies the numeric UNIX UID of the user the credential is associated with. If not specified this is automatically derived from the UID of the calling user, if that can be determined."),
                SD_VARLINK_DEFINE_INPUT(uid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The decrypted plaintext data in Base64 encoding."),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(BadFormat);
static SD_VARLINK_DEFINE_ERROR(NameMismatch);
static SD_VARLINK_DEFINE_ERROR(TimeMismatch);
static SD_VARLINK_DEFINE_ERROR(NoSuchUser);
static SD_VARLINK_DEFINE_ERROR(BadScope);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Credentials,
                "io.systemd.Credentials",
                SD_VARLINK_INTERFACE_COMMENT("APIs for encrypting and decrypting service credentials."),
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
                &vl_error_BadScope);
