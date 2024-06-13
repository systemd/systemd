/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Credentials.h"

static VARLINK_DEFINE_METHOD(
                Encrypt,
                VARLINK_FIELD_COMMENT("The name for the encrypted credential, a string suitable for inclusion in a file name. If not specified no name is encoded in the credential. Typically, if this credential is stored on disk, this is how the file should be called, and permits authentication of the filename."),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Plaintext to encrypt. Suitable only for textual data. Either this field or 'data' (below) must be provided."),
                VARLINK_DEFINE_INPUT(text, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Plaintext to encrypt, encoded in Base64. Suitable for binary data. Either this field or 'text' (above) must be provided."),
                VARLINK_DEFINE_INPUT(data, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Timestamp to store in the credential. In µs since the UNIX epoch, i.e. Jan 1st 1970. If not specified the current time is used."),
                VARLINK_DEFINE_INPUT(timestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Timestamp when to the credential should be considered invalid. In µs since the UNIX epoch. If not specified, the credential remains valid forever."),
                VARLINK_DEFINE_INPUT(notAfter, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The intended scope for the credential. One of 'system' or 'user'. If not specified defaults to 'system', unless an uid is specified (see below), in which case it default to 'user'."),
                VARLINK_DEFINE_INPUT(scope, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The numeric UNIX UID of the user the credential shall be scoped to. Only relevant if 'user' scope is selected (see above). If not specified and 'user' scope is selected defaults to the UID of the calling user, if that can be determined."),
                VARLINK_DEFINE_INPUT(uid, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Controls whether interactive authentication (via polkit) shall be allowed. If unspecified defaults to false."),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Encrypted credential in Base64 encoding. This can be stored in a credential file, for consumption in LoadEncryptedCredential= and similar calls. Note that the Base64 encoding should be retained when copied into a file."),
                VARLINK_DEFINE_OUTPUT(blob, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                Decrypt,
                VARLINK_FIELD_COMMENT("The name of the encrypted credential. Must the same string specified when the credential was encrypted, in order to authenticate this. If not specified authentication of the credential name is not done."),
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The encrypted credential in Base64 encoding. This corresponds of the 'blob' field returned by the 'Encrypt' method."),
                VARLINK_DEFINE_INPUT(blob, VARLINK_STRING, 0),
                VARLINK_FIELD_COMMENT("The timestamp to use when validating the credential's time validity range. If not specified the current time is used."),
                VARLINK_DEFINE_INPUT(timestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The scope for this credential. If not specified no restrictions on the credential scope are made."),
                VARLINK_DEFINE_INPUT(scope, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("If the 'user' scope is selected, specifies the numeric UNIX UID of the user the credential is associated with. If not specified this is automatically derived from the UID of the calling user, if that can be determined."),
                VARLINK_DEFINE_INPUT(uid, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("Controls whether interactive authentication (via polkit) shall be allowed. If unspecified defaults to false."),
                VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_FIELD_COMMENT("The decrypted plaintext data in Base64 encoding."),
                VARLINK_DEFINE_OUTPUT(data, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(BadFormat);
static VARLINK_DEFINE_ERROR(NameMismatch);
static VARLINK_DEFINE_ERROR(TimeMismatch);
static VARLINK_DEFINE_ERROR(NoSuchUser);
static VARLINK_DEFINE_ERROR(BadScope);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Credentials,
                "io.systemd.Credentials",
                VARLINK_INTERFACE_COMMENT("APIs for encrypting and decrypting service credentials."),
                VARLINK_SYMBOL_COMMENT("Encrypts some plaintext data, returns an encrypted credential."),
                &vl_method_Encrypt,
                VARLINK_SYMBOL_COMMENT("Decrypts an encrypted credential, returns plaintext data."),
                &vl_method_Decrypt,
                VARLINK_SYMBOL_COMMENT("Indicates that a corrupt and unsupported encrypted credential was provided."),
                &vl_error_BadFormat,
                VARLINK_SYMBOL_COMMENT("The specified name does not match the name stored in the credential."),
                &vl_error_NameMismatch,
                VARLINK_SYMBOL_COMMENT("The credential's is no longer or not yet valid."),
                &vl_error_TimeMismatch,
                VARLINK_SYMBOL_COMMENT("The specified user does not exist."),
                &vl_error_NoSuchUser,
                VARLINK_SYMBOL_COMMENT("The credential does not match the selected scope."),
                &vl_error_BadScope);
