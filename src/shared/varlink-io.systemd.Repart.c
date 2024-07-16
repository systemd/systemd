/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.repart.h"
#include "sd-varlink-idl.h"

/* NOTE: This API was intentionally designed to be the minimum needed by known clients. With Varlink, you can
 *       always add more functionality, but removing functionality would be backwards incompatible. If
 *       something you need is missing, PRs implementing it will be welcome! */

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EmptyMode,
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks without an existing partition table"),
                SD_VARLINK_DEFINE_ENUM_VALUE(refuse),
                SD_VARLINK_FIELD_COMMENT("Create a new partition table if one doesn't already exist on disk"),
                SD_VARLINK_DEFINE_ENUM_VALUE(allow),
                SD_VARLINK_FIELD_COMMENT("Refuse to operate on disks with an existing partition table, and create a new table if none exists."),
                SD_VARLINK_DEFINE_ENUM_VALUE(require),
                SD_VARLINK_FIELD_COMMENT("Always create a new partition table, potentially overwriting an existing table."),
                SD_VARLINK_DEFINE_ENUM_VALUE(force),
                SD_VARLINK_FIELD_COMMENT(""),
                SD_VARLINK_DEFINE_ENUM_VALUE(create));

static SD_VARLINK_DEFINE_METHOD(
                Check,
                SD_VARLINK_FIELD_COMMENT("The path to the target block device's node. The client should use the target's by-diskseq symlink if possible."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Paths to static definition files to be used by the client. Note that this is NOT intended for dynamically-generated definitions created by code."),
                SD_VARLINK_DEFINE_INPUT(definition_paths, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                /* Known-missing: A field for code-generated definitions. This shouldn't be hard to impl,
                 * just tedious: you'd need to define a Varlink type for the config file and then implement
                 * parsers for it. */


                /* NOTE: The above field is NOT intended */
                /* NOTE: The above is NOT indented */

                )






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
                SD_VARLINK_FIELD_COMMENT("Controls whether interactive authentication (via polkit) shall be allowed. If unspecified defaults to false."),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_FIELD_COMMENT("Controls whether interactive authentication (via polkit) shall be allowed. If unspecified defaults to false."),
                SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The decrypted plaintext data in Base64 encoding."),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(BadFormat);
static SD_VARLINK_DEFINE_ERROR(NameMismatch);
static SD_VARLINK_DEFINE_ERROR(TimeMismatch);
static SD_VARLINK_DEFINE_ERROR(NoSuchUser);
static SD_VARLINK_DEFINE_ERROR(BadScope);












SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Repart,
                "io.systemd.Repart",
                SD_VARLINK_INTERFACE_COMMENT("APIs for declaratively re-partitioning disks. Most useful for OS installers. This API is intentionally designed to be the minimum necessary for known clients, if you need some functionality that's missing PRs are welcome!");

                SD_VARLINK_SYMBOL_COMMENT("Behaviors for disks that are completely empty (i.e. don't have a partition table yet)"),
                &vl_type_EmptyMode,

                SD_VARLINK_SYMBOL_COMMENT("Lets a client check if the image it's about to deploy will fit on a given target disk."),
                &vl_method_Check,
                SD_VARLINK_SYMBOL_COMMENT("Lets a client deploy an image onto a given target disk."),
                &vl_method_Partition,

                SD_VARLINK_SYMBOL_COMMENT("The specified disk is "),
                &vl_error_DiskTooSmall,
                SD_VARLINK_SYMBOL_COMMENT(""),
                &vl_error_WontFit);
