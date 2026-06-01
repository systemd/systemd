/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.CryptEnroll.h"

/* The credential types this interface knows about. The same enum is used for the 'mechanism' to enroll, for
 * the slot types to wipe, and for the slot types reported by ListSlots. Note that only password, recovery_key
 * and fido2 may actually be *enrolled* via the Enroll() method; pkcs11 and tpm2 slots can be listed and wiped,
 * but enrolling them requires the systemd-cryptenroll command line. Enroll() rejects them with an
 * InvalidParameter error rather than via interface validation, so they are part of this enum. */
static SD_VARLINK_DEFINE_ENUM_TYPE(
                EnrollMechanism,
                SD_VARLINK_FIELD_COMMENT("A regular passphrase"),
                SD_VARLINK_DEFINE_ENUM_VALUE(password),
                SD_VARLINK_FIELD_COMMENT("A randomly generated recovery key"),
                SD_VARLINK_DEFINE_ENUM_VALUE(recovery),
                SD_VARLINK_FIELD_COMMENT("A PKCS#11 security token (not enrollable via this interface)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(pkcs11),
                SD_VARLINK_FIELD_COMMENT("A FIDO2 security token"),
                SD_VARLINK_DEFINE_ENUM_VALUE(fido2),
                SD_VARLINK_FIELD_COMMENT("A TPM2 device (not enrollable via this interface)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(tpm2));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Enroll,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Path to the LUKS2 block device or image to operate on."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Which kind of credential to enroll. Only 'password', 'recovery_key' and 'fido2' may be enrolled via this interface; 'pkcs11' and 'tpm2' are rejected with an InvalidParameter error."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mechanism, EnrollMechanism, 0),

                SD_VARLINK_FIELD_COMMENT("How to unlock the volume for the enrollment operation is inferred from which of the following fields are set: setting unlockPassword unlocks via that password, unlockKeyFile/unlockKeyFileDescriptorIndex via a key file, unlockFido2Device via FIDO2, unlockTpm2Device via TPM2. If none are set the volume is unlocked via cached credentials. At most one may be set."),
                SD_VARLINK_DEFINE_INPUT(unlockPassword, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to a key file to unlock the volume with."),
                SD_VARLINK_DEFINE_INPUT(unlockKeyFile, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Index into the file descriptors passed along with this call, identifying a key file to unlock the volume with."),
                SD_VARLINK_DEFINE_INPUT(unlockKeyFileDescriptorIndex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to a FIDO2 device to unlock the volume with. Leave the path empty to automatically discover a suitable device."),
                SD_VARLINK_DEFINE_INPUT(unlockFido2Device, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to a TPM2 device to unlock the volume with. Leave the path empty to automatically discover a suitable device."),
                SD_VARLINK_DEFINE_INPUT(unlockTpm2Device, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("The passphrase to enroll, when mechanism is 'password'. Contains key material."),
                SD_VARLINK_DEFINE_INPUT(password, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("Path to the FIDO2 device to enroll, when mechanism is 'fido2'. Leave empty to automatically discover a suitable device."),
                SD_VARLINK_DEFINE_INPUT(fido2Device, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The FIDO2 token PIN to use for enrollment. Contains key material."),
                SD_VARLINK_DEFINE_INPUT(fido2Pin, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether unlocking the FIDO2 enrollment shall require a client PIN. Defaults to true."),
                SD_VARLINK_DEFINE_INPUT(fido2WithClientPin, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether unlocking the FIDO2 enrollment shall require user presence (touch). Defaults to true."),
                SD_VARLINK_DEFINE_INPUT(fido2WithUserPresence, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether unlocking the FIDO2 enrollment shall require user verification. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(fido2WithUserVerification, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),

                SD_VARLINK_FIELD_COMMENT("Explicit list of keyslot indexes to wipe after enrolling."),
                SD_VARLINK_DEFINE_INPUT(wipeSlots, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Wipe all already-enrolled slots of these types after enrolling."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(wipeTypes, EnrollMechanism, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                VARLINK_DEFINE_POLKIT_INPUT,

                SD_VARLINK_FIELD_COMMENT("The keyslot the new credential was enrolled into. Set on the terminating reply only."),
                SD_VARLINK_DEFINE_OUTPUT(keyslot, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The keyslots wiped as part of this call, if any."),
                SD_VARLINK_DEFINE_OUTPUT(wipedSlots, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The generated recovery key, when mechanism is 'recoveryKey'. Contains key material."),
                SD_VARLINK_DEFINE_OUTPUT(recoveryKey, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Progress indicator, only sent on intermediate replies when 'more' was set. Currently the only value is 'touch', signalling that the FIDO2 token is waiting for a touch. Unset on the terminating reply."),
                SD_VARLINK_DEFINE_OUTPUT(state, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListSlots,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Path to the LUKS2 block device or image to operate on."),
                SD_VARLINK_DEFINE_INPUT(node, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A currently enrolled keyslot index."),
                SD_VARLINK_DEFINE_OUTPUT(slot, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of the keyslot. Unset for a bare password slot with no token, or when a token of an unrecognized type is present."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, EnrollMechanism, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(VolumeUnderForeignManagement);
static SD_VARLINK_DEFINE_ERROR(PasswordRequired);
static SD_VARLINK_DEFINE_ERROR(PasswordIncorrect);
static SD_VARLINK_DEFINE_ERROR(FidoDeviceNotFound);
static SD_VARLINK_DEFINE_ERROR(FidoActionTimeout);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_CryptEnroll,
                "io.systemd.CryptEnroll",
                SD_VARLINK_INTERFACE_COMMENT("API for enrolling credentials into LUKS2 volumes via systemd-cryptenroll."),
                SD_VARLINK_SYMBOL_COMMENT("The credential types this interface knows about, used both as the enrollment mechanism and as the slot type reported by ListSlots."),
                &vl_type_EnrollMechanism,
                SD_VARLINK_SYMBOL_COMMENT("Enroll a credential into a LUKS2 volume. When enrolling a FIDO2 token that requires user presence, the call must be made with the 'more' flag, so that the server can report when a touch is required via a 'touch' state notification."),
                &vl_method_Enroll,
                SD_VARLINK_SYMBOL_COMMENT("Enumerate the keyslots currently enrolled in a LUKS2 volume, one per reply. Must be called with the 'more' flag."),
                &vl_method_ListSlots,
                SD_VARLINK_SYMBOL_COMMENT("The volume is managed by another subsystem (e.g. systemd-homed) and may not be enrolled into directly."),
                &vl_error_VolumeUnderForeignManagement,
                SD_VARLINK_SYMBOL_COMMENT("A password is required to unlock the volume, but none was provided."),
                &vl_error_PasswordRequired,
                SD_VARLINK_SYMBOL_COMMENT("The provided password did not unlock the volume."),
                &vl_error_PasswordIncorrect,
                SD_VARLINK_SYMBOL_COMMENT("No matching FIDO2 device was found."),
                &vl_error_FidoDeviceNotFound,
                SD_VARLINK_SYMBOL_COMMENT("The FIDO2 token was not interacted with in time."),
                &vl_error_FidoActionTimeout);
