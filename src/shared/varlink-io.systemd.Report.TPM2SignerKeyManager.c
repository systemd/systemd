/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Report.TPM2SignerKeyManager.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                KeyType,
                SD_VARLINK_FIELD_COMMENT("An ordinary signing key protected by an existing storage key that is stored at a persistent handle in the TPM."),
                SD_VARLINK_DEFINE_ENUM_VALUE(ordinary),
                SD_VARLINK_FIELD_COMMENT("A signing key that is stored at a persistent handle in the TPM and may or may not be a primary key."),
                SD_VARLINK_DEFINE_ENUM_VALUE(persistent),
                SD_VARLINK_FIELD_COMMENT("A signing key that is a primary object and which is recreated from a template when required."),
                SD_VARLINK_DEFINE_ENUM_VALUE(primary));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                SigningScheme,
                SD_VARLINK_FIELD_COMMENT("RSASSA - old RSA Signature Scheme with Appendix (PKCS#1 v1.5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(rsassa),
                SD_VARLINK_FIELD_COMMENT("RSASSA-PSS - improved RSA Signature Scheme with Appendix based on the Probability Signature Scheme (PKCS#1 v2.1)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(rsapss),
                SD_VARLINK_FIELD_COMMENT("ECDSA - a verson of the Digital Signature Algorithm based on elliptic curves."),
                SD_VARLINK_DEFINE_ENUM_VALUE(ecdsa));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                HashAlgorithm,
                SD_VARLINK_FIELD_COMMENT("SHA-256"),
                SD_VARLINK_DEFINE_ENUM_VALUE(sha256),
                SD_VARLINK_FIELD_COMMENT("SHA-384"),
                SD_VARLINK_DEFINE_ENUM_VALUE(sha384),
                SD_VARLINK_FIELD_COMMENT("SHA-512"),
                SD_VARLINK_DEFINE_ENUM_VALUE(sha512));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ECCCurve,
                SD_VARLINK_FIELD_COMMENT("256-bit prime field Weierstrass curve, also known as secp256r1 or prime256v1."),
                SD_VARLINK_DEFINE_ENUM_VALUE(nistp256),
                SD_VARLINK_FIELD_COMMENT("384-bit prime field Weierstrass curve, also known as secp384r1 or ansip384r1."),
                SD_VARLINK_DEFINE_ENUM_VALUE(nistp384),
                SD_VARLINK_FIELD_COMMENT("521-bit prime field Weierstrass curve, also known as secp521r1 or ansip421r1."),
                SD_VARLINK_DEFINE_ENUM_VALUE(nistp521));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                Hierarchy,
                SD_VARLINK_FIELD_COMMENT("The TPM's storage hierarchy. This hierarchy is invalidated by a TPM2_Clear."),
                SD_VARLINK_DEFINE_ENUM_VALUE(owner),
                SD_VARLINK_FIELD_COMMENT("The TPM's endorsement hierarchy. This hierarchy is not invalidated by a TPM2_Clear."),
                SD_VARLINK_DEFINE_ENUM_VALUE(endorsement),
                SD_VARLINK_FIELD_COMMENT("The TPM's null hierarchy. This hierarchy is invalidated on every TPM reset."),
                SD_VARLINK_DEFINE_ENUM_VALUE(null));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                KeyStatus,
                SD_VARLINK_FIELD_COMMENT("The signing key is available for signing."),
                SD_VARLINK_DEFINE_ENUM_VALUE(available),
                SD_VARLINK_FIELD_COMMENT("The signing key is no longer available. For an ordinary key, this might be because the persistent object in the TPM at the parent handle is no longer the correct one. For persistent keys, this is because the object at the persistent handle in the TPM is no longer available or the correct one. For primary keys, this is because the hierarchy seed has changed."),
                SD_VARLINK_DEFINE_ENUM_VALUE(unavailable));

static SD_VARLINK_DEFINE_METHOD(
                CreateKey,
                SD_VARLINK_FIELD_COMMENT("The name to use for the new signing key."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The type of signing key to create."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(type, KeyType, 0),
                SD_VARLINK_FIELD_COMMENT("The signing scheme that the new signing key will use."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(scheme, SigningScheme, 0),
                SD_VARLINK_FIELD_COMMENT("The digest algorithm that the new signing key will use. This will also be used for the new key's name algorithm."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(hashAlg, HashAlgorithm, 0),
                SD_VARLINK_FIELD_COMMENT("For RSA keys, the size of the key's modulus in bits."),
                SD_VARLINK_DEFINE_INPUT(rsaKeyBits, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For elliptic keys, the curve to use."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(eccCurve, ECCCurve, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For ordinary or persistent keys, the persistent handle for the parent of the new signing key. For persistent keys, only this field, parentContext or hierarchy shall be specified."),
                SD_VARLINK_DEFINE_INPUT(parentHandle, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For persistent keys, the base64 encoded TPMS_CONTEXT of the parent of the new signing key, which allows the parent to be a transient object. This must be a TPMS_CONTEXT in the form serialized by TSS2, containing the TSS2 handle metadata. Only this field, parentHandle or hierarchy shall be specified."),
                SD_VARLINK_DEFINE_INPUT(parentContext, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For persistent or primary keys, the hierarchy to create the new signing key in. For persistent keys, only this field, parentHandle or parentContedt shall be specified."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(hierarchy, Hierarchy, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For persistent keys, the handle to which the new signing key will be stored in the TPM."),
                SD_VARLINK_DEFINE_INPUT(persistentHandle, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For primary keys, a base64 encoded nonce used to customize the template."),
                SD_VARLINK_DEFINE_INPUT(primaryNonce, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new signing key's public area as the JSON encoded TPMT_PUBLIC structure."),
                SD_VARLINK_DEFINE_OUTPUT(public, SD_VARLINK_OBJECT, 0),
                SD_VARLINK_FIELD_COMMENT("The new signing key's public part, PEM encoded."),
                SD_VARLINK_DEFINE_OUTPUT(publicPEM, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                DeleteKey,
                SD_VARLINK_FIELD_COMMENT("The name of the signing key to delete."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListKeys,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("A filter to select which signing keys to return. Supports globbing."),
                SD_VARLINK_DEFINE_INPUT(filter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The name of the signing key."),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of signing key."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(type, KeyType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The status of the signing key."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(status, KeyStatus, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The signing key's public area as a JSON encoded TPMT_PUBLIC structure."),
                SD_VARLINK_DEFINE_OUTPUT(public, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The new signing key's public part, PEM encoded."),
                SD_VARLINK_DEFINE_OUTPUT(publicPEM, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For persistent signing keys, the handle at which this key is stored in the TPM."),
                SD_VARLINK_DEFINE_OUTPUT(persistentHandle, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For primary signing keys, the TPM hierarchy in which the key resides."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(hierarchy, Hierarchy, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The base64 encoded voucher associated with this signing key, if one exists. The format of the voucher is not specified."),
                SD_VARLINK_DEFINE_OUTPUT(voucher, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(KeyExists);

static SD_VARLINK_DEFINE_ERROR(
                UnsupportedTemplate,
                SD_VARLINK_FIELD_COMMENT("The template parameter that is not supported by the TPM."),
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NotEnoughSpace);
static SD_VARLINK_DEFINE_ERROR(PersistentHandleExists);
static SD_VARLINK_DEFINE_ERROR(NoSuchKey);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Report_TPM2SignerKeyManager,
                "io.systemd.Report.TPM2SignerKeyManager",
                SD_VARLINK_INTERFACE_COMMENT("API for managing signing keys for the TPM2 report signer."),
                SD_VARLINK_SYMBOL_COMMENT("Create a new key for signing reports with the TPM."),
                &vl_method_CreateKey,
                SD_VARLINK_SYMBOL_COMMENT("Delete an existing signing key."),
                &vl_method_DeleteKey,
                SD_VARLINK_SYMBOL_COMMENT("List available signing keys."),
                &vl_method_ListKeys,
                SD_VARLINK_SYMBOL_COMMENT("The type of signing key."),
                &vl_type_KeyType,
                SD_VARLINK_SYMBOL_COMMENT("The signature scheme supported by a signing key."),
                &vl_type_SigningScheme,
                SD_VARLINK_SYMBOL_COMMENT("The digest algorithm used by a signing key for generating signatures."),
                &vl_type_HashAlgorithm,
                SD_VARLINK_SYMBOL_COMMENT("The elliptic curve of a signing key."),
                &vl_type_ECCCurve,
                SD_VARLINK_SYMBOL_COMMENT("The TPM hierarchy that a primary signing key is created in."),
                &vl_type_Hierarchy,
                SD_VARLINK_SYMBOL_COMMENT("The status of a signing key."),
                &vl_type_KeyStatus,
                SD_VARLINK_SYMBOL_COMMENT("A signing key with the requested name already exists."),
                &vl_error_KeyExists,
                SD_VARLINK_SYMBOL_COMMENT("The requested combination of key template parameters (signing scheme, digest algorithm, RSA key size or elliptic curve) is not supported by the TPM."),
                &vl_error_UnsupportedTemplate,
                SD_VARLINK_SYMBOL_COMMENT("There is not enough persistent storage space in the TPM to persist a new object."),
                &vl_error_NotEnoughSpace,
                SD_VARLINK_SYMBOL_COMMENT("A persistent object already exists at the requested handle."),
                &vl_error_PersistentHandleExists,
                SD_VARLINK_SYMBOL_COMMENT("No signing key with the requested name exists."),
                &vl_error_NoSuchKey);
