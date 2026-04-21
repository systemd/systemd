/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/asn1.h>

#include "shared-forward.h"

#define SPC_INDIRECT_DATA_OBJID "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_DATA_OBJID "1.3.6.1.4.1.311.2.1.15"

typedef struct {
        ASN1_OBJECT *type;
        ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue);

typedef struct {
        ASN1_OBJECT *algorithm;
        ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier);

typedef struct {
        AlgorithmIdentifier *digestAlgorithm;
        ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo);

typedef struct {
        SpcAttributeTypeAndOptionalValue *data;
        DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent);

typedef struct {
        int type;
        union {
                ASN1_BMPSTRING *unicode;
                ASN1_IA5STRING *ascii;
        } value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString);

typedef struct {
        ASN1_OCTET_STRING *classId;
        ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject);

typedef struct {
        int type;
        union {
                ASN1_IA5STRING *url;
                SpcSerializedObject *moniker;
                SpcString *file;
        } value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink);

typedef struct {
        ASN1_BIT_STRING *flags;
        SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcIndirectDataContent*, SpcIndirectDataContent_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcLink*, SpcLink_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcPeImageData*, SpcPeImageData_free, NULL);
