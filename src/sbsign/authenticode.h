/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <openssl/asn1t.h>

#include "macro.h"

#define SPC_INDIRECT_DATA_OBJID "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_DATA_OBJID "1.3.6.1.4.1.311.2.1.15"

typedef struct {
        ASN1_OBJECT *type;
        ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue);

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
        ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
        ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue);

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue);

typedef struct {
        ASN1_OBJECT *algorithm;
        ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier);

ASN1_SEQUENCE(AlgorithmIdentifier) = {
        ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
        ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier);

typedef struct {
        AlgorithmIdentifier *digestAlgorithm;
        ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo);

ASN1_SEQUENCE(DigestInfo) = {
        ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
        ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo);

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo);

typedef struct {
        SpcAttributeTypeAndOptionalValue *data;
        DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent);

ASN1_SEQUENCE(SpcIndirectDataContent) = {
        ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
        ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent);

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcIndirectDataContent*, SpcIndirectDataContent_free, NULL);

typedef struct {
        int type;
        union {
                ASN1_BMPSTRING *unicode;
                ASN1_IA5STRING *ascii;
        } value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString);

ASN1_CHOICE(SpcString) = {
        ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
        ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString);

IMPLEMENT_ASN1_FUNCTIONS(SpcString);

typedef struct {
        ASN1_OCTET_STRING *classId;
        ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject);

ASN1_SEQUENCE(SpcSerializedObject) = {
        ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
        ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject);

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject);

typedef struct {
        int type;
        union {
                ASN1_IA5STRING *url;
                SpcSerializedObject *moniker;
                SpcString *file;
        } value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink);

ASN1_CHOICE(SpcLink) = {
        ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
        ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
        ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink);

IMPLEMENT_ASN1_FUNCTIONS(SpcLink);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcLink*, SpcLink_free, NULL);

typedef struct {
        ASN1_BIT_STRING *flags;
        SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData);

ASN1_SEQUENCE(SpcPeImageData) = {
        ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
        ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcPeImageData*, SpcPeImageData_free, NULL);
