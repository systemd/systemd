/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Timestamp.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                HashAlgorithm,
                SD_VARLINK_FIELD_COMMENT("SHA-1"),
                SD_VARLINK_DEFINE_ENUM_VALUE(SHA1),
                SD_VARLINK_FIELD_COMMENT("SHA-256."),
                SD_VARLINK_DEFINE_ENUM_VALUE(SHA256),
                SD_VARLINK_FIELD_COMMENT("SHA-384."),
                SD_VARLINK_DEFINE_ENUM_VALUE(SHA384),
                SD_VARLINK_FIELD_COMMENT("SHA-512."),
                SD_VARLINK_DEFINE_ENUM_VALUE(SHA512));

static SD_VARLINK_DEFINE_METHOD(
                Request,
                SD_VARLINK_FIELD_COMMENT("The digest to time-stamp, i.e. the message imprint, as a hex encoded string. Its decoded length must match the selected hash algorithm (e.g. 32 bytes for SHA-256). Exactly one of 'digest' and 'dataFileDescriptor' must be specified."),
                SD_VARLINK_DEFINE_INPUT(digest, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Index of a file descriptor to digest with the selected hash algorithm, as an alternative to supplying a digest directly. Must refer to a regular file opened for reading, no larger than the configured DataSizeMax= limit. The file is read in full from its beginning. Exactly one of 'digest' and 'dataFileDescriptor' must be specified."),
                SD_VARLINK_DEFINE_INPUT(dataFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The hash algorithm the supplied digest was computed with, or that the supplied file descriptor should be digested with. Defaults to 'SHA256' if not specified."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(hashAlgorithm, HashAlgorithm, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Time-Stamp Authority to contact, overriding the one configured in timestampd.conf. Must be a 'tcp://' URL, or an 'http://' or 'https://' one if this build has libcurl support. If not specified the configured default authority is used."),
                SD_VARLINK_DEFINE_INPUT(authority, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true, omit the random nonce that is otherwise included in the request. RFC 3161 recommends a nonce to detect replays, so leave this unset unless the authority cannot handle one."),
                SD_VARLINK_DEFINE_INPUT(noNonce, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to ask the authority to include its signing certificate in the returned token (RFC 3161 certReq). Defaults to true."),
                SD_VARLINK_DEFINE_INPUT(requestCertificate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The time-stamp token returned by the authority, PEM-encoded with a 'PKCS7' label. The token is a CMS/PKCS#7 SignedData structure as returned by the authority."),
                SD_VARLINK_DEFINE_OUTPUT(token, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(
                InvalidDigest,
                SD_VARLINK_FIELD_COMMENT("A description of why the digest was rejected."),
                SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(UnsupportedHashAlgorithm);
static SD_VARLINK_DEFINE_ERROR(DataTooLarge);
static SD_VARLINK_DEFINE_ERROR(NoAuthorityConfigured);
static SD_VARLINK_DEFINE_ERROR(
                InvalidAuthority,
                SD_VARLINK_FIELD_COMMENT("A description of why the authority URL was rejected."),
                SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(
                TimestampAuthorityError,
                SD_VARLINK_FIELD_COMMENT("The RFC 3161 PKIStatus value returned by the authority (e.g. 2 for 'rejection')."),
                SD_VARLINK_DEFINE_FIELD(status, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The human readable status string returned by the authority, if any."),
                SD_VARLINK_DEFINE_FIELD(statusString, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The RFC 3161 PKIFailureInfo bits set by the authority, if any, as the bit numbers PKIFailureInfo assigns (e.g. 0 for 'badAlg', 25 for 'systemFailure')."),
                SD_VARLINK_DEFINE_FIELD(failureInfo, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));
static SD_VARLINK_DEFINE_ERROR(
                NameResolutionFailure,
                SD_VARLINK_FIELD_COMMENT("A description of the resolution failure."),
                SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(
                ConnectionFailure,
                SD_VARLINK_FIELD_COMMENT("A description of the connection failure."),
                SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(TimedOut);
static SD_VARLINK_DEFINE_ERROR(
                InvalidResponse,
                SD_VARLINK_FIELD_COMMENT("A description of what was wrong with the response."),
                SD_VARLINK_DEFINE_FIELD(reason, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Timestamp,
                "io.systemd.Timestamp",
                SD_VARLINK_INTERFACE_COMMENT("An API for requesting RFC 3161 time-stamp tokens from a Time-Stamp Authority (TSA)."),
                SD_VARLINK_SYMBOL_COMMENT("The hash algorithm a digest was computed with."),
                &vl_type_HashAlgorithm,
                SD_VARLINK_SYMBOL_COMMENT("Request a time-stamp token for a digest."),
                &vl_method_Request,
                SD_VARLINK_SYMBOL_COMMENT("The supplied digest is not valid."),
                &vl_error_InvalidDigest,
                SD_VARLINK_SYMBOL_COMMENT("The specified hash algorithm is not supported."),
                &vl_error_UnsupportedHashAlgorithm,
                SD_VARLINK_SYMBOL_COMMENT("The supplied file descriptor refers to a file that is larger than this service is willing to digest."),
                &vl_error_DataTooLarge,
                SD_VARLINK_SYMBOL_COMMENT("No authority was specified in the request and none is configured in timestampd.conf."),
                &vl_error_NoAuthorityConfigured,
                SD_VARLINK_SYMBOL_COMMENT("The specified authority URL is not valid."),
                &vl_error_InvalidAuthority,
                SD_VARLINK_SYMBOL_COMMENT("The authority responded but refused to grant a token."),
                &vl_error_TimestampAuthorityError,
                SD_VARLINK_SYMBOL_COMMENT("The authority's host name could not be resolved."),
                &vl_error_NameResolutionFailure,
                SD_VARLINK_SYMBOL_COMMENT("The authority could not be reached, the connection to it terminated early, or it refused the request at the transport level."),
                &vl_error_ConnectionFailure,
                SD_VARLINK_SYMBOL_COMMENT("The authority did not answer within the configured timeout."),
                &vl_error_TimedOut,
                SD_VARLINK_SYMBOL_COMMENT("The authority answered, but the response was invalid."),
                &vl_error_InvalidResponse);
