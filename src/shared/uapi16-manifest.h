/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "sd-id128.h"
#include "sd-json.h"

#include "recurse-dir.h"
#include "sha256.h"
#include "string-util.h"
#include "path-util.h"

typedef struct Uapi16Contents {
        char *file;
        char *url;
        struct iovec literal;
        char *encoding;
        uint64_t encoded_size;
        struct iovec encoded_sha256;
        uint64_t original_size;
        struct iovec original_sha256;
        uint64_t offset;
} Uapi16Contents;

#define UAPI16_CONTENTS_NULL (const Uapi16Contents) { \
                .encoded_size = UINT64_MAX,           \
                .original_size = UINT64_MAX,          \
        }

/* An extended attribute in the "user" namespace */
typedef struct Uapi16Xattr {
        char *name;          /* The attribute name, without the "user." prefix */
        struct iovec value;
} Uapi16Xattr;

typedef enum Uapi16Validity {
        UAPI16_REVOKED,
        UAPI16_GOOD,
        _UAPI16_VALIDITY_MAX,
        _UAPI16_VALIDITY_INVALID = -EINVAL,
} Uapi16Validity;

typedef struct Uapi16Object {
        char *name;
        char *media_type;
        mode_t type;  /* the inode type, i.e. S_IFREG, S_IFDIR, … – but no access mode bits */
        uint64_t size;
        mode_t mode;  /* the access bits, without inode type */
        uid_t uid;
        gid_t gid;
        uint64_t major, minor;
        nsec_t mtime_nsec;
        uint64_t inode_token;
        Uapi16Xattr *user_xattrs;  /* sorted by name */
        size_t n_user_xattrs;
        bool user_xattrs_set;      /* if false, the object conveys no information about "user" xattrs */
        char *gpt_label;
        sd_id128_t gpt_uuid;
        bool gpt_uuid_set;
        sd_id128_t gpt_type_uuid;
        bool gpt_type_uuid_set;
        sd_id128_t gpt_disk_uuid;
        bool gpt_disk_uuid_set;
        uint64_t gpt_flags;
        bool gpt_flags_set;
        int gpt_no_auto;
        int gpt_growfs;
        int read_only;
        Uapi16Contents *contents;
        size_t n_contents;
        struct iovec sha256;
        usec_t valid_since_usec, valid_until_usec;
        Uapi16Validity validity;

        /* NB: we omit a bunch of UAPI.16 specified fields we currently don't intend to consume.  */
} Uapi16Object;

#define UAPI16_OBJECT_NULL (const Uapi16Object) {     \
                .size = UINT64_MAX,                   \
                .mode = MODE_INVALID,                 \
                .uid = UID_INVALID,                   \
                .gid = GID_INVALID,                   \
                .major = UINT64_MAX,                  \
                .minor = UINT64_MAX,                  \
                .mtime_nsec = NSEC_INFINITY,          \
                .inode_token = UINT64_MAX,            \
                .read_only = -1,                      \
                .gpt_no_auto = -1,                    \
                .gpt_growfs = -1,                     \
                .valid_until_usec = USEC_INFINITY,    \
                .validity = _UAPI16_VALIDITY_INVALID, \
        }

#define UAPI16_MANIFEST_FILENAME "Uapi16Manifest"
#define UAPI16_MANIFEST_SUFFIX ".Uapi16Manifest"
#define UAPI16_MANIFEST_MEDIA_TYPE "application/vnd.uapi.16.manifest"
#define UAPI16_SIGNATURE_MEDIA_TYPE "application/vnd.uapi.16.signature"
#define UAPI16_TRAILER_MEDIA_TYPE "application/vnd.uapi.16.trailer"

/* Returns true for the file name of the manifest when embedded in the file tree it covers (and its suffixed
 * variants). Note that should only be checked for top-level files. */
static inline bool uapi16_manifest_filename_is_reserved(const char *name) {
        return filename_is_valid(name) && /* refuse paths, insist on filenames */
                (streq(name, UAPI16_MANIFEST_FILENAME) ||
                 !isempty(startswith(name, UAPI16_MANIFEST_FILENAME ".")));
}

/* Returns true when this is a regular manifest with the .Uapi16Manifest suffix at any location */
static inline bool uapi16_manifest_filename_is_suffixed(const char *name) {
        return filename_is_valid(name) && /* refuse paths, insist on filenames */
                (endswith(name, UAPI16_MANIFEST_SUFFIX) || !isempty(strstr(name, UAPI16_MANIFEST_SUFFIX ".")));
}

/* Validates the "name" field of a file object: a normalized relative path, that is not reserved. */
bool uapi16_name_is_valid(const char *s) _pure_;

/* Validates the name of an extended attribute (without namespace prefix) */
bool uapi16_xattr_name_is_valid(const char *s) _pure_;

void uapi16_contents_done(Uapi16Contents *c);
void uapi16_xattr_done(Uapi16Xattr *x);
void uapi16_xattr_array_free(Uapi16Xattr *x, size_t n);

/* Sorts the array by name, and refuses duplicates with -ENOTUNIQ */
int uapi16_xattr_array_sort(Uapi16Xattr *x, size_t n);

/* Builds the "extendedAttributes" field from a list of "user" namespace xattrs */
int uapi16_xattrs_build_json(const Uapi16Xattr *x, size_t n, sd_json_variant **ret);

void uapi16_object_done(Uapi16Object *o);
int uapi16_object_check_validity(Uapi16Object *o);

int dispatch_uapi16_object(sd_json_variant *v, size_t n, sd_json_dispatch_flags_t flags, Uapi16Object *ret);

DECLARE_STRING_TABLE_LOOKUP(uapi16_validity, Uapi16Validity);

/* Returns the "mediaType" field of an object in the JSON-SEQ stream, so that callers can tell file objects,
 * signature objects and objects of unknown type apart. Returns 0 if the object has no such field. */
int uapi16_object_media_type(sd_json_variant *v, const char **ret);

typedef enum Uapi16SignatureMechanism {
        UAPI16_SIGNATURE_PKCS7,
        UAPI16_SIGNATURE_OPENPGP,
        _UAPI16_SIGNATURE_MECHANISM_MAX,
        _UAPI16_SIGNATURE_MECHANISM_INVALID = -EINVAL,
} Uapi16SignatureMechanism;

DECLARE_STRING_TABLE_LOOKUP(uapi16_signature_mechanism, Uapi16SignatureMechanism);

typedef struct Uapi16Signature {
        char *media_type;
        Uapi16SignatureMechanism mechanism; /* _INVALID if the mechanism is not known to us */
        struct iovec key;                   /* Key identifier (fingerprint), may be unset */
        struct iovec data;                  /* The signature blob */
} Uapi16Signature;

#define UAPI16_SIGNATURE_NULL (const Uapi16Signature) {                 \
                .mechanism = _UAPI16_SIGNATURE_MECHANISM_INVALID,       \
        }

void uapi16_signature_done(Uapi16Signature *s);

/* Parses a signature object, i.e. an object with the UAPI16_SIGNATURE_MEDIA_TYPE media type. */
int dispatch_uapi16_signature_object(sd_json_variant *v, sd_json_dispatch_flags_t flags, Uapi16Signature *ret);
