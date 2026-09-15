/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sha256.h"

/* Generic helpers for generating (and verifying) file manifests of directory trees, in various formats. */

typedef enum ManifestFormat {
        MANIFEST_FORMAT_LIST,       /* A simple list of file names, one per line */
        _MANIFEST_FORMAT_MAX,
        _MANIFEST_FORMAT_INVALID = -EINVAL,
} ManifestFormat;

/* Optional per-inode fields to include in a manifest, as bitmask. Note that the inode type is not
 * covered by this: it is always included if the format can express it. */
typedef enum ManifestField {
        MANIFEST_FIELD_MODE       = 1 << 0, /* Access mode bits */
        MANIFEST_FIELD_UID        = 1 << 1, /* Owning UID */
        MANIFEST_FIELD_GID        = 1 << 2, /* Owning GID */
        MANIFEST_FIELD_SIZE       = 1 << 3, /* File size (regular files, symlinks) */
        MANIFEST_FIELD_HASH       = 1 << 4, /* Hash of file contents, see ManifestHash for the algorithm */
        MANIFEST_FIELD_SYMLINK    = 1 << 5, /* Symlink target */
        MANIFEST_FIELD_DEVICE     = 1 << 6, /* Major/minor of device nodes */
        MANIFEST_FIELD_HARDLINK   = 1 << 7, /* Hardlink grouping information (only UAPI.16 supports this) */
        MANIFEST_FIELD_MTIME      = 1 << 8, /* Modification time (not in the default set, opt-in) */
        MANIFEST_FIELD_USER_XATTR = 1 << 9, /* Extended attributes in the "user." namespace (only UAPI.16, opt-in) */
        _MANIFEST_FIELD_ALL       = (1 << 10) - 1,
        /* What systemd-dissect --mtree/--manifest have always generated. */
        _MANIFEST_FIELD_DEFAULT   = MANIFEST_FIELD_MODE|MANIFEST_FIELD_UID|MANIFEST_FIELD_GID|MANIFEST_FIELD_SIZE|
                                    MANIFEST_FIELD_HASH|MANIFEST_FIELD_SYMLINK|MANIFEST_FIELD_DEVICE|MANIFEST_FIELD_HARDLINK,
        _MANIFEST_FIELD_INVALID   = -EINVAL,
} ManifestField;

typedef struct ManifestContext {
        ManifestFormat format;
        ManifestField fields;
        FILE *output;           /* not owned */
        bool color;
} ManifestContext;

#define MANIFEST_CONTEXT_NULL                              \
        (const ManifestContext) {                          \
                .format = _MANIFEST_FORMAT_INVALID,        \
                .fields = _MANIFEST_FIELD_DEFAULT,         \
        }

void manifest_context_done(ManifestContext *c);

const char* manifest_format_to_string(ManifestFormat i) _const_;
ManifestFormat manifest_format_from_string(const char *s) _pure_;

/* Only for single bits */
const char* manifest_field_to_string(ManifestField f) _const_;
ManifestField manifest_field_from_string(const char *s) _pure_;

/* Parses a comma separated list of field names. Each item may be prefixed with "+" or "-" to add or remove
 * the field from the mask passed in in *ret, otherwise the mask is reset with the first item. "all", "default"
 * and "none" are accepted as special values. */
int manifest_fields_from_string(const char *s, ManifestField *ret);
int manifest_fields_to_string(ManifestField f, char **ret);

/* Generates a manifest of the directory tree the specified fd refers to, in the format and with the fields
 * configured in the context. */
int manifest_make(ManifestContext *c, int dir_fd);

/* Calculates the hash of the file the specified fd refers to, with the algorithm configured in the context.
 * The fd may be an O_PATH fd. Flushes the output stream first, so that users get an idea where we are when
 * hashing takes a while. */
int manifest_context_hash_fd(ManifestContext *c, int inode_fd, uint8_t ret[static SHA256_DIGEST_SIZE]);
