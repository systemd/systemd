/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "host-properties.h"
#include "uapi16-manifest.h"

/* Properties of the system resources may be restricted to via "user.uapi.match_…" extended attributes, see
 * MatchXAttr= in sysupdate.d(5) and systemd.v(7). Each extended attribute carries a NUL separated list of
 * entries. */
typedef enum XAttrMatch {
        XATTR_MATCH_HOSTNAME,           /* globs */
        XATTR_MATCH_MACHINE_ID,         /* globs */
        XATTR_MATCH_MACHINE_TAGS,       /* globs, any matching any tag */
        XATTR_MATCH_IMAGE_ID,           /* globs */
        XATTR_MATCH_IMAGE_VERSION,      /* version expressions, all must hold */
        XATTR_MATCH_OS_ID,              /* globs */
        XATTR_MATCH_OS_VERSION_ID,      /* version expressions, all must hold */
        _XATTR_MATCH_MAX,
        _XATTR_MATCH_INVALID = -EINVAL,
} XAttrMatch;

#define XATTR_MATCH_MASK(m) (1U << (m))
#define XATTR_MATCH_MASK_ALL ((1U << _XATTR_MATCH_MAX) - 1)

DECLARE_STRING_TABLE_LOOKUP(xattr_match, XAttrMatch);

/* Returns the name of the extended attribute, without the "user." prefix */
const char* xattr_match_to_xattr_name(XAttrMatch m) _const_;

/* Checks whether a single entry is valid for the specified extended attribute */
bool xattr_match_entry_is_valid(XAttrMatch m, const char *s);

/* Tests a list of entries as read from an extended attribute against the host properties. Returns > 0 on
 * match, 0 on mismatch, and -EINVAL if an entry is invalid. */
int xattr_match_test_strv(XAttrMatch m, char * const *l, const HostProperties *h);

typedef struct XAttrMatchFilter {
        unsigned mask;          /* XATTR_MATCH_MASK() of the matches to check */
        HostProperties *host;   /* loaded lazily, only once there's actually something to match against */
        const char *root;       /* where to load the host properties from */
} XAttrMatchFilter;

/* The entries of the "user.uapi.match_…" extended attributes, indexed by XAttrMatch, NULL if not set */
typedef char **XAttrMatchLists[_XATTR_MATCH_MAX];
void xattr_match_lists_done(XAttrMatchLists *lists);

/* Reads the extended attributes enabled in the XATTR_MATCH_MASK() mask from the specified inode. If path is
 * empty, the inode dir_fd refers to is used (which may be an O_PATH fd). */
int xattr_match_lists_read(int dir_fd, const char *path, unsigned mask, XAttrMatchLists *ret);

/* Tests the lists enabled in the filter's mask against the host properties, see below for return values.
 * "what" is used for logging. */
int xattr_match_filter_test_lists(const XAttrMatchFilter *f, XAttrMatchLists lists, const char *what);

/* Check whether an instance is suitable for the host, based on the "user.uapi.match_…" extended attributes
 * of a file object in a UAPI.16 manifest, or of an inode. An instance that carries none of the extended
 * attributes enabled in the mask is unrestricted, and in that case the host properties are not loaded.
 * Returns > 0 if the instance is suitable, 0 if not (logged at debug level, or as warning if an extended
 * attribute is invalid), < 0 on error. */
int xattr_match_filter_test_uapi16_object(const XAttrMatchFilter *f, const Uapi16Object *o);
int xattr_match_filter_test_inode(const XAttrMatchFilter *f, int dir_fd, const char *path);
