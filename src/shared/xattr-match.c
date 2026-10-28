/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "alloc-util.h"
#include "compare-operator.h"
#include "errno-util.h"
#include "log.h"
#include "memory-util.h"
#include "nulstr-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "xattr-match.h"
#include "utf8.h"
#include "xattr-util.h"

static const char* const xattr_match_table[_XATTR_MATCH_MAX] = {
        [XATTR_MATCH_HOSTNAME]      = "hostname",
        [XATTR_MATCH_MACHINE_ID]    = "machine-id",
        [XATTR_MATCH_MACHINE_TAGS]  = "machine-tags",
        [XATTR_MATCH_IMAGE_ID]      = "image-id",
        [XATTR_MATCH_IMAGE_VERSION] = "image-version",
        [XATTR_MATCH_OS_ID]         = "os-id",
        [XATTR_MATCH_OS_VERSION_ID] = "os-version-id",
};

DEFINE_STRING_TABLE_LOOKUP(xattr_match, XAttrMatch);

static const char* const xattr_match_xattr_name_table[_XATTR_MATCH_MAX] = {
        [XATTR_MATCH_HOSTNAME]      = "match_hostname",
        [XATTR_MATCH_MACHINE_ID]    = "match_machine_id",
        [XATTR_MATCH_MACHINE_TAGS]  = "match_machine_tags",
        [XATTR_MATCH_IMAGE_ID]      = "match_image_id",
        [XATTR_MATCH_IMAGE_VERSION] = "match_image_version",
        [XATTR_MATCH_OS_ID]         = "match_os_id",
        [XATTR_MATCH_OS_VERSION_ID] = "match_os_version_id",
};

const char* xattr_match_to_xattr_name(XAttrMatch m) {
        assert(m >= 0);
        assert(m < _XATTR_MATCH_MAX);

        return xattr_match_xattr_name_table[m];
}

static const char* host_value(XAttrMatch m, const HostProperties *h, char buf[static SD_ID128_STRING_MAX]) {
        assert(h);

        switch (m) {

        case XATTR_MATCH_HOSTNAME:
                return h->hostname;

        case XATTR_MATCH_MACHINE_ID:
                return sd_id128_is_null(h->machine_id) ? NULL : sd_id128_to_string(h->machine_id, buf);

        case XATTR_MATCH_IMAGE_ID:
                return h->image_id;

        case XATTR_MATCH_IMAGE_VERSION:
                return h->image_version;

        case XATTR_MATCH_OS_ID:
                return h->os_id;

        case XATTR_MATCH_OS_VERSION_ID:
                return h->os_version_id;

        default:
                assert_not_reached();
        }
}

static CompareOperator parse_version_expression(const char **s) {
        assert(s);

        CompareOperator op = parse_compare_operator(s, COMPARE_ALLOW_FNMATCH|COMPARE_EQUAL_BY_STRING);
        if (op < 0) /* No operator? Then treat as glob, like ConditionVersion= does */
                op = COMPARE_FNMATCH_EQUAL;

        *s += strspn(*s, WHITESPACE);
        return op;
}

bool xattr_match_entry_is_valid(XAttrMatch m, const char *s) {
        assert(m >= 0);
        assert(m < _XATTR_MATCH_MAX);

        if (isempty(s) || !utf8_is_valid(s))
                return false;

        if (IN_SET(m, XATTR_MATCH_IMAGE_VERSION, XATTR_MATCH_OS_VERSION_ID)) {
                (void) parse_version_expression(&s);
                return !isempty(s);
        }

        return true;
}

static int test_versions(char * const *l, const char *version) {
        int r;

        /* All expressions must hold. The entries have been validated already. */

        if (!version)
                return false;

        STRV_FOREACH(i, l) {
                const char *s = *i;
                CompareOperator op = parse_version_expression(&s);

                r = version_or_fnmatch_compare(op, version, s);
                if (r <= 0)
                        return r;
        }

        return true;
}

int xattr_match_test_strv(XAttrMatch m, char * const *l, const HostProperties *h) {
        assert(m >= 0);
        assert(m < _XATTR_MATCH_MAX);
        assert(h);

        if (strv_isempty(l))
                return -EINVAL;

        STRV_FOREACH(i, l)
                if (!xattr_match_entry_is_valid(m, *i))
                        return -EINVAL;

        if (m == XATTR_MATCH_MACHINE_TAGS) {
                STRV_FOREACH(i, l)
                        STRV_FOREACH(t, h->machine_tags)
                                if (fnmatch(*i, *t, /* flags= */ 0) == 0)
                                        return true;

                return false;
        }

        char buf[SD_ID128_STRING_MAX];
        const char *v = host_value(m, h, buf);

        if (IN_SET(m, XATTR_MATCH_IMAGE_VERSION, XATTR_MATCH_OS_VERSION_ID))
                return test_versions(l, v);

        if (!v)
                return false;

        STRV_FOREACH(i, l)
                if (fnmatch(*i, v, /* flags= */ 0) == 0)
                        return true;

        return false;
}

void xattr_match_lists_done(XAttrMatchLists *lists) {
        assert(lists);

        FOREACH_ELEMENT(l, *lists)
                *l = strv_free(*l);
}

int xattr_match_filter_test_lists(const XAttrMatchFilter *f, XAttrMatchLists lists, const char *what) {
        int r;

        assert(lists);

        if (!f || f->mask == 0)
                return true;

        assert(f->host);

        for (XAttrMatch m = 0; m < _XATTR_MATCH_MAX; m++) {
                if (!lists[m] || !FLAGS_SET(f->mask, XATTR_MATCH_MASK(m)))
                        continue;

                /* Only load the host properties once there's something to match them against. This is
                 * cheap after the first time, the properties are cached. */
                r = host_properties_load(f->host, f->root);
                if (r < 0)
                        return r;

                r = xattr_match_test_strv(m, lists[m], f->host);
                if (r == -EINVAL) {
                        log_warning("Extended attribute 'user.%s' of '%s' is invalid, not considering it.",
                                    xattr_match_to_xattr_name(m), strna(what));
                        return false;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to match extended attribute 'user.%s' of '%s': %m",
                                               xattr_match_to_xattr_name(m), strna(what));
                if (r == 0) {
                        log_debug("Extended attribute 'user.%s' of '%s' does not match this system, ignoring.",
                                  xattr_match_to_xattr_name(m), strna(what));
                        return false;
                }
        }

        return true;
}

int xattr_match_filter_test_uapi16_object(const XAttrMatchFilter *f, const Uapi16Object *o) {
        assert(o);

        if (!f || f->mask == 0)
                return true;

        /* No information about extended attributes in the manifest, hence no restrictions */
        if (!o->user_xattrs_set)
                return true;

        _cleanup_(xattr_match_lists_done) XAttrMatchLists lists = {};
        for (XAttrMatch m = 0; m < _XATTR_MATCH_MAX; m++) {
                if (!FLAGS_SET(f->mask, XATTR_MATCH_MASK(m)))
                        continue;

                const char *n = xattr_match_to_xattr_name(m);
                FOREACH_ARRAY(x, o->user_xattrs, o->n_user_xattrs) {
                        if (!streq(x->name, n))
                                continue;

                        lists[m] = strv_parse_nulstr(x->value.iov_base, x->value.iov_len);
                        if (!lists[m])
                                return log_oom();
                        break;
                }
        }

        return xattr_match_filter_test_lists(f, lists, o->name);
}

int xattr_match_lists_read(int dir_fd, const char *path, unsigned mask, XAttrMatchLists *ret) {
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);
        assert(ret);

        _cleanup_(xattr_match_lists_done) XAttrMatchLists lists = {};
        for (XAttrMatch m = 0; m < _XATTR_MATCH_MAX; m++) {
                if (!FLAGS_SET(mask, XATTR_MATCH_MASK(m)))
                        continue;

                _cleanup_free_ char *n = strjoin("user.", xattr_match_to_xattr_name(m));
                if (!n)
                        return -ENOMEM;

                r = getxattr_at_strv(dir_fd, path, n, /* at_flags= */ 0, &lists[m]);
                if (ERRNO_IS_NEG_XATTR_ABSENT(r))
                        continue;
                if (r < 0)
                        return r;
        }

        memcpy(*ret, lists, sizeof(lists));
        zero(lists);
        return 0;
}

int xattr_match_filter_test_inode(const XAttrMatchFilter *f, int dir_fd, const char *path) {
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        if (!f || f->mask == 0)
                return true;

        _cleanup_(xattr_match_lists_done) XAttrMatchLists lists = {};
        r = xattr_match_lists_read(dir_fd, path, f->mask, &lists);
        if (r < 0)
                return log_error_errno(r, "Failed to read 'user.match_*' extended attributes of '%s': %m", path);

        return xattr_match_filter_test_lists(f, lists, path);
}
