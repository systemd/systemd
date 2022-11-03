/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hexdecoct.h"
#include "list.h"
#include "parse-util.h"
#include "path-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "sysupdate-pattern.h"
#include "sysupdate-util.h"

typedef enum PatternElementType {
        PATTERN_LITERAL,
        PATTERN_VERSION,
        PATTERN_PARTITION_UUID,
        PATTERN_PARTITION_FLAGS,
        PATTERN_MTIME,
        PATTERN_MODE,
        PATTERN_SIZE,
        PATTERN_TRIES_DONE,
        PATTERN_TRIES_LEFT,
        PATTERN_NO_AUTO,
        PATTERN_READ_ONLY,
        PATTERN_GROWFS,
        PATTERN_SHA256SUM,
        _PATTERN_ELEMENT_TYPE_MAX,
        _PATTERN_ELEMENT_TYPE_INVALID = -EINVAL,
} PatternElementType;

typedef struct PatternElement PatternElement;

struct PatternElement {
        PatternElementType type;
        LIST_FIELDS(PatternElement, elements);
        char literal[];
};

static PatternElement *pattern_element_free_all(PatternElement *e) {
        PatternElement *p;

        while ((p = LIST_POP(elements, e)))
                free(p);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(PatternElement*, pattern_element_free_all);

static PatternElementType pattern_element_type_from_char(char c) {
        switch (c) {
        case 'v':
                return PATTERN_VERSION;
        case 'u':
                return PATTERN_PARTITION_UUID;
        case 'f':
                return PATTERN_PARTITION_FLAGS;
        case 't':
                return PATTERN_MTIME;
        case 'm':
                return PATTERN_MODE;
        case 's':
                return PATTERN_SIZE;
        case 'd':
                return PATTERN_TRIES_DONE;
        case 'l':
                return PATTERN_TRIES_LEFT;
        case 'a':
                return PATTERN_NO_AUTO;
        case 'r':
                return PATTERN_READ_ONLY;
        case 'g':
                return PATTERN_GROWFS;
        case 'h':
                return PATTERN_SHA256SUM;
        default:
                return _PATTERN_ELEMENT_TYPE_INVALID;
        }
}

static bool valid_char(char x) {

        /* Let's refuse control characters here, and let's reserve some characters typically used in pattern
         * languages so that we can use them later, possibly. */

        if ((unsigned) x < ' ' || x >= 127)
                return false;

        return !IN_SET(x, '$', '*', '?', '[', ']', '!', '\\', '/', '|');
}

static int pattern_split(
                const char *pattern,
                PatternElement **ret) {

        _cleanup_(pattern_element_free_allp) PatternElement *first = NULL;
        bool at = false, last_literal = true;
        PatternElement *last = NULL;
        uint64_t mask_found = 0;
        size_t l, k = 0;

        assert(pattern);

        l = strlen(pattern);

        for (const char *e = pattern; *e != 0; e++) {
                if (*e == '@') {
                        if (!at) {
                                at = true;
                                continue;
                        }

                        /* Two at signs in a sequence, write out one */
                        at = false;

                } else if (at) {
                        PatternElementType t;
                        uint64_t bit;

                        t = pattern_element_type_from_char(*e);
                        if (t < 0)
                                return log_debug_errno(t, "Unknown pattern field marker '@%c'.", *e);

                        bit = UINT64_C(1) << t;
                        if (mask_found & bit)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Pattern field marker '@%c' appears twice in pattern.", *e);

                        /* We insist that two pattern field markers are separated by some literal string that
                         * we can use to separate the fields when parsing. */
                        if (!last_literal)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Found two pattern field markers without separating literal.");

                        if (ret) {
                                PatternElement *z;

                                z = malloc(offsetof(PatternElement, literal));
                                if (!z)
                                        return -ENOMEM;

                                z->type = t;
                                LIST_INSERT_AFTER(elements, first, last, z);
                                last = z;
                        }

                        mask_found |= bit;
                        last_literal = at = false;
                        continue;
                }

                if (!valid_char(*e))
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(EBADRQC),
                                        "Invalid character 0x%0x in pattern, refusing.",
                                        (unsigned) *e);

                last_literal = true;

                if (!ret)
                        continue;

                if (!last || last->type != PATTERN_LITERAL) {
                        PatternElement *z;

                        z = malloc0(offsetof(PatternElement, literal) + l + 1); /* l is an upper bound to all literal elements */
                        if (!z)
                                return -ENOMEM;

                        z->type = PATTERN_LITERAL;
                        k = 0;

                        LIST_INSERT_AFTER(elements, first, last, z);
                        last = z;
                }

                assert(last);
                assert(last->type == PATTERN_LITERAL);

                last->literal[k++] = *e;
        }

        if (at)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Trailing @ character found, refusing.");
        if (!(mask_found & (UINT64_C(1) << PATTERN_VERSION)))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Version field marker '@v' not specified in pattern, refusing.");

        if (ret)
                *ret = TAKE_PTR(first);

        return 0;
}

int pattern_match(const char *pattern, const char *s, InstanceMetadata *ret) {
        _cleanup_(instance_metadata_destroy) InstanceMetadata found = INSTANCE_METADATA_NULL;
        _cleanup_(pattern_element_free_allp) PatternElement *elements = NULL;
        const char *p;
        int r;

        assert(pattern);
        assert(s);

        r = pattern_split(pattern, &elements);
        if (r < 0)
                return r;

        p = s;
        LIST_FOREACH(elements, e, elements) {
                _cleanup_free_ char *t = NULL;
                const char *n;

                if (e->type == PATTERN_LITERAL) {
                        const char *k;

                        /* Skip literal fields */
                        k = startswith(p, e->literal);
                        if (!k)
                                goto nope;

                        p = k;
                        continue;
                }

                if (e->elements_next) {
                        /* The next element must be literal, as we use it to determine where to split */
                        assert(e->elements_next->type == PATTERN_LITERAL);

                        n = strstr(p, e->elements_next->literal);
                        if (!n)
                                goto nope;

                } else
                        /* End of the string */
                        assert_se(n = strchr(p, 0));
                t = strndup(p, n - p);
                if (!t)
                        return -ENOMEM;

                switch (e->type) {

                case PATTERN_VERSION:
                        if (!version_is_valid(t)) {
                                log_debug("Version string is not valid, refusing: %s", t);
                                goto nope;
                        }

                        assert(!found.version);
                        found.version = TAKE_PTR(t);
                        break;

                case PATTERN_PARTITION_UUID: {
                        sd_id128_t id;

                        if (sd_id128_from_string(t, &id) < 0)
                                goto nope;

                        assert(!found.partition_uuid_set);
                        found.partition_uuid = id;
                        found.partition_uuid_set = true;
                        break;
                }

                case PATTERN_PARTITION_FLAGS: {
                        uint64_t f;

                        if (safe_atoux64(t, &f) < 0)
                                goto nope;

                        if (found.partition_flags_set && found.partition_flags != f)
                                goto nope;

                        assert(!found.partition_flags_set);
                        found.partition_flags = f;
                        found.partition_flags_set = true;
                        break;
                }

                case PATTERN_MTIME: {
                        uint64_t v;

                        if (safe_atou64(t, &v) < 0)
                                goto nope;
                        if (v == USEC_INFINITY) /* Don't permit our internal special infinity value */
                                goto nope;
                        if (v / 1000000U > TIME_T_MAX) /* Make sure this fits in a timespec structure */
                                goto nope;

                        assert(found.mtime == USEC_INFINITY);
                        found.mtime = v;
                        break;
                }

                case PATTERN_MODE: {
                        mode_t m;

                        r = parse_mode(t, &m);
                        if (r < 0)
                                goto nope;
                        if (m & ~0775) /* Don't allow world-writable files or suid files to be generated this way */
                                goto nope;

                        assert(found.mode == MODE_INVALID);
                        found.mode = m;
                        break;
                }

                case PATTERN_SIZE: {
                        uint64_t u;

                        r = safe_atou64(t, &u);
                        if (r < 0)
                                goto nope;
                        if (u == UINT64_MAX)
                                goto nope;

                        assert(found.size == UINT64_MAX);
                        found.size = u;
                        break;
                }

                case PATTERN_TRIES_DONE: {
                        uint64_t u;

                        r = safe_atou64(t, &u);
                        if (r < 0)
                                goto nope;
                        if (u == UINT64_MAX)
                                goto nope;

                        assert(found.tries_done == UINT64_MAX);
                        found.tries_done = u;
                        break;
                }

                case PATTERN_TRIES_LEFT: {
                        uint64_t u;

                        r = safe_atou64(t, &u);
                        if (r < 0)
                                goto nope;
                        if (u == UINT64_MAX)
                                goto nope;

                        assert(found.tries_left == UINT64_MAX);
                        found.tries_left = u;
                        break;
                }

                case PATTERN_NO_AUTO:
                        r = parse_boolean(t);
                        if (r < 0)
                                goto nope;

                        assert(found.no_auto < 0);
                        found.no_auto = r;
                        break;

                case PATTERN_READ_ONLY:
                        r = parse_boolean(t);
                        if (r < 0)
                                goto nope;

                        assert(found.read_only < 0);
                        found.read_only = r;
                        break;

                case PATTERN_GROWFS:
                        r = parse_boolean(t);
                        if (r < 0)
                                goto nope;

                        assert(found.growfs < 0);
                        found.growfs = r;
                        break;

                case PATTERN_SHA256SUM: {
                        _cleanup_free_ void *d = NULL;
                        size_t l;

                        if (strlen(t) != sizeof(found.sha256sum) * 2)
                                goto nope;

                        r = unhexmem(t, sizeof(found.sha256sum) * 2, &d, &l);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                goto nope;

                        assert(!found.sha256sum_set);
                        assert(l == sizeof(found.sha256sum));
                        memcpy(found.sha256sum, d, l);
                        found.sha256sum_set = true;
                        break;
                }

                default:
                        assert_se("unexpected pattern element");
                }

                p = n;
        }

        if (ret) {
                *ret = found;
                found = (InstanceMetadata) INSTANCE_METADATA_NULL;
        }

        return true;

nope:
        if (ret)
                *ret = (InstanceMetadata) INSTANCE_METADATA_NULL;

        return false;
}

int pattern_match_many(char **patterns, const char *s, InstanceMetadata *ret) {
        _cleanup_(instance_metadata_destroy) InstanceMetadata found = INSTANCE_METADATA_NULL;
        int r;

        STRV_FOREACH(p, patterns) {
                r = pattern_match(*p, s, &found);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (ret) {
                                *ret = found;
                                found = (InstanceMetadata) INSTANCE_METADATA_NULL;
                        }

                        return true;
                }
        }

        if (ret)
                *ret = (InstanceMetadata) INSTANCE_METADATA_NULL;

        return false;
}

int pattern_valid(const char *pattern) {
        int r;

        r = pattern_split(pattern, NULL);
        if (r == -EINVAL)
                return false;
        if (r < 0)
                return r;

        return true;
}

int pattern_format(
                const char *pattern,
                const InstanceMetadata *fields,
                char **ret) {

        _cleanup_(pattern_element_free_allp) PatternElement *elements = NULL;
        _cleanup_free_ char *j = NULL;
        int r;

        assert(pattern);
        assert(fields);
        assert(ret);

        r = pattern_split(pattern, &elements);
        if (r < 0)
                return r;

        LIST_FOREACH(elements, e, elements) {

                switch (e->type) {

                case PATTERN_LITERAL:
                        if (!strextend(&j, e->literal))
                                return -ENOMEM;

                        break;

                case PATTERN_VERSION:
                        if (!fields->version)
                                return -ENXIO;

                        if (!strextend(&j, fields->version))
                                return -ENOMEM;
                        break;

                case PATTERN_PARTITION_UUID: {
                        char formatted[SD_ID128_STRING_MAX];

                        if (!fields->partition_uuid_set)
                                return -ENXIO;

                        if (!strextend(&j, sd_id128_to_string(fields->partition_uuid, formatted)))
                                return -ENOMEM;

                        break;
                }

                case PATTERN_PARTITION_FLAGS:
                        if (!fields->partition_flags_set)
                                return -ENXIO;

                        r = strextendf(&j, "%" PRIx64, fields->partition_flags);
                        if (r < 0)
                                return r;

                        break;

                case PATTERN_MTIME:
                        if (fields->mtime == USEC_INFINITY)
                                return -ENXIO;

                        r = strextendf(&j, "%" PRIu64, fields->mtime);
                        if (r < 0)
                                return r;

                        break;

                case PATTERN_MODE:
                        if (fields->mode == MODE_INVALID)
                                return -ENXIO;

                        r = strextendf(&j, "%03o", fields->mode);
                        if (r < 0)
                                return r;

                        break;

                case PATTERN_SIZE:
                        if (fields->size == UINT64_MAX)
                                return -ENXIO;

                        r = strextendf(&j, "%" PRIu64, fields->size);
                        if (r < 0)
                                return r;
                        break;

                case PATTERN_TRIES_DONE:
                        if (fields->tries_done == UINT64_MAX)
                                return -ENXIO;

                        r = strextendf(&j, "%" PRIu64, fields->tries_done);
                        if (r < 0)
                                return r;
                        break;

                case PATTERN_TRIES_LEFT:
                        if (fields->tries_left == UINT64_MAX)
                                return -ENXIO;

                        r = strextendf(&j, "%" PRIu64, fields->tries_left);
                        if (r < 0)
                                return r;
                        break;

                case PATTERN_NO_AUTO:
                        if (fields->no_auto < 0)
                                return -ENXIO;

                        if (!strextend(&j, one_zero(fields->no_auto)))
                                return -ENOMEM;

                        break;

                case PATTERN_READ_ONLY:
                        if (fields->read_only < 0)
                                return -ENXIO;

                        if (!strextend(&j, one_zero(fields->read_only)))
                                return -ENOMEM;

                        break;

                case PATTERN_GROWFS:
                        if (fields->growfs < 0)
                                return -ENXIO;

                        if (!strextend(&j, one_zero(fields->growfs)))
                                return -ENOMEM;

                        break;

                case PATTERN_SHA256SUM: {
                        _cleanup_free_ char *h = NULL;

                        if (!fields->sha256sum_set)
                                return -ENXIO;

                        h = hexmem(fields->sha256sum, sizeof(fields->sha256sum));
                        if (!h)
                                return -ENOMEM;

                        if (!strextend(&j, h))
                                return -ENOMEM;

                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        *ret = TAKE_PTR(j);
        return 0;
}
