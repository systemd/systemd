/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "hashmap.h"
#include "log.h"
#include "machine-tags.h"
#include "string-util.h"
#include "strv.h"

bool machine_tag_is_valid(const char *s) {
        size_t n = strlen_ptr(s);
        if (n <= 0 || n >= 256)
                return false;

        /* Don't allow "-" and "." as first char. (This is load-bearing, we want that "+"/"-" can be used as
         * prefix for adding/removing tags from the list). */
        if (strchr("-.=", s[0]))
                return false;

        /* We allow parameterization of tags, with a "=" as separator */
        const char *eq = strchr(s, '=');
        if (eq) {
                assert(eq > s);

                /* If there is an '=', then make the same restrictions as for the first char on the last char before it */
                if (strchr("-.", eq[-1]))
                        return false;
        } else {
                /* If there's no '=', then make the restriction on the very last character */
                if (strchr("-.", s[n-1]))
                        return false;
        }

        return in_charset(s, ALPHANUMERICAL "-.=");
}

static int machine_tag_key(const char *tag, char **ret) {
        assert(tag);
        assert(ret);

        /* Returns the key of a machine tag, i.e. everything up to and including the first '=', or the whole
         * tag if it has no '='. When those keys are used in a Hashmap, this allows a bare tag and an
         * assignment to coexist. */

        const char *eq = strchrnul(tag, '=');
        char *k = strndup(tag, (eq - tag) + (*eq == '='));
        if (!k)
                return -ENOMEM;

        *ret = k;
        return 0;
}

int machine_tag_list_is_valid(char **l) {
        int r;

        r = machine_tags_from_strv(l, /* graceful= */ false, /* ret= */ NULL);
        switch (r) {
        case -EINVAL:
        case -E2BIG:
                return false;
        case 0:
                return true;
        default:
                return r;
        }
}

int machine_tags_from_string(const char *s, bool graceful, char ***ret) {
        assert(ret);

        /* Parse the colon-separated TAGS= machine-info field into a sorted, deduplicated strv. */

        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_strv_free_ char **l = strv_split(s, ":");
        if (!l)
                return -ENOMEM;

        return machine_tags_from_strv(l, graceful, ret);
}

int machine_tags_from_strv(char **l, bool graceful, char ***ret) {
        int r;

        /* Go through a list of tags and verify each tag. If 'graceful' is true invalid tags are silently
         * dropped, otherwise an invalid tag makes us fail with -EINVAL. If the same tag or key is specified
         * more than once, the one specified last wins if 'graceful' is true, otherwise this makes us fail
         * with -EINVAL, too. At most MACHINE_TAGS_MAX valid tags are accepted. The result is sorted only
         * after deduplication, and is NULL if no (valid) tags remain. */

        /* Maps the key of each tag to the tag itself (borrowed from 'l'). */
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        STRV_FOREACH(i, l) {
                if (!machine_tag_is_valid(*i)) {
                        if (graceful)
                                continue;

                        return -EINVAL;
                }

                if (hashmap_size(h) >= MACHINE_TAGS_MAX)
                        return -E2BIG;

                _cleanup_free_ char *k = NULL;
                r = machine_tag_key(*i, &k);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&h, &string_hash_ops_free, k, *i);
                if (IN_SET(r, 0, -EEXIST)) {  /* same key and value or same key but different value */
                        if (!graceful)
                                return -EINVAL;

                        if (r == -EEXIST)
                                /* not the same value pointer, update to the later value */
                                assert_se(hashmap_update(h, k, *i) >= 0);
                        continue;
                }
                if (r < 0)
                        return r;
                TAKE_PTR(k);
        }

        if (ret) {
                _cleanup_strv_free_ char **cleaned = NULL;
                char *v;
                HASHMAP_FOREACH(v, h) {
                        r = strv_extend(&cleaned, v);
                        if (r < 0)
                                return r;
                }

                strv_sort(cleaned);
                *ret = TAKE_PTR(cleaned);
        }

        return 0;
}

/* The accumulated tag list is kept in a Hashmap that maps the key of each tag (see machine_tag_key()) to the
 * tag itself, so that adding a tag replaces any tag with the same key. Both keys and values are owned by the
 * hashmap. */

static int tags_add(Hashmap **h, const char *tag) {
        int r;

        assert(h);
        assert(tag);

        _cleanup_free_ char *k = NULL;
        r = machine_tag_key(tag, &k);
        if (r < 0)
                return r;

        _cleanup_free_ char *v = strdup(tag);
        if (!v)
                return -ENOMEM;

        /* Drop any previous tag with the same key first, as hashmap_replace() would leak the old entry. */
        _cleanup_free_ char *old_k = NULL, *old_v = NULL;
        old_v = hashmap_remove2(*h, k, (void**) &old_k);

        r = hashmap_ensure_put(h, &string_hash_ops_free_free, k, v);
        if (r < 0)
                return r;

        TAKE_PTR(k);
        TAKE_PTR(v);
        return 0;
}

static void tags_remove_matching(Hashmap *h, const char *pattern) {
        char *v, *k;

        assert(pattern);

        /* Removes all tags matching the specified glob pattern. Removing the current entry while iterating
         * is explicitly allowed by the Hashmap API. */

        HASHMAP_FOREACH_KEY(v, k, h)
                if (fnmatch(pattern, v, /* flags= */ 0) == 0) {
                        assert_se(hashmap_remove(h, k) == v);
                        free(k);
                        free(v);
                }
}

static int apply_conf_file(ConfFile *c, Hashmap **h) {
        int r;

        assert(c);
        assert(h);

        _cleanup_fclose_ FILE *f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f)
                return log_error_errno(errno, "Failed to open %s: %m", c->original_path);

        log_debug("Applying %s", c->original_path);

        for (unsigned line = 1;; line++) {
                _cleanup_free_ char *l = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", c->original_path);
                if (r == 0)
                        break;

                if (isempty(l) || strchr(COMMENTS, l[0]))
                        continue;

                for (const char *p = l;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(NULL, LOG_WARNING, c->original_path, line, r,
                                           "Failed to parse line, ignoring: %m");
                                break;
                        }
                        if (r == 0)
                                break;

                        const char *e = word;
                        if (e[0] == '-') {
                                /* A removal, with an optional glob pattern. Non-glob patterns must be valid tags. */
                                e++;

                                if (isempty(e) || (!string_is_glob(e) && !machine_tag_is_valid(e))) {
                                        log_syntax(NULL, LOG_WARNING, c->original_path, line, SYNTHETIC_ERRNO(EINVAL),
                                                   "Invalid machine tag pattern '%s', ignoring.", word);
                                        continue;
                                }

                                tags_remove_matching(*h, e);
                                continue;
                        }

                        /* An addition, with an optional '+' prefix for symmetry with "hostnamectl tags" */
                        if (e[0] == '+')
                                e++;

                        if (!machine_tag_is_valid(e)) {
                                log_syntax(NULL, LOG_WARNING, c->original_path, line, SYNTHETIC_ERRNO(EINVAL),
                                           "Invalid machine tag '%s', ignoring.", word);
                                continue;
                        }

                        r = tags_add(h, e);
                        if (r < 0)
                                return log_oom();
                }
        }

        return 0;
}

int machine_tags_apply_config(const char *root, char * const *base, char ***ret) {
        int r;

        assert(ret);

        /* Reads the .tags files from the tags.d/ directories below 'root' (or "/" if NULL), and applies the
         * additions and removals they declare, in the order the files are sorted in, on top of the 'base' tag
         * list. Returns the resulting list, sorted, or NULL if it is empty. */

        _cleanup_hashmap_free_ Hashmap *h = NULL;
        STRV_FOREACH(i, base) {
                r = tags_add(&h, *i);
                if (r < 0)
                        return log_oom();
        }

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = conf_files_list_strv_full(
                        ".tags",
                        root,
                        CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
                        (const char* const*) CONF_PATHS_STRV("tags.d"),
                        &files, &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate tags.d/ files: %m");

        FOREACH_ARRAY(c, files, n_files) {
                r = apply_conf_file(*c, &h);
                if (r < 0)
                        return r;
        }

        if (hashmap_size(h) > MACHINE_TAGS_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "Too many machine tags configured (%u > %u).",
                                       hashmap_size(h), MACHINE_TAGS_MAX);

        _cleanup_strv_free_ char **l = NULL;
        char *v;
        HASHMAP_FOREACH(v, h) {
                r = strv_extend(&l, v);
                if (r < 0)
                        return log_oom();
        }

        strv_sort(l);
        *ret = TAKE_PTR(l);
        return 0;
}
