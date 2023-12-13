/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmspawn-mount.h"
#include "alloc-util.h"
#include "extract-word.h"
#include "macro.h"
#include "parse-argument.h"
#include "path-util.h"
#include "string-util.h"

void runtime_mount_free_all(RuntimeMount *mounts, size_t n) {
        assert(mounts || n == 0);

        FOREACH_ARRAY(m, mounts, n) {
                free(m->source);
                free(m->target);
        }

        free(mounts);
}

int runtime_mount_parse(RuntimeMount **mounts, size_t *n_mounts, const char *s, bool read_only) {
        _cleanup_free_ char *source = NULL, *target = NULL, *source_rel = NULL;
        int r;

        assert(mounts);
        assert(n_mounts);

        r = extract_first_word(&s, &source_rel, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (isempty(source_rel))
                return -EINVAL;

        r = path_make_absolute_cwd(source_rel, &source);
        if (r < 0)
                return r;

        /* virtiofsd only supports directories */
        if (!is_dir(source, /* follow= */ true))
                return -ENOTDIR;

        target = s ? strdup(s) : TAKE_PTR(source_rel);
        if (!target)
                return -ENOMEM;

        if (!path_is_absolute(target))
                return -EINVAL;

        if (!GREEDY_REALLOC(*mounts, *n_mounts + 1))
                return -ENOMEM;

        (*mounts)[(*n_mounts)++] = (RuntimeMount) {
                .source = TAKE_PTR(source),
                .target = TAKE_PTR(target),
                .read_only = read_only,
        };

        return 0;
}
