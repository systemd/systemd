/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmspawn-mount.h"
#include "alloc-util.h"
#include "extract-word.h"
#include "macro.h"
#include "parse-argument.h"
#include "path-util.h"
#include "string-util.h"

static void runtime_mount_done(RuntimeMount *mount) {
        assert(mount);

        mount->source = mfree(mount->source);
        mount->target = mfree(mount->target);
}

void runtime_mount_context_done(RuntimeMountContext *ctx) {
        assert(ctx);

        FOREACH_ARRAY(mount, ctx->mounts, ctx->n_mounts)
                runtime_mount_done(mount);

        free(ctx->mounts);
}

int runtime_mount_parse(RuntimeMountContext *ctx, const char *s, bool read_only) {
        _cleanup_(runtime_mount_done) RuntimeMount mount = { .read_only = read_only };
        _cleanup_free_ char *source_rel = NULL;
        int r;

        assert(ctx);

        r = extract_first_word(&s, &source_rel, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        if (isempty(source_rel))
                return -EINVAL;

        r = path_make_absolute_cwd(source_rel, &mount.source);
        if (r < 0)
                return r;

        /* virtiofsd only supports directories */
        if (!is_dir(mount.source, /* follow= */ true))
                return -ENOTDIR;

        mount.target = s ? strdup(s) : TAKE_PTR(source_rel);
        if (!mount.target)
                return -ENOMEM;

        if (!path_is_absolute(mount.target))
                return -EINVAL;

        if (!GREEDY_REALLOC(ctx->mounts, ctx->n_mounts + 1))
                return log_oom();

        ctx->mounts[ctx->n_mounts++] = TAKE_STRUCT(mount);

        return 0;
}
