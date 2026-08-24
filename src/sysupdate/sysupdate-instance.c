/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "compress.h"
#include "log.h"
#include "sysupdate-instance.h"
#include "sysupdate-resource.h"

void instance_metadata_destroy(InstanceMetadata *m) {
        assert(m);
        free(m->version);
}

int instance_get_expected_size(const Instance *i, uint64_t *ret_size, uint64_t *ret_allocated) {
        struct stat st;
        bool compressed;

        assert(i);
        assert(i->resource);
        assert(i->path);
        assert(ret_size);
        assert(ret_allocated);

        *ret_size = i->metadata.size;
        *ret_allocated = UINT64_MAX;

        if (RESOURCE_IS_URL(i->resource->type) ||
            i->resource->type == RESOURCE_TAR)
                return 0;

        compressed = compression_from_filename(i->path) != COMPRESSION_NONE;
        if (compressed && *ret_size == UINT64_MAX)
                return 0;

        if (stat(i->path, &st) < 0) {
                if (*ret_size == UINT64_MAX)
                        log_debug_errno(
                                        errno,
                                        "Failed to stat local source '%s', size unknown: %m",
                                        i->path);
                return 0;
        }

        if (!S_ISREG(st.st_mode))
                return 0;

        if (*ret_size == UINT64_MAX)
                *ret_size = (uint64_t) st.st_size;

        /* A local, uncompressed regular-file source can retain its sparse allocation pattern when written
         * to a sparse target. */
        if (!compressed && !MUL_SAFE(ret_allocated, (uint64_t) st.st_blocks, UINT64_C(512)))
                *ret_allocated = UINT64_MAX;

        return 0;
}

int instance_new(
                Resource *rr,
                const char *path,
                const InstanceMetadata *f,
                Instance **ret) {

        _cleanup_(instance_freep) Instance *i = NULL;
        _cleanup_free_ char *p = NULL, *v = NULL;

        assert(rr);
        assert(path);
        assert(f);
        assert(f->version);
        assert(ret);

        p = strdup(path);
        if (!p)
                return log_oom();

        v = strdup(f->version);
        if (!v)
                return log_oom();

        i = new(Instance, 1);
        if (!i)
                return log_oom();

        *i = (Instance) {
                .resource = rr,
                .metadata = *f,
                .path = TAKE_PTR(p),
                .partition_info = PARTITION_INFO_NULL,
        };

        i->metadata.version = TAKE_PTR(v);

        *ret = TAKE_PTR(i);
        return 0;
}

Instance *instance_free(Instance *i) {
        if (!i)
                return NULL;

        instance_metadata_destroy(&i->metadata);

        free(i->path);
        partition_info_destroy(&i->partition_info);

        return mfree(i);
}
