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

void instance_get_expected_size(const Instance *i, uint64_t *ret_size) {
        struct stat st;
        uint64_t size;

        assert(i);
        assert(i->resource);
        assert(i->path);
        assert(ret_size);

        size = i->metadata.size;
        *ret_size = size;

        if (size != UINT64_MAX)
                return;

        if (RESOURCE_IS_URL(i->resource->type) ||
            i->resource->type == RESOURCE_TAR)
                return;

        if (compression_from_filename(i->path) != COMPRESSION_NONE)
                return;

        if (stat(i->path, &st) < 0) {
                log_debug_errno(errno, "Failed to stat local source '%s', size unknown: %m", i->path);
                return;
        }

        if (!S_ISREG(st.st_mode))
                return;

        *ret_size = (uint64_t) st.st_size;
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
