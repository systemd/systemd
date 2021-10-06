/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "sysupdate-instance.h"

void instance_metadata_destroy(InstanceMetadata *m) {
        assert(m);
        free(m->version);
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
