/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "in-addr-util.h"
#include "ether-addr-util.h"
#include "network-cloud-azure.h"
#include "network-cloud-util.h"
#include "parse-util.h"

int network_cloud_provider_new(CloudProvider provider, NetworkCloudProvider **ret) {
        _cleanup_(network_cloud_provider_freep) NetworkCloudProvider *m = NULL;

        m = new(NetworkCloudProvider, 1);
        if (!m)
                return -ENOMEM;

        *m = (NetworkCloudProvider) {
                .provider = provider,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

void *network_cloud_provider_free(NetworkCloudProvider *m) {
        NetworkCloudMetaData *i;

        if (!m)
                return NULL;

        ORDERED_HASHMAP_FOREACH(i, m->interfaces_by_mac) {
                if (m->provider == CLOUD_PROVIDER_AZURE)
                        ordered_hashmap_free_with_destructor(i->ipv4, azure_cloud_metadata_free);

                free(i);
        }

        ordered_hashmap_free(m->interfaces_by_mac);
        return mfree(m);
}

int network_cloud_metadata_new(NetworkCloudMetaData **ret) {
        _cleanup_free_ NetworkCloudMetaData *m = NULL;

        m = new0(NetworkCloudMetaData, 1);
        if (!m)
                return -ENOMEM;

        *ret = TAKE_PTR(m);
        return 0;
}

size_t network_cloud_meta_data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        NetworkCloudProvider *m = userdata;
        size_t sz = size * nmemb;

        assert(contents);
        assert(m);
        assert(nmemb <= SSIZE_MAX / size);

        if (sz <= 0)
                return 0;

        if (!GREEDY_REALLOC(m->payload, m->payload_allocated, m->payload_size + sz))
                return log_oom();

        memcpy(m->payload + m->payload_size, contents, sz);
        m->payload_size += sz;
        m->payload[m->payload_size] = 0;

        return sz;
}
