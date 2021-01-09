/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "in-addr-util.h"
#include "ether-addr-util.h"
#include "network-cloud-util.h"
#include "parse-util.h"

int network_cloud_manager_new(CloudProvider provider, NetworkCloudManager **ret) {
        _cleanup_(network_cloud_manager_freep) NetworkCloudManager *m = NULL;

        m = new(NetworkCloudManager, 1);
        if (!m)
                return -ENOMEM;

        *m = (NetworkCloudManager) {
                .provider = provider,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

void *network_cloud_manager_free(NetworkCloudManager *m) {
        NetworkCloudMetaData *i;

        if (!m)
                return NULL;

        ORDERED_HASHMAP_FOREACH(i, m->interfaces_by_mac) {
                if (m->provider == CLOUD_PROVIDER_AZURE)
                        ordered_hashmap_free_free(i->ipv4);

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

int format_cloud_to_ether(const char *s, char **ea) {
        const char *m;
        char *p, *l;
        size_t i;

        assert(s);

        p = malloc0(strlen(s) + ETHER_ADDR_TO_STRING_MAX);
        if (!p)
                return -ENOMEM;

        for (i = 0, l = p, m = s; i < strlen(s); i++) {
                strncpy(l, m, 2);
                l += 2;

                if (m != s + strlen(s) - 2)
                        *l++ = ':';
                m += 2;
        }

        *ea = TAKE_PTR(p);
        return 0;
}

size_t network_cloud_meta_data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        NetworkCloudManager *m = userdata;
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

        return sz;
}
