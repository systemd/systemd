/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LIBCURL
#include <curl/curl.h>
#endif

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "hashmap.h"

typedef enum CloudProvider {
        CLOUD_PROVIDER_AZURE,
        CLOUD_PROVIDER_GCP,
        CLOUD_PROVIDER_EC2,
} CloudProvider;

typedef struct NetworkCloudMetaData {
        struct ether_addr mac;

        OrderedHashmap *ipv4;
} NetworkCloudMetaData;

typedef struct NetworkCloudManager {
        CloudProvider provider;

        char *payload;
        size_t payload_size;
        size_t payload_allocated;

        OrderedHashmap *interfaces_by_mac;
} NetworkCloudManager;

int network_cloud_manager_new(CloudProvider provider, NetworkCloudManager **ret);
void *network_cloud_manager_free(NetworkCloudManager *m);
size_t network_cloud_meta_data_write_callback(void *contents, size_t size, size_t nmemb, void *userdata);

DEFINE_TRIVIAL_CLEANUP_FUNC(NetworkCloudManager *, network_cloud_manager_free);

int network_cloud_metadata_new(NetworkCloudMetaData **ret);

int format_cloud_to_ether(const char *s, char **ea);

#if HAVE_LIBCURL
DEFINE_TRIVIAL_CLEANUP_FUNC(CURL*, curl_easy_cleanup);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct curl_slist*, curl_slist_free_all);
#endif
