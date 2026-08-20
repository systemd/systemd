/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "tests.h"

static DnssdRegisteredService* add_service(Manager *manager, const char *id, ResolveConfigSource source) {
        DnssdRegisteredService *service;

        service = new0(DnssdRegisteredService, 1);
        ASSERT_NOT_NULL(service);

        service->id = strdup(id);
        ASSERT_NOT_NULL(service->id);
        service->manager = manager;
        service->config_source = source;

        ASSERT_OK(hashmap_ensure_put(&manager->dnssd_registered_services, &string_hash_ops, service->id, service));

        return service;
}

TEST(clear_on_reload) {
        Manager manager = {};
        DnssdRegisteredService *dynamic;

        add_service(&manager, "static-one", RESOLVE_CONFIG_SOURCE_FILE);
        dynamic = add_service(&manager, "dynamic-one", RESOLVE_CONFIG_SOURCE_DBUS);

        dnssd_registered_service_clear_on_reload(manager.dnssd_registered_services);

        ASSERT_EQ(hashmap_size(manager.dnssd_registered_services), 1u);
        ASSERT_TRUE(hashmap_get(manager.dnssd_registered_services, "dynamic-one") == dynamic);

        dnssd_registered_service_remove(dynamic, /* send_goodbye= */ false);
        ASSERT_TRUE(hashmap_isempty(manager.dnssd_registered_services));
        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

TEST(remove_without_goodbye) {
        Manager manager = {};
        DnssdRegisteredService *service;

        service = add_service(&manager, "shutdown", RESOLVE_CONFIG_SOURCE_DBUS);
        ASSERT_NULL(dnssd_registered_service_remove(service, /* send_goodbye= */ false));
        ASSERT_TRUE(hashmap_isempty(manager.dnssd_registered_services));

        manager.dnssd_registered_services = hashmap_free(manager.dnssd_registered_services);
}

TEST(free_unpublished) {
        _cleanup_(dnssd_registered_service_freep) DnssdRegisteredService *service = NULL;
        Manager manager = {};

        service = new0(DnssdRegisteredService, 1);
        ASSERT_NOT_NULL(service);
        service->id = strdup("unpublished");
        ASSERT_NOT_NULL(service->id);
        service->manager = &manager;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
