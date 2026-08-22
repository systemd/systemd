/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-object.h"
#include "dns-domain.h"
#include "random-util.h"
#include "resolved-bus.h"
#include "resolved-dns-browse-services-bus.h"
#include "resolved-dns-browse-services.h"
#include "resolved-dns-query.h"
#include "resolved-manager.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

#define BROWSER_PATH_PREFIX "/org/freedesktop/resolve1/browser"
#define BROWSER_INTERFACE "org.freedesktop.resolve1.DnssdServiceBrowser"

static int browser_on_bus_track(sd_bus_track *track, void *userdata) {
        DnsServiceBrowser *sb = ASSERT_PTR(userdata);

        assert(track);
        dns_service_browser_stop(sb);
        return 0;
}

static int browser_send_updates(DnsServiceBrowser *sb, DnsServiceBrowserUpdate *updates) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *signal = NULL;
        int r;

        assert(sb);

        r = sd_bus_message_new_signal_to(sb->manager->bus, &signal, sb->bus_owner, sb->bus_path,
                                         BROWSER_INTERFACE, "ServicesChanged");
        if (r < 0)
                return r;
        r = sd_bus_message_open_container(signal, 'a', "(sisssi)");
        if (r < 0)
                return r;
        LIST_FOREACH(updates, u, updates) {
                r = sd_bus_message_append(signal, "(sisssi)", u->update, u->family, u->name, u->type,
                                          u->domain, u->ifindex);
                if (r < 0)
                        return r;
        }
        r = sd_bus_message_close_container(signal);
        if (r < 0)
                return r;
        return sd_bus_send(sb->manager->bus, signal, NULL);
}

static DnsServiceBrowser* browser_find_by_path(Manager *m, const char *path) {
        return hashmap_get(m->dns_service_browsers_by_path, path);
}

static DnsServiceBrowser* browser_find_by_owner(Manager *m, const char *owner) {
        DnsServiceBrowser *sb;

        assert(m);
        assert(owner);

        SET_FOREACH(sb, m->dns_service_browsers)
                if (streq_ptr(sb->bus_owner, owner))
                        return sb;

        return NULL;
}

static int browser_method_stop(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        DnsServiceBrowser *sb = ASSERT_PTR(userdata);

        assert(message);

        if (!streq_ptr(sd_bus_message_get_sender(message), sb->bus_owner))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only the browser owner may stop it.");

        dns_service_browser_stop(sb);
        return sd_bus_reply_method_return(message, NULL);
}

static int browser_object_find(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **found,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        DnsServiceBrowser *sb;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        sb = browser_find_by_path(m, path);
        if (!sb)
                return 0;
        *found = sb;
        return 1;
}

static int browser_node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **list = NULL;
        Manager *m = ASSERT_PTR(userdata);
        DnsServiceBrowser *sb;
        size_t n = 0;

        assert(bus);
        assert(path);
        assert(nodes);

        list = new0(char*, hashmap_size(m->dns_service_browsers_by_path) + 1);
        if (!list)
                return -ENOMEM;
        HASHMAP_FOREACH(sb, m->dns_service_browsers_by_path) {
                list[n] = strdup(sb->bus_path);
                if (!list[n])
                        return -ENOMEM;
                n++;
        }
        *nodes = TAKE_PTR(list);
        return 1;
}

static const sd_bus_vtable browser_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Stop", NULL, NULL, browser_method_stop, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL_WITH_ARGS("ServicesChanged", SD_BUS_ARGS("a(sisssi)", updates), 0),
        SD_BUS_VTABLE_END,
};

const BusObjectImplementation dns_service_browser_object = {
        BROWSER_PATH_PREFIX,
        BROWSER_INTERFACE,
        .fallback_vtables = BUS_FALLBACK_VTABLES({browser_vtable, browser_object_find}),
        .node_enumerator = browser_node_enumerator,
};

int bus_method_browse_services(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(dns_service_browser_unrefp) DnsServiceBrowser *sb = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *domain, *invalid_parameter, *type, *sender;
        uint64_t flags, token;
        int ifindex, r;

        bus_client_log(message, "service browsing");

        r = sd_bus_message_read(message, "ssit", &domain, &type, &ifindex, &flags);
        if (r < 0)
                return r;
        r = dns_service_browser_validate_request(domain, type, ifindex, &invalid_parameter);
        if (r == -EINVAL)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid browse parameter '%s'.", invalid_parameter);
        if (r < 0)
                return r;
        if (validate_and_mangle_query_flags(m, &flags, /* name= */ NULL, /* ok= */ 0) < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid query flags.");

        sender = sd_bus_message_get_sender(message);
        if (!sender)
                return -ENXIO;
        if (browser_find_by_owner(m, sender))
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED,
                                        "Only one service browser per client is permitted.");
        r = dns_service_browser_new(m, domain, type, ifindex, flags, browser_send_updates, &sb);
        if (r == -EBUSY)
                return sd_bus_error_set(error, SD_BUS_ERROR_LIMITS_EXCEEDED,
                                        "Too many service browsers are active.");
        if (r < 0)
                return r;

        sb->bus_owner = strdup(sender);
        if (!sb->bus_owner)
                return -ENOMEM;
        do {
                sb->bus_path = mfree(sb->bus_path);
                token = random_u64();
                if (asprintf(&sb->bus_path, BROWSER_PATH_PREFIX "/%" PRIu64, token) < 0)
                        return -ENOMEM;
        } while (browser_find_by_path(m, sb->bus_path));

        r = hashmap_ensure_put(&m->dns_service_browsers_by_path, &string_hash_ops, sb->bus_path, sb);
        if (r < 0)
                return r;

        r = sd_bus_track_new(sd_bus_message_get_bus(message), &sb->bus_track, browser_on_bus_track, sb);
        if (r < 0)
                return r;
        r = sd_bus_track_add_sender(sb->bus_track, message);
        if (r < 0)
                return r;
        r = sd_bus_reply_method_return(message, "ot", sb->bus_path, flags);
        if (r < 0)
                return r;

        TAKE_PTR(sb);
        return 1;
}
