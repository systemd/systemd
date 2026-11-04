/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "log.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-hostname.h"
#include "networkd-manager.h"
#include "string-util.h"

static int on_hostname_change(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ char *hostname = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Link *link;

        /* Pollers are woken up when the hostname is changed in any UTS namespace, hence check if ours
         * has actually changed. */
        hostname = gethostname_malloc();
        if (!hostname) {
                log_oom_warning();
                return 0;
        }

        if (streq_ptr(hostname, m->kernel_hostname))
                return 0;

        log_debug("System hostname changed to '%s', updating hostname in DHCP clients.", hostname);

        free_and_replace(m->kernel_hostname, hostname);

        HASHMAP_FOREACH(link, m->links_by_index) {
                (void) dhcp4_update_hostname(link);
                (void) dhcp6_update_hostname(link);
        }

        return 0;
}

int manager_watch_hostname(Manager *m) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(m);

        /* The kernel wakes up pollers of this file when the hostname is changed. */
        fd = xopenat(AT_FDCWD, "/proc/sys/kernel/hostname", O_RDONLY|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                log_warning_errno(fd, "Failed to open /proc/sys/kernel/hostname, ignoring: %m");
                return 0;
        }

        r = sd_event_add_io(m->event, &m->hostname_event_source, fd, /* events= */ 0, on_hostname_change, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add hostname event source: %m");

        r = sd_event_source_set_io_fd_own(m->hostname_event_source, /* own= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to pass ownership of hostname file descriptor to event source: %m");

        TAKE_FD(fd);

        (void) sd_event_source_set_description(m->hostname_event_source, "hostname");

        m->kernel_hostname = gethostname_malloc();
        if (!m->kernel_hostname)
                return log_oom();

        return 0;
}

sd_varlink* hostname_varlink_close(sd_varlink *vl) {
        if (!vl)
                return NULL;

        free(sd_varlink_get_userdata(vl));
        return sd_varlink_flush_close_unref(vl);
}

static int set_hostname_handler(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        Manager *m = ASSERT_PTR(sd_event_get_userdata(sd_varlink_get_event(link)));

        _cleanup_free_ char *hostname = sd_varlink_set_userdata(link, NULL);

        m->hostname_varlink = sd_varlink_close_unref(m->hostname_varlink);

        if (error_id) {
                log_warning_errno(sd_varlink_error_to_errno(error_id, parameters),
                                  "Could not set transient hostname, ignoring: %s", error_id);
                return 0;
        }

        return free_and_replace(m->dynamic_hostname, hostname);
}

int manager_set_hostname(Manager *m, const char *hostname) {
        int r;

        assert(m);

        /* Skip if the requested hostname already matches the in-flight one, or the applied one if idle. */
        const char *effective = m->hostname_varlink ? sd_varlink_get_userdata(m->hostname_varlink) : m->dynamic_hostname;
        if (streq_ptr(hostname, effective)) {
                log_debug("Transient hostname is already set to '%s', skipping.", strna(hostname));
                return 0;
        }

        log_debug("Setting transient hostname: '%s'", strna(hostname));

        _cleanup_free_ char *h = NULL;
        if (hostname) {
                h = strdup(hostname);
                if (!h)
                        return log_oom();
        }

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Hostname");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-hostnamed: %m");

        (void) sd_varlink_set_description(vl, "hostname");

        r = sd_varlink_attach_event(vl, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach hostname Varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(vl, set_hostname_handler);
        if (r < 0)
                return log_error_errno(r, "Failed to bind hostname reply callback: %m");

        r = sd_varlink_invokebo(
                        vl,
                        "io.systemd.Hostname.SetHostname",
                        SD_JSON_BUILD_PAIR_STRING("newValue", hostname));
        if (r < 0)
                return log_error_errno(r, "Failed to set transient hostname: %m");

        sd_varlink_set_userdata(vl, TAKE_PTR(h));

        hostname_varlink_close(m->hostname_varlink);
        m->hostname_varlink = TAKE_PTR(vl);
        return 0;
}

static int get_product_uuid_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        Manager *manager = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        const void *a;
        size_t sz;
        int r;

        assert(m);

        /* To avoid calling GetProductUUID() bus method so frequently, set the flag below
         * even if the method fails. */
        manager->has_product_uuid = true;

        e = sd_bus_message_get_error(m);
        if (e) {
                r = sd_bus_error_get_errno(e);
                log_warning_errno(r, "Could not get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %s",
                                  bus_error_message(e, r));
                return 0;
        }

        r = sd_bus_message_read_array(m, 'y', &a, &sz);
        if (r < 0) {
                log_warning_errno(r, "Failed to get product UUID. Falling back to use machine-app-specific ID as DUID-UUID: %m");
                return 0;
        }

        if (sz != sizeof(sd_id128_t)) {
                log_warning("Invalid product UUID. Falling back to use machine-app-specific ID as DUID-UUID.");
                return 0;
        }

        log_debug("Successfully obtained product UUID");

        memcpy(&manager->duid_product_uuid.raw_data, a, sz);
        manager->duid_product_uuid.raw_data_len = sz;

        return 0;
}

int manager_request_product_uuid(Manager *m) {
        static bool bus_method_is_called = false;
        int r;

        assert(m);

        if (bus_method_is_called)
                return 0;

        if (sd_bus_is_ready(m->bus) <= 0 && !m->product_uuid_requested) {
                log_debug("Not connected to system bus, requesting product UUID later.");
                m->product_uuid_requested = true;
                return 0;
        }

        m->product_uuid_requested = false;

        r = bus_call_method_async(
                        m->bus,
                        /* ret_slot= */ NULL,
                        bus_hostname,
                        "GetProductUUID",
                        get_product_uuid_handler,
                        m,
                        "b",
                        false);
        if (r < 0)
                return log_warning_errno(r, "Failed to get product UUID: %m");

        log_debug("Requesting product UUID.");

        bus_method_is_called = true;

        return 0;
}
