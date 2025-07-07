/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-locator.h"

const BusLocator* const bus_home_mgr = &(BusLocator){
        .destination = "org.freedesktop.home1",
        .path = "/org/freedesktop/home1",
        .interface = "org.freedesktop.home1.Manager",
};

const BusLocator* const bus_import_mgr = &(BusLocator){
        .destination ="org.freedesktop.import1",
        .path = "/org/freedesktop/import1",
        .interface = "org.freedesktop.import1.Manager"
};

const BusLocator* const bus_locale = &(BusLocator){
        .destination = "org.freedesktop.locale1",
        .path = "/org/freedesktop/locale1",
        .interface = "org.freedesktop.locale1"
};

const BusLocator* const bus_login_mgr = &(BusLocator){
        .destination = "org.freedesktop.login1",
        .path = "/org/freedesktop/login1",
        .interface = "org.freedesktop.login1.Manager"
};

const BusLocator* const bus_machine_mgr = &(BusLocator){
        .destination ="org.freedesktop.machine1",
        .path = "/org/freedesktop/machine1",
        .interface = "org.freedesktop.machine1.Manager"
};

const BusLocator* const bus_network_mgr = &(BusLocator){
        .destination = "org.freedesktop.network1",
        .path = "/org/freedesktop/network1",
        .interface = "org.freedesktop.network1.Manager"
};

const BusLocator* const bus_oom_mgr = &(BusLocator){
        .destination = "org.freedesktop.oom1",
        .path = "/org/freedesktop/oom1",
        .interface = "org.freedesktop.oom1.Manager"
};

const BusLocator* const bus_portable_mgr = &(BusLocator){
        .destination = "org.freedesktop.portable1",
        .path = "/org/freedesktop/portable1",
        .interface = "org.freedesktop.portable1.Manager"
};

const BusLocator* const bus_resolve_mgr = &(BusLocator){
        .destination = "org.freedesktop.resolve1",
        .path = "/org/freedesktop/resolve1",
        .interface = "org.freedesktop.resolve1.Manager"
};

const BusLocator* const bus_systemd_mgr = &(BusLocator){
        .destination = "org.freedesktop.systemd1",
        .path = "/org/freedesktop/systemd1",
        .interface = "org.freedesktop.systemd1.Manager"
};

const BusLocator* const bus_sysupdate_mgr = &(BusLocator){
        .destination = "org.freedesktop.sysupdate1",
        .path = "/org/freedesktop/sysupdate1",
        .interface = "org.freedesktop.sysupdate1.Manager"
};

const BusLocator* const bus_timedate = &(BusLocator){
        .destination = "org.freedesktop.timedate1",
        .path = "/org/freedesktop/timedate1",
        .interface = "org.freedesktop.timedate1"
};

const BusLocator* const bus_timesync_mgr = &(BusLocator){
        .destination = "org.freedesktop.timesync1",
        .path = "/org/freedesktop/timesync1",
        .interface = "org.freedesktop.timesync1.Manager"
};

const BusLocator* const bus_hostname = &(BusLocator){
        .destination = "org.freedesktop.hostname1",
        .path = "/org/freedesktop/hostname1",
        .interface = "org.freedesktop.hostname1"
};

/* Shorthand flavors of the sd-bus convenience helpers with destination,path,interface strings encapsulated
 * within a single struct. */
int bus_call_method_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                const char *types, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, types);
        r = sd_bus_call_method_asyncv(bus, ret_slot, locator->destination, locator->path, locator->interface, member, callback, userdata, types, ap);
        va_end(ap);

        return r;
}

int bus_call_method(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply,
                const char *types, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, types);
        r = sd_bus_call_methodv(bus, locator->destination, locator->path, locator->interface, member, reterr_error, ret_reply, types, ap);
        va_end(ap);

        return r;
}

int bus_get_property(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply,
                const char *type) {

        assert(locator);

        return sd_bus_get_property(bus, locator->destination, locator->path, locator->interface, member, reterr_error, ret_reply, type);
}

int bus_get_property_trivial(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                char type,
                void *ret) {

        assert(locator);

        return sd_bus_get_property_trivial(bus, locator->destination, locator->path, locator->interface, member, reterr_error, type, ret);
}

int bus_get_property_string(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                char **ret) {

        assert(locator);

        return sd_bus_get_property_string(bus, locator->destination, locator->path, locator->interface, member, reterr_error, ret);
}

int bus_get_property_strv(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                char ***ret) {

        assert(locator);

        return sd_bus_get_property_strv(bus, locator->destination, locator->path, locator->interface, member, reterr_error, ret);
}

int bus_set_property(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *reterr_error,
                const char *type, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, type);
        r = sd_bus_set_propertyv(bus, locator->destination, locator->path, locator->interface, member, reterr_error, type, ap);
        va_end(ap);

        return r;
}

int bus_match_signal(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata) {

        assert(locator);

        return sd_bus_match_signal(bus, ret_slot, locator->destination, locator->path, locator->interface, member, callback, userdata);
}

int bus_match_signal_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata) {

        assert(locator);

        return sd_bus_match_signal_async(bus, ret_slot, locator->destination, locator->path, locator->interface, member, callback, install_callback, userdata);
}

int bus_message_new_method_call(
                sd_bus *bus,
                sd_bus_message **ret,
                const BusLocator *locator,
                const char *member) {

        assert(locator);

        return sd_bus_message_new_method_call(bus, ret, locator->destination, locator->path, locator->interface, member);
}
