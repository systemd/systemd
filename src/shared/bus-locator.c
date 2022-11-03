/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-locator.h"
#include "macro.h"

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

const BusLocator* const bus_timedate = &(BusLocator){
        .destination = "org.freedesktop.timedate1",
        .path = "/org/freedesktop/timedate1",
        .interface = "org.freedesktop.timedate1"
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
                sd_bus_slot **slot,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                const char *types, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, types);
        r = sd_bus_call_method_asyncv(bus, slot, locator->destination, locator->path, locator->interface, member, callback, userdata, types, ap);
        va_end(ap);

        return r;
}

int bus_call_method(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *types, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, types);
        r = sd_bus_call_methodv(bus, locator->destination, locator->path, locator->interface, member, error, reply, types, ap);
        va_end(ap);

        return r;
}

int bus_get_property(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *type) {

        assert(locator);

        return sd_bus_get_property(bus, locator->destination, locator->path, locator->interface, member, error, reply, type);
}

int bus_get_property_trivial(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                char type, void *ptr) {

        assert(locator);

        return sd_bus_get_property_trivial(bus, locator->destination, locator->path, locator->interface, member, error, type, ptr);
}

int bus_get_property_string(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                char **ret) {

        assert(locator);

        return sd_bus_get_property_string(bus, locator->destination, locator->path, locator->interface, member, error, ret);
}

int bus_get_property_strv(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                char ***ret) {

        assert(locator);

        return sd_bus_get_property_strv(bus, locator->destination, locator->path, locator->interface, member, error, ret);
}

int bus_set_property(
                sd_bus *bus,
                const BusLocator *locator,
                const char *member,
                sd_bus_error *error,
                const char *type, ...) {

        va_list ap;
        int r;

        assert(locator);

        va_start(ap, type);
        r = sd_bus_set_propertyv(bus, locator->destination, locator->path, locator->interface, member, error, type, ap);
        va_end(ap);

        return r;
}

int bus_match_signal(
                sd_bus *bus,
                sd_bus_slot **ret,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata) {

        assert(locator);

        return sd_bus_match_signal(bus, ret, locator->destination, locator->path, locator->interface, member, callback, userdata);
}

int bus_match_signal_async(
                sd_bus *bus,
                sd_bus_slot **ret,
                const BusLocator *locator,
                const char *member,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata) {

        assert(locator);

        return sd_bus_match_signal_async(bus, ret, locator->destination, locator->path, locator->interface, member, callback, install_callback, userdata);
}

int bus_message_new_method_call(
                sd_bus *bus,
                sd_bus_message **m,
                const BusLocator *locator,
                const char *member) {

        assert(locator);

        return sd_bus_message_new_method_call(bus, m, locator->destination, locator->path, locator->interface, member);
}
