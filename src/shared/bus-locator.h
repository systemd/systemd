/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

typedef struct BusLocator {
        const char *destination;
        const char *path;
        const char *interface;
} BusLocator;

extern const BusLocator* const bus_home_mgr;
extern const BusLocator* const bus_hostname;
extern const BusLocator* const bus_import_mgr;
extern const BusLocator* const bus_locale;
extern const BusLocator* const bus_login_mgr;
extern const BusLocator* const bus_machine_mgr;
extern const BusLocator* const bus_network_mgr;
extern const BusLocator* const bus_oom_mgr;
extern const BusLocator* const bus_portable_mgr;
extern const BusLocator* const bus_resolve_mgr;
extern const BusLocator* const bus_systemd_mgr;
extern const BusLocator* const bus_sysupdate_mgr;
extern const BusLocator* const bus_timedate;
extern const BusLocator* const bus_timesync_mgr;

/* Shorthand flavors of the sd-bus convenience helpers with destination,path,interface strings encapsulated
 * within a single struct. */
int bus_call_method_async(sd_bus *bus, sd_bus_slot **slot, const BusLocator *locator, const char *member, sd_bus_message_handler_t callback, void *userdata, const char *types, ...);
int bus_call_method(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, sd_bus_message **reply, const char *types, ...);
int bus_get_property(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, sd_bus_message **reply, const char *type);
int bus_get_property_trivial(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, char type, void *ptr);
int bus_get_property_string(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, char **ret);
int bus_get_property_strv(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, char ***ret);
int bus_set_property(sd_bus *bus, const BusLocator *locator, const char *member, sd_bus_error *error, const char *type, ...);
int bus_match_signal(sd_bus *bus, sd_bus_slot **ret, const BusLocator *locator, const char *member, sd_bus_message_handler_t callback, void *userdata);
int bus_match_signal_async(sd_bus *bus, sd_bus_slot **ret, const BusLocator *locator, const char *member, sd_bus_message_handler_t callback, sd_bus_message_handler_t install_callback, void *userdata);
int bus_message_new_method_call(sd_bus *bus, sd_bus_message **m, const BusLocator *locator, const char *member);
