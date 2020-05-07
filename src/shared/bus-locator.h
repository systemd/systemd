/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct BusLocator {
        const char    *destination;
        const char    *path;
        const char    *interface;
} BusLocator;

extern const BusLocator* const bus_home_mgr;
extern const BusLocator* const bus_import_mgr;
extern const BusLocator* const bus_locale;
extern const BusLocator* const bus_login_mgr;
extern const BusLocator* const bus_machine_mgr;
extern const BusLocator* const bus_network_mgr;
extern const BusLocator* const bus_portable_mgr;
extern const BusLocator* const bus_resolve_mgr;
extern const BusLocator* const bus_systemd_mgr;
extern const BusLocator* const bus_timedate;
