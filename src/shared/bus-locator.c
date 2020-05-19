/* SPDX-License-Identifier: LGPL-2.1+ */

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
