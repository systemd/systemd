/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "log.h"
#include "bus-introspect.h"

static int prop_get(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return -EINVAL;
}

static int prop_set(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return -EINVAL;
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Hello", "ssas", "a(uu)", NULL, 0),
        SD_BUS_METHOD("DeprecatedHello", "", "", NULL, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_METHOD("DeprecatedHelloNoReply", "", "", NULL, SD_BUS_VTABLE_DEPRECATED|SD_BUS_VTABLE_METHOD_NO_REPLY),
        SD_BUS_SIGNAL("Wowza", "sss", 0),
        SD_BUS_SIGNAL("DeprecatedWowza", "ut", SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_WRITABLE_PROPERTY("AProperty", "s", prop_get, prop_set, 0, 0),
        SD_BUS_PROPERTY("AReadOnlyDeprecatedProperty", "(ut)", prop_get, 0, SD_BUS_VTABLE_DEPRECATED),
        SD_BUS_PROPERTY("ChangingProperty", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Invalidating", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION),
        SD_BUS_PROPERTY("Constant", "t", prop_get, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

int main(int argc, char *argv[]) {
        struct introspect intro;

        log_set_max_level(LOG_DEBUG);

        assert_se(introspect_begin(&intro, false) >= 0);

        fprintf(intro.f, " <interface name=\"org.foo\">\n");
        assert_se(introspect_write_interface(&intro, vtable) >= 0);
        fputs(" </interface>\n", intro.f);

        fflush(intro.f);
        fputs(intro.introspection, stdout);

        introspect_free(&intro);

        return 0;
}
