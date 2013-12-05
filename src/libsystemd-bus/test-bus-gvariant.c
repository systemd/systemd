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

#ifdef HAVE_GLIB
#include <glib.h>
#endif

#include "util.h"
#include "sd-bus.h"
#include "bus-gvariant.h"
#include "bus-util.h"
#include "bus-internal.h"
#include "bus-message.h"

static void test_bus_gvariant_is_fixed_size(void) {
        assert(bus_gvariant_is_fixed_size("") > 0);
        assert(bus_gvariant_is_fixed_size("y") > 0);
        assert(bus_gvariant_is_fixed_size("u") > 0);
        assert(bus_gvariant_is_fixed_size("b") > 0);
        assert(bus_gvariant_is_fixed_size("n") > 0);
        assert(bus_gvariant_is_fixed_size("q") > 0);
        assert(bus_gvariant_is_fixed_size("i") > 0);
        assert(bus_gvariant_is_fixed_size("t") > 0);
        assert(bus_gvariant_is_fixed_size("d") > 0);
        assert(bus_gvariant_is_fixed_size("s") == 0);
        assert(bus_gvariant_is_fixed_size("o") == 0);
        assert(bus_gvariant_is_fixed_size("g") == 0);
        assert(bus_gvariant_is_fixed_size("h") > 0);
        assert(bus_gvariant_is_fixed_size("ay") == 0);
        assert(bus_gvariant_is_fixed_size("v") == 0);
        assert(bus_gvariant_is_fixed_size("(u)") > 0);
        assert(bus_gvariant_is_fixed_size("(uuuuy)") > 0);
        assert(bus_gvariant_is_fixed_size("(uusuuy)") == 0);
        assert(bus_gvariant_is_fixed_size("a{ss}") == 0);
        assert(bus_gvariant_is_fixed_size("((u)yyy(b(iiii)))") > 0);
        assert(bus_gvariant_is_fixed_size("((u)yyy(b(iiivi)))") == 0);
}

static void test_bus_gvariant_get_alignment(void) {
        assert(bus_gvariant_get_alignment("") == 1);
        assert(bus_gvariant_get_alignment("y") == 1);
        assert(bus_gvariant_get_alignment("b") == 1);
        assert(bus_gvariant_get_alignment("u") == 4);
        assert(bus_gvariant_get_alignment("s") == 1);
        assert(bus_gvariant_get_alignment("o") == 1);
        assert(bus_gvariant_get_alignment("g") == 1);
        assert(bus_gvariant_get_alignment("v") == 8);
        assert(bus_gvariant_get_alignment("h") == 4);
        assert(bus_gvariant_get_alignment("i") == 4);
        assert(bus_gvariant_get_alignment("t") == 8);
        assert(bus_gvariant_get_alignment("x") == 8);
        assert(bus_gvariant_get_alignment("q") == 2);
        assert(bus_gvariant_get_alignment("n") == 2);
        assert(bus_gvariant_get_alignment("d") == 8);
        assert(bus_gvariant_get_alignment("ay") == 1);
        assert(bus_gvariant_get_alignment("as") == 1);
        assert(bus_gvariant_get_alignment("au") == 4);
        assert(bus_gvariant_get_alignment("an") == 2);
        assert(bus_gvariant_get_alignment("ans") == 2);
        assert(bus_gvariant_get_alignment("ant") == 8);
        assert(bus_gvariant_get_alignment("(ss)") == 1);
        assert(bus_gvariant_get_alignment("(ssu)") == 4);
        assert(bus_gvariant_get_alignment("a(ssu)") == 4);
}

static void test_marshal(void) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;

        assert_se(sd_bus_open_system(&bus) >= 0);
        bus->use_gvariant = true; /* dirty hack */

        assert_se(sd_bus_message_new_method_call(bus, "a.service.name", "/an/object/path/which/is/really/really/long/so/that/we/hit/the/eight/bit/boundary/by/quite/some/margin/to/test/this/stuff/that/it/really/works", "an.interface.name", "AMethodName", &m) >= 0);

        /* assert_se(sd_bus_message_append(m, "ssy(sts)v", "first-string-parameter", "second-string-parameter", 9, "a", (uint64_t) 7777, "b", "(su)", "xxx", 4712) >= 0);  */
        assert_se(sd_bus_message_append(m,
                                        "a(usv)", 2,
                                        4711, "first-string-parameter", "(st)", "X", (uint64_t) 1111,
                                        4712, "second-string-parameter", "(a(si))", 2, "Y", 5, "Z", 6) >= 0);

        assert_se(bus_message_seal(m, 4711) >= 0);

#ifdef HAVE_GLIB
        {
                GVariant *v;
                char *t;

#if !defined(GLIB_VERSION_2_36)
                g_type_init();
#endif

                v = g_variant_new_from_data(G_VARIANT_TYPE("(yyyyuuua(yv))"), m->header, sizeof(struct bus_header) + BUS_MESSAGE_FIELDS_SIZE(m), false, NULL, NULL);
                t = g_variant_print(v, TRUE);
                printf("%s\n", t);
                g_free(t);
                g_variant_unref(v);

                v = g_variant_new_from_data(G_VARIANT_TYPE("(a(usv))"), m->body.data, BUS_MESSAGE_BODY_SIZE(m), false, NULL, NULL);
                t = g_variant_print(v, TRUE);
                printf("%s\n", t);
                g_free(t);
                g_variant_unref(v);
        }
#endif

}

int main(int argc, char *argv[]) {

        test_bus_gvariant_is_fixed_size();
        test_bus_gvariant_get_alignment();
        test_marshal();

        return 0;
}
