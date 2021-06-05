/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-match.h"
#include "bus-message.h"
#include "bus-slot.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "tests.h"

static bool mask[32];

static int filter(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Ran %u", PTR_TO_UINT(userdata));
        assert_se(PTR_TO_UINT(userdata) < ELEMENTSOF(mask));
        mask[PTR_TO_UINT(userdata)] = true;
        return 0;
}

static bool mask_contains(unsigned a[], unsigned n) {
        unsigned i, j;

        for (i = 0; i < ELEMENTSOF(mask); i++) {
                bool found = false;

                for (j = 0; j < n; j++)
                        if (a[j] == i) {
                                found = true;
                                break;
                        }

                if (found != mask[i])
                        return false;
        }

        return true;
}

static int match_add(sd_bus_slot *slots, struct bus_match_node *root, const char *match, int value) {
        struct bus_match_component *components;
        unsigned n_components;
        sd_bus_slot *s;
        int r;

        s = slots + value;

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                return r;

        s->userdata = INT_TO_PTR(value);
        s->match_callback.callback = filter;

        r = bus_match_add(root, components, n_components, &s->match_callback);
        bus_match_parse_free(components, n_components);

        return r;
}

static void test_match_scope(const char *match, enum bus_match_scope scope) {
        struct bus_match_component *components = NULL;
        unsigned n_components = 0;

        assert_se(bus_match_parse(match, &components, &n_components) >= 0);
        assert_se(bus_match_get_scope(components, n_components) == scope);
        bus_match_parse_free(components, n_components);
}

int main(int argc, char *argv[]) {
        struct bus_match_node root = {
                .type = BUS_MATCH_ROOT,
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_slot slots[19] = {};
        int r;

        test_setup_logging(LOG_INFO);

        r = sd_bus_open_user(&bus);
        if (r < 0)
                r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_tests_skipped("Failed to connect to bus");

        assert_se(match_add(slots, &root, "arg2='wal\\'do',sender='foo',type='signal',interface='bar.x',", 1) >= 0);
        assert_se(match_add(slots, &root, "arg2='wal\\'do2',sender='foo',type='signal',interface='bar.x',", 2) >= 0);
        assert_se(match_add(slots, &root, "arg3='test',sender='foo',type='signal',interface='bar.x',", 3) >= 0);
        assert_se(match_add(slots, &root, "arg3='test',sender='foo',type='method_call',interface='bar.x',", 4) >= 0);
        assert_se(match_add(slots, &root, "", 5) >= 0);
        assert_se(match_add(slots, &root, "interface='quux.x'", 6) >= 0);
        assert_se(match_add(slots, &root, "interface='bar.x'", 7) >= 0);
        assert_se(match_add(slots, &root, "member='waldo',path='/foo/bar'", 8) >= 0);
        assert_se(match_add(slots, &root, "path='/foo/bar'", 9) >= 0);
        assert_se(match_add(slots, &root, "path_namespace='/foo'", 10) >= 0);
        assert_se(match_add(slots, &root, "path_namespace='/foo/quux'", 11) >= 0);
        assert_se(match_add(slots, &root, "arg1='two'", 12) >= 0);
        assert_se(match_add(slots, &root, "member='waldo',arg2path='/prefix/'", 13) >= 0);
        assert_se(match_add(slots, &root, "member=waldo,path='/foo/bar',arg3namespace='prefix'", 14) >= 0);
        assert_se(match_add(slots, &root, "arg4has='pi'", 15) >= 0);
        assert_se(match_add(slots, &root, "arg4has='pa'", 16) >= 0);
        assert_se(match_add(slots, &root, "arg4has='po'", 17) >= 0);
        assert_se(match_add(slots, &root, "arg4='pi'", 18) >= 0);

        bus_match_dump(stdout, &root, 0);

        assert_se(sd_bus_message_new_signal(bus, &m, "/foo/bar", "bar.x", "waldo") >= 0);
        assert_se(sd_bus_message_append(m, "ssssas", "one", "two", "/prefix/three", "prefix.four", 3, "pi", "pa", "po") >= 0);
        assert_se(sd_bus_message_seal(m, 1, 0) >= 0);

        zero(mask);
        assert_se(bus_match_run(NULL, &root, m) == 0);
        assert_se(mask_contains((unsigned[]) { 9, 8, 7, 5, 10, 12, 13, 14, 15, 16, 17 }, 11));

        assert_se(bus_match_remove(&root, &slots[8].match_callback) >= 0);
        assert_se(bus_match_remove(&root, &slots[13].match_callback) >= 0);

        bus_match_dump(stdout, &root, 0);

        zero(mask);
        assert_se(bus_match_run(NULL, &root, m) == 0);
        assert_se(mask_contains((unsigned[]) { 9, 5, 10, 12, 14, 7, 15, 16, 17 }, 9));

        for (enum bus_match_node_type i = 0; i < _BUS_MATCH_NODE_TYPE_MAX; i++) {
                char buf[32];
                const char *x;

                assert_se(x = bus_match_node_type_to_string(i, buf, sizeof(buf)));

                if (i >= BUS_MATCH_MESSAGE_TYPE)
                        assert_se(bus_match_node_type_from_string(x, strlen(x)) == i);
        }

        bus_match_free(&root);

        test_match_scope("interface='foobar'", BUS_MATCH_GENERIC);
        test_match_scope("", BUS_MATCH_GENERIC);
        test_match_scope("interface='org.freedesktop.DBus.Local'", BUS_MATCH_LOCAL);
        test_match_scope("sender='org.freedesktop.DBus.Local'", BUS_MATCH_LOCAL);
        test_match_scope("member='gurke',path='/org/freedesktop/DBus/Local'", BUS_MATCH_LOCAL);
        test_match_scope("arg2='piep',sender='org.freedesktop.DBus',member='waldo'", BUS_MATCH_DRIVER);

        return 0;
}
