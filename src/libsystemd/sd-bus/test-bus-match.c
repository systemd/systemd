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

#include <assert.h>

#include "log.h"
#include "util.h"
#include "macro.h"

#include "bus-match.h"
#include "bus-message.h"
#include "bus-util.h"

static bool mask[32];

static int filter(sd_bus *b, sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        log_info("Ran %i", PTR_TO_INT(userdata));
        mask[PTR_TO_INT(userdata)] = true;
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

static int match_add(struct bus_match_node *root, const char *match, int value) {
        struct bus_match_component *components = NULL;
        unsigned n_components = 0;
        int r;

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                return r;

        r = bus_match_add(root, components, n_components, filter, INT_TO_PTR(value), 0, NULL);
        bus_match_parse_free(components, n_components);

        return r;
}

static int match_remove(struct bus_match_node *root, const char *match, int value) {
        struct bus_match_component *components = NULL;
        unsigned n_components = 0;
        int r;

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                return r;

        r = bus_match_remove(root, components, n_components, filter, INT_TO_PTR(value), 0);
        bus_match_parse_free(components, n_components);

        return r;
}

int main(int argc, char *argv[]) {
        struct bus_match_node root;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        enum bus_match_node_type i;

        zero(root);
        root.type = BUS_MATCH_ROOT;

        assert_se(match_add(&root, "arg2='wal\\'do',sender='foo',type='signal',interface='bar.x',", 1) >= 0);
        assert_se(match_add(&root, "arg2='wal\\'do2',sender='foo',type='signal',interface='bar.x',", 2) >= 0);
        assert_se(match_add(&root, "arg3='test',sender='foo',type='signal',interface='bar.x',", 3) >= 0);
        assert_se(match_add(&root, "arg3='test',sender='foo',type='method_call',interface='bar.x',", 4) >= 0);
        assert_se(match_add(&root, "", 5) >= 0);
        assert_se(match_add(&root, "interface='quux.x'", 6) >= 0);
        assert_se(match_add(&root, "interface='bar.x'", 7) >= 0);
        assert_se(match_add(&root, "member='waldo',path='/foo/bar'", 8) >= 0);
        assert_se(match_add(&root, "path='/foo/bar'", 9) >= 0);
        assert_se(match_add(&root, "path_namespace='/foo'", 10) >= 0);
        assert_se(match_add(&root, "path_namespace='/foo/quux'", 11) >= 0);
        assert_se(match_add(&root, "arg1='two'", 12) >= 0);
        assert_se(match_add(&root, "member='waldo',arg2path='/prefix/'", 13) >= 0);
        assert_se(match_add(&root, "member=waldo,path='/foo/bar',arg3namespace='prefix'", 14) >= 0);

        bus_match_dump(&root, 0);

        assert_se(sd_bus_message_new_signal(NULL, &m, "/foo/bar", "bar.x", "waldo") >= 0);
        assert_se(sd_bus_message_append(m, "ssss", "one", "two", "/prefix/three", "prefix.four") >= 0);
        assert_se(bus_message_seal(m, 1, 0) >= 0);

        zero(mask);
        assert_se(bus_match_run(NULL, &root, m) == 0);
        assert_se(mask_contains((unsigned[]) { 9, 8, 7, 5, 10, 12, 13, 14 }, 8));

        assert_se(match_remove(&root, "member='waldo',path='/foo/bar'", 8) > 0);
        assert_se(match_remove(&root, "arg2path='/prefix/',member='waldo'", 13) > 0);
        assert_se(match_remove(&root, "interface='bar.xx'", 7) == 0);

        bus_match_dump(&root, 0);

        zero(mask);
        assert_se(bus_match_run(NULL, &root, m) == 0);
        assert_se(mask_contains((unsigned[]) { 9, 5, 10, 12, 14, 7 }, 6));

        for (i = 0; i < _BUS_MATCH_NODE_TYPE_MAX; i++) {
                char buf[32];
                const char *x;

                assert_se(x = bus_match_node_type_to_string(i, buf, sizeof(buf)));

                if (i >= BUS_MATCH_MESSAGE_TYPE)
                        assert_se(bus_match_node_type_from_string(x, strlen(x)) == i);
        }

        bus_match_free(&root);

        return 0;
}
