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

#include "bus-util.h"
#include "dbus-client-track.h"

static unsigned long tracked_client_hash(const void *a, const uint8_t hash_key[HASH_KEY_SIZE]) {
        const BusTrackedClient *x = a;

        return string_hash_func(x->name, hash_key) ^ trivial_hash_func(x->bus, hash_key);
}

static int tracked_client_compare(const void *a, const void *b) {
        const BusTrackedClient *x = a, *y = b;
        int r;

        r = strcmp(x->name, y->name);
        if (r != 0)
                return r;

        if (x->bus < y->bus)
                return -1;
        if (x->bus > y->bus)
                return 1;

        return 0;
}

static int on_name_owner_changed(sd_bus *bus, sd_bus_message *message, void *userdata, sd_bus_error *error) {
        BusTrackedClient *c = userdata;
        const char *name, *old, *new;
        int r;

        assert(bus);
        assert(message);

        r = sd_bus_message_read(message, "sss", &name, &old, &new);
        if (r < 0) {
                bus_log_parse_error(r);
                return r;
        }

        bus_client_untrack(c->set, bus, name);
        return 0;
}

static char *build_match(const char *name) {

        return strjoin("type='signal',"
                       "sender='org.freedesktop.DBus',"
                       "path='/org/freedesktop/DBus',"
                       "interface='org.freedesktop.DBus',"
                       "member='NameOwnerChanged',"
                       "arg0='", name, "'", NULL);
}

int bus_client_track(Set **s, sd_bus *bus, const char *name) {
        BusTrackedClient *c, *found;
        size_t l;
        int r;

        assert(s);
        assert(bus);

        r = set_ensure_allocated(s, tracked_client_hash, tracked_client_compare);
        if (r < 0)
                return r;

        name = strempty(name);

        l = strlen(name);

        c = alloca(offsetof(BusTrackedClient, name) + l + 1);
        c->set = *s;
        c->bus = bus;
        strcpy(c->name, name);

        found = set_get(*s, c);
        if (found)
                return 0;

        c = memdup(c, offsetof(BusTrackedClient, name) + l + 1);
        if (!c)
                return -ENOMEM;

        r = set_put(*s, c);
        if (r < 0) {
                free(c);
                return r;
        }

        if (!isempty(name)) {
                _cleanup_free_ char *match = NULL;

                match = build_match(name);
                if (!match) {
                        set_remove(*s, c);
                        free(c);
                        return -ENOMEM;
                }

                r = sd_bus_add_match(bus, match, on_name_owner_changed, c);
                if (r < 0) {
                        set_remove(*s, c);
                        free(c);
                        return r;
                }
        }

        sd_bus_ref(c->bus);
        return 1;
}

static void bus_client_free_one(Set *s, BusTrackedClient *c) {
        assert(s);
        assert(c);

        if (!isempty(c->name)) {
                _cleanup_free_ char *match = NULL;

                match = build_match(c->name);
                if (match)
                        sd_bus_remove_match(c->bus, match, on_name_owner_changed, c);
        }

        sd_bus_unref(c->bus);
        set_remove(s, c);
        free(c);
}

int bus_client_untrack(Set *s, sd_bus *bus, const char *name) {
        BusTrackedClient *c, *found;
        size_t l;

        assert(bus);
        assert(s);
        assert(name);

        name = strempty(name);

        l = strlen(name);

        c = alloca(offsetof(BusTrackedClient, name) + l + 1);
        c->bus = bus;
        strcpy(c->name, name);

        found = set_get(s, c);
        if (!found)
                return 0;

        bus_client_free_one(s, found);
        return 1;
}

void bus_client_track_free(Set *s) {
        BusTrackedClient *c;

        while ((c = set_first(s)))
                bus_client_free_one(s, c);

        set_free(s);
}

int bus_client_untrack_bus(Set *s, sd_bus *bus) {
        BusTrackedClient *c;
        Iterator i;
        int r = 0;

        SET_FOREACH(c, s, i)
                if (c->bus == bus) {
                        bus_client_free_one(s, c);
                        r++;
                }

        return r;
}

void bus_client_track_serialize(Manager *m, FILE *f, Set *s) {
        BusTrackedClient *c;
        Iterator i;

        assert(m);
        assert(f);

        SET_FOREACH(c, s, i) {
                if (c->bus == m->api_bus)
                        fprintf(f, "subscribed=%s\n", isempty(c->name) ? "*" : c->name);
                else
                        fprintf(f, "subscribed=%p %s\n", c->bus, isempty(c->name) ? "*" : c->name);
        }
}

int bus_client_track_deserialize_item(Manager *m, Set **s, const char *line) {
        const char *e, *q, *name;
        sd_bus *bus;
        void *p;
        int r;

        e = startswith(line, "subscribed=");
        if (!e)
                return 0;

        q = strpbrk(e, WHITESPACE);
        if (!q) {
                if (m->api_bus) {
                        bus = m->api_bus;
                        name = e;
                        goto finish;
                }

                return 1;
        }

        if (sscanf(e, "%p", &p) != 1) {
                log_debug("Failed to parse subscription pointer.");
                return -EINVAL;
        }

        bus = set_get(m->private_buses, p);
        if (!bus)
                return 1;

        name = q + strspn(q, WHITESPACE);

finish:
        r = bus_client_track(s, bus, streq(name, "*") ? NULL : name);
        if (r < 0) {
                log_debug("Failed to deserialize client subscription: %s", strerror(-r));
                return r;
        }

        return 1;
}
