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
#include "sd-bus-protocol.h"
#include "bus-introspect.h"
#include "bus-signature.h"
#include "bus-internal.h"
#include "bus-protocol.h"

int introspect_begin(struct introspect *i, bool trusted) {
        assert(i);

        zero(*i);
        i->trusted = trusted;

        i->f = open_memstream(&i->introspection, &i->size);
        if (!i->f)
                return -ENOMEM;

        fputs(BUS_INTROSPECT_DOCTYPE
              "<node>\n", i->f);

        return 0;
}

int introspect_write_default_interfaces(struct introspect *i, bool object_manager) {
        assert(i);

        fputs(BUS_INTROSPECT_INTERFACE_PEER
              BUS_INTROSPECT_INTERFACE_INTROSPECTABLE
              BUS_INTROSPECT_INTERFACE_PROPERTIES, i->f);

        if (object_manager)
                fputs(BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER, i->f);

        return 0;
}

int introspect_write_child_nodes(struct introspect *i, Set *s, const char *prefix) {
        char *node;

        assert(i);
        assert(prefix);

        while ((node = set_steal_first(s))) {
                const char *e;

                e = object_path_startswith(node, prefix);
                if (e && e[0])
                        fprintf(i->f, " <node name=\"%s\"/>\n", e);

                free(node);
        }

        return 0;
}

static void introspect_write_flags(struct introspect *i, int type, int flags) {
        if (flags & SD_BUS_VTABLE_DEPRECATED)
                fputs("   <annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n", i->f);

        if (type == _SD_BUS_VTABLE_METHOD && (flags & SD_BUS_VTABLE_METHOD_NO_REPLY))
                fputs("   <annotation name=\"org.freedesktop.DBus.Method.NoReply\" value=\"true\"/>\n", i->f);

        if (type == _SD_BUS_VTABLE_PROPERTY || type == _SD_BUS_VTABLE_WRITABLE_PROPERTY) {
                if (flags & SD_BUS_VTABLE_PROPERTY_CONST)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"const\"/>\n", i->f);
                else if (flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"invalidates\"/>\n", i->f);
                else if (!(flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE))
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n", i->f);
        }

        if (!i->trusted &&
            (type == _SD_BUS_VTABLE_METHOD || type == _SD_BUS_VTABLE_WRITABLE_PROPERTY) &&
            !(flags & SD_BUS_VTABLE_UNPRIVILEGED))
                fputs("   <annotation name=\"org.freedesktop.systemd1.Privileged\" value=\"true\"/>\n", i->f);
}

static int introspect_write_arguments(struct introspect *i, const char *signature, const char *direction) {
        int r;

        for (;;) {
                size_t l;

                if (!*signature)
                        return 0;

                r = signature_element_length(signature, &l);
                if (r < 0)
                        return r;

                fprintf(i->f, "   <arg type=\"%.*s\"", (int) l, signature);

                if (direction)
                        fprintf(i->f, " direction=\"%s\"/>\n", direction);
                else
                        fputs("/>\n", i->f);

                signature += l;
        }
}

int introspect_write_interface(struct introspect *i, const sd_bus_vtable *v) {
        assert(i);
        assert(v);

        for (; v->type != _SD_BUS_VTABLE_END; v++) {

                /* Ignore methods, signals and properties that are
                 * marked "hidden", but do show the interface
                 * itself */

                if (v->type != _SD_BUS_VTABLE_START && (v->flags & SD_BUS_VTABLE_HIDDEN))
                        continue;

                switch (v->type) {

                case _SD_BUS_VTABLE_START:
                        if (v->flags & SD_BUS_VTABLE_DEPRECATED)
                                fputs("  <annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n", i->f);
                        break;

                case _SD_BUS_VTABLE_METHOD:
                        fprintf(i->f, "  <method name=\"%s\">\n", v->x.method.member);
                        introspect_write_arguments(i, strempty(v->x.method.signature), "in");
                        introspect_write_arguments(i, strempty(v->x.method.result), "out");
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </method>\n", i->f);
                        break;

                case _SD_BUS_VTABLE_PROPERTY:
                case _SD_BUS_VTABLE_WRITABLE_PROPERTY:
                        fprintf(i->f, "  <property name=\"%s\" type=\"%s\" access=\"%s\">\n",
                                v->x.property.member,
                                v->x.property.signature,
                                v->type == _SD_BUS_VTABLE_WRITABLE_PROPERTY ? "readwrite" : "read");
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </property>\n", i->f);
                        break;

                case _SD_BUS_VTABLE_SIGNAL:
                        fprintf(i->f, "  <signal name=\"%s\">\n", v->x.signal.member);
                        introspect_write_arguments(i, strempty(v->x.signal.signature), NULL);
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </signal>\n", i->f);
                        break;
                }

        }

        return 0;
}

int introspect_finish(struct introspect *i, sd_bus *bus, sd_bus_message *m, sd_bus_message **reply) {
        sd_bus_message *q;
        int r;

        assert(i);
        assert(m);
        assert(reply);

        fputs("</node>\n", i->f);
        fflush(i->f);

        if (ferror(i->f))
                return -ENOMEM;

        r = sd_bus_message_new_method_return(m, &q);
        if (r < 0)
                return r;

        r = sd_bus_message_append(q, "s", i->introspection);
        if (r < 0) {
                sd_bus_message_unref(q);
                return r;
        }

        *reply = q;
        return 0;
}

void introspect_free(struct introspect *i) {
        assert(i);

        if (i->f)
                fclose(i->f);

        if (i->introspection)
                free(i->introspection);

        zero(*i);
}
