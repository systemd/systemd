/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-internal.h"
#include "bus-introspect.h"
#include "bus-objects.h"
#include "bus-protocol.h"
#include "bus-signature.h"
#include "fd-util.h"
#include "fileio.h"
#include "memory-util.h"
#include "string-util.h"

#define BUS_INTROSPECT_DOCTYPE                                       \
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
        "\"https://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"

#define BUS_INTROSPECT_INTERFACE_PEER                                \
        " <interface name=\"org.freedesktop.DBus.Peer\">\n"             \
        "  <method name=\"Ping\"/>\n"                                   \
        "  <method name=\"GetMachineId\">\n"                            \
        "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        " </interface>\n"

#define BUS_INTROSPECT_INTERFACE_INTROSPECTABLE                      \
        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"   \
        "  <method name=\"Introspect\">\n"                              \
        "   <arg name=\"xml_data\" type=\"s\" direction=\"out\"/>\n"    \
        "  </method>\n"                                                 \
        " </interface>\n"

#define BUS_INTROSPECT_INTERFACE_PROPERTIES                          \
        " <interface name=\"org.freedesktop.DBus.Properties\">\n"       \
        "  <method name=\"Get\">\n"                                     \
        "   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n" \
        "   <arg name=\"property_name\" direction=\"in\" type=\"s\"/>\n" \
        "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"GetAll\">\n"                                  \
        "   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n" \
        "   <arg name=\"props\" direction=\"out\" type=\"a{sv}\"/>\n"   \
        "  </method>\n"                                                 \
        "  <method name=\"Set\">\n"                                     \
        "   <arg name=\"interface_name\" direction=\"in\" type=\"s\"/>\n" \
        "   <arg name=\"property_name\" direction=\"in\" type=\"s\"/>\n" \
        "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"        \
        "  </method>\n"                                                 \
        "  <signal name=\"PropertiesChanged\">\n"                       \
        "   <arg type=\"s\" name=\"interface_name\"/>\n"                \
        "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"        \
        "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"       \
        "  </signal>\n"                                                 \
        " </interface>\n"

#define BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER                      \
        " <interface name=\"org.freedesktop.DBus.ObjectManager\">\n"    \
        "  <method name=\"GetManagedObjects\">\n"                       \
        "   <arg type=\"a{oa{sa{sv}}}\" name=\"object_paths_interfaces_and_properties\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <signal name=\"InterfacesAdded\">\n"                         \
        "   <arg type=\"o\" name=\"object_path\"/>\n"                   \
        "   <arg type=\"a{sa{sv}}\" name=\"interfaces_and_properties\"/>\n" \
        "  </signal>\n"                                                 \
        "  <signal name=\"InterfacesRemoved\">\n"                       \
        "   <arg type=\"o\" name=\"object_path\"/>\n"                   \
        "   <arg type=\"as\" name=\"interfaces\"/>\n"                   \
        "  </signal>\n"                                                 \
        " </interface>\n"

int introspect_begin(struct introspect *i, bool trusted) {
        assert(i);

        *i = (struct introspect) {
                .trusted = trusted,
        };

        i->f = open_memstream_unlocked(&i->introspection, &i->size);
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

static int set_interface_name(struct introspect *intro, const char *interface_name) {
        if (streq_ptr(intro->interface_name, interface_name))
                return 0;

        if (intro->interface_name)
                fputs(" </interface>\n", intro->f);

        if (interface_name)
                fprintf(intro->f, " <interface name=\"%s\">\n", interface_name);

        return free_and_strdup(&intro->interface_name, interface_name);
}

int introspect_write_child_nodes(struct introspect *i, OrderedSet *s, const char *prefix) {
        char *node;

        assert(i);
        assert(prefix);

        assert_se(set_interface_name(i, NULL) >= 0);

        while ((node = ordered_set_steal_first(s))) {
                const char *e;

                e = object_path_startswith(node, prefix);
                if (e && e[0])
                        fprintf(i->f, " <node name=\"%s\"/>\n", e);

                free(node);
        }

        return 0;
}

static void introspect_write_flags(struct introspect *i, int type, uint64_t flags) {
        if (flags & SD_BUS_VTABLE_DEPRECATED)
                fputs("   <annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n", i->f);

        if (type == _SD_BUS_VTABLE_METHOD && (flags & SD_BUS_VTABLE_METHOD_NO_REPLY))
                fputs("   <annotation name=\"org.freedesktop.DBus.Method.NoReply\" value=\"true\"/>\n", i->f);

        if (IN_SET(type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY)) {
                if (flags & SD_BUS_VTABLE_PROPERTY_EXPLICIT)
                        fputs("   <annotation name=\"org.freedesktop.systemd1.Explicit\" value=\"true\"/>\n", i->f);

                if (flags & SD_BUS_VTABLE_PROPERTY_CONST)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"const\"/>\n", i->f);
                else if (flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION)
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"invalidates\"/>\n", i->f);
                else if (!(flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE))
                        fputs("   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n", i->f);
        }

        if (!i->trusted &&
            IN_SET(type, _SD_BUS_VTABLE_METHOD, _SD_BUS_VTABLE_WRITABLE_PROPERTY) &&
            !(flags & SD_BUS_VTABLE_UNPRIVILEGED))
                fputs("   <annotation name=\"org.freedesktop.systemd1.Privileged\" value=\"true\"/>\n", i->f);
}

/* Note that "names" is both an input and an output parameter. It initially points to the first argument name in a
   NULL-separated list of strings, and is then advanced with each argument, and the resulting pointer is returned. */
static int introspect_write_arguments(struct introspect *i, const char *signature, const char **names, const char *direction) {
        int r;

        for (;;) {
                size_t l;

                if (!*signature)
                        return 0;

                r = signature_element_length(signature, &l);
                if (r < 0)
                        return r;

                fprintf(i->f, "   <arg type=\"%.*s\"", (int) l, signature);

                if (**names != '\0') {
                        fprintf(i->f, " name=\"%s\"", *names);
                        *names += strlen(*names) + 1;
                }

                if (direction)
                        fprintf(i->f, " direction=\"%s\"/>\n", direction);
                else
                        fputs("/>\n", i->f);

                signature += l;
        }
}

int introspect_write_interface(
                struct introspect *i,
                const char *interface_name,
                const sd_bus_vtable *v) {

        const sd_bus_vtable *vtable = ASSERT_PTR(v);
        const char *names = "";
        int r;

        assert(i);
        assert(interface_name);

        r = set_interface_name(i, interface_name);
        if (r < 0)
                return r;

        for (; v->type != _SD_BUS_VTABLE_END; v = bus_vtable_next(vtable, v)) {

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
                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.method.names);
                        introspect_write_arguments(i, strempty(v->x.method.signature), &names, "in");
                        introspect_write_arguments(i, strempty(v->x.method.result), &names, "out");
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
                        if (bus_vtable_has_names(vtable))
                                names = strempty(v->x.signal.names);
                        introspect_write_arguments(i, strempty(v->x.signal.signature), &names, NULL);
                        introspect_write_flags(i, v->type, v->flags);
                        fputs("  </signal>\n", i->f);
                        break;
                }

        }

        return 0;
}

int introspect_finish(struct introspect *i, char **ret) {
        int r;

        assert(i);

        assert_se(set_interface_name(i, NULL) >= 0);

        fputs("</node>\n", i->f);

        r = fflush_and_check(i->f);
        if (r < 0)
                return r;

        i->f = safe_fclose(i->f);
        *ret = TAKE_PTR(i->introspection);

        return 0;
}

void introspect_free(struct introspect *i) {
        assert(i);

        /* Normally introspect_finish() does all the work, this is just a backup for error paths */

        safe_fclose(i->f);
        free(i->interface_name);
        free(i->introspection);
}
