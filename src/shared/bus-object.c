/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-introspect.h"
#include "bus-object.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

int bus_add_implementation(sd_bus *bus, const BusObjectImplementation *impl, void *userdata) {
        int r;

        log_debug("Registering bus object implementation for path=%s iface=%s", impl->path, impl->interface);

        for (const sd_bus_vtable **p = impl->vtables; p && *p; p++) {
                r = sd_bus_add_object_vtable(bus, NULL,
                                             impl->path,
                                             impl->interface,
                                             *p,
                                             userdata);
                if (r < 0)
                        return log_error_errno(r, "Failed to register bus path %s with interface %s: %m",
                                               impl->path,
                                               impl->interface);
        }

        for (const BusObjectVtablePair *p = impl->fallback_vtables; p && p->vtable; p++) {
                r = sd_bus_add_fallback_vtable(bus, NULL,
                                               impl->path,
                                               impl->interface,
                                               p->vtable,
                                               p->object_find,
                                               userdata);
                if (r < 0)
                        return log_error_errno(r, "Failed to register bus path %s with interface %s: %m",
                                               impl->path,
                                               impl->interface);
        }

        if (impl->node_enumerator) {
                r = sd_bus_add_node_enumerator(bus, NULL,
                                               impl->path,
                                               impl->node_enumerator,
                                               userdata);
                if (r < 0)
                        return log_error_errno(r, "Failed to add node enumerator for %s: %m",
                                               impl->path);
        }

        if (impl->manager) {
                r = sd_bus_add_object_manager(bus, NULL, impl->path);
                if (r < 0)
                        return log_error_errno(r, "Failed to add object manager for %s: %m", impl->path);
        }

        for (size_t i = 0; impl->children && impl->children[i]; i++) {
                r = bus_add_implementation(bus, impl->children[i], userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const BusObjectImplementation* find_implementation(
                const char *pattern,
                const BusObjectImplementation* const* bus_objects) {

        for (size_t i = 0; bus_objects && bus_objects[i]; i++) {
                const BusObjectImplementation *impl = bus_objects[i];

                if (STR_IN_SET(pattern, impl->path, impl->interface))
                        return impl;

                impl = find_implementation(pattern, impl->children);
                if (impl)
                        return impl;
        }

        return NULL;
}

static int bus_introspect_implementation(
                struct introspect *intro,
                const BusObjectImplementation *impl) {
        int r;

        for (const sd_bus_vtable **p = impl->vtables; p && *p; p++) {
                r = introspect_write_interface(intro, impl->interface, *p);
                if (r < 0)
                        return log_error_errno(r, "Failed to write introspection data: %m");
        }

        for (const BusObjectVtablePair *p = impl->fallback_vtables; p && p->vtable; p++) {
                r = introspect_write_interface(intro, impl->interface, p->vtable);
                if (r < 0)
                        return log_error_errno(r, "Failed to write introspection data: %m");
        }

        return 0;
}

static void list_paths(
                FILE *out,
                const BusObjectImplementation* const* bus_objects) {

        for (size_t i = 0; bus_objects[i]; i++) {
                fprintf(out, "%s\t%s\n", bus_objects[i]->path, bus_objects[i]->interface);
                if (bus_objects[i]->children)
                        list_paths(out, bus_objects[i]->children);
        }
}

int bus_introspect_implementations(
                FILE *out,
                const char *pattern,
                const BusObjectImplementation* const* bus_objects) {

        const BusObjectImplementation *impl, *main_impl = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        if (streq(pattern, "list")) {
                list_paths(out, bus_objects);
                return 0;
        }

        struct introspect intro = {};
        bool is_interface = sd_bus_interface_name_is_valid(pattern);

        impl = find_implementation(pattern, bus_objects);
        if (!impl)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "%s %s not found",
                                       is_interface ? "Interface" : "Object path",
                                       pattern);

        /* We use trusted=false here to get all the @org.freedesktop.systemd1.Privileged annotations. */
        r = introspect_begin(&intro, false);
        if (r < 0)
                return log_error_errno(r, "Failed to write introspection data: %m");

        r = introspect_write_default_interfaces(&intro, impl->manager);
        if (r < 0)
                return log_error_errno(r, "Failed to write introspection data: %m");

        /* Check if there is a non-fallback path that applies to the given interface, also
         * print it. This is useful in the case of units: o.fd.systemd1.Service is declared
         * as a fallback vtable for o/fd/systemd1/unit, and we also want to print
         * o.fd.systemd1.Unit, which is the non-fallback implementation. */
        if (impl->fallback_vtables && is_interface)
                main_impl = find_implementation(impl->path, bus_objects);

        if (main_impl)
                bus_introspect_implementation(&intro, main_impl);

        if (impl != main_impl)
                bus_introspect_implementation(&intro, impl);

        _cleanup_ordered_set_free_ OrderedSet *nodes = NULL;

        for (size_t i = 0; impl->children && impl->children[i]; i++) {
                r = ordered_set_put_strdup(&nodes, impl->children[i]->path);
                if (r < 0)
                        return log_oom();
        }

        r = introspect_write_child_nodes(&intro, nodes, impl->path);
        if (r < 0)
                return r;

        r = introspect_finish(&intro, &s);
        if (r < 0)
                return log_error_errno(r, "Failed to write introspection data: %m");

        fputs(s, out);
        return 0;
}
