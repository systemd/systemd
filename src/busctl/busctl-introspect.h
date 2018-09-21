/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

typedef struct XMLIntrospectOps {
        int (*on_path)(const char *path, void *userdata);
        int (*on_interface)(const char *name, uint64_t flags, void *userdata);
        int (*on_method)(const char *interface, const char *name, const char *signature, const char *result, uint64_t flags, void *userdata);
        int (*on_signal)(const char *interface, const char *name, const char *signature, uint64_t flags, void *userdata);
        int (*on_property)(const char *interface, const char *name, const char *signature, bool writable, uint64_t flags, void *userdata);
} XMLIntrospectOps;

int parse_xml_introspect(const char *prefix, const char *xml, const XMLIntrospectOps *ops, void *userdata);
