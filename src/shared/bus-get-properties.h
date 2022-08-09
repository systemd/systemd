/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "macro.h"

int bus_property_get_bool(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int bus_property_set_bool(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *error);
int bus_property_get_id128(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

#define bus_property_get_usec ((sd_bus_property_get_t) NULL)
#define bus_property_set_usec ((sd_bus_property_set_t) NULL)

assert_cc(sizeof(int) == sizeof(int32_t));
#define bus_property_get_int ((sd_bus_property_get_t) NULL)

assert_cc(sizeof(unsigned) == sizeof(uint32_t));
#define bus_property_get_unsigned ((sd_bus_property_get_t) NULL)

/* On 64bit machines we can use the default serializer for size_t and
 * friends, otherwise we need to cast this manually */
#if __SIZEOF_SIZE_T__ == 8
#define bus_property_get_size ((sd_bus_property_get_t) NULL)
#else
int bus_property_get_size(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
#endif

#if __SIZEOF_LONG__ == 8
#define bus_property_get_long ((sd_bus_property_get_t) NULL)
#define bus_property_get_ulong ((sd_bus_property_get_t) NULL)
#else
int bus_property_get_long(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int bus_property_get_ulong(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
#endif

/* uid_t and friends on Linux 32 bit. This means we can just use the
 * default serializer for 32bit unsigned, for serializing it, and map
 * it to NULL here */
assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define bus_property_get_uid ((sd_bus_property_get_t) NULL)

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define bus_property_get_gid ((sd_bus_property_get_t) NULL)

assert_cc(sizeof(pid_t) == sizeof(uint32_t));
#define bus_property_get_pid ((sd_bus_property_get_t) NULL)

assert_cc(sizeof(mode_t) == sizeof(uint32_t));
#define bus_property_get_mode ((sd_bus_property_get_t) NULL)

int bus_property_get_rlimit(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

#define BUS_DEFINE_PROPERTY_GET_GLOBAL(function, bus_type, val)         \
        int function(sd_bus *bus,                                       \
                     const char *path,                                  \
                     const char *interface,                             \
                     const char *property,                              \
                     sd_bus_message *reply,                             \
                     void *userdata,                                    \
                     sd_bus_error *error) {                             \
                                                                        \
                assert(bus);                                            \
                assert(reply);                                          \
                                                                        \
                return sd_bus_message_append(reply, bus_type, val);     \
        }

#define BUS_DEFINE_PROPERTY_GET2(function, bus_type, data_type, get1, get2) \
        int function(sd_bus *bus,                                       \
                     const char *path,                                  \
                     const char *interface,                             \
                     const char *property,                              \
                     sd_bus_message *reply,                             \
                     void *userdata,                                    \
                     sd_bus_error *error) {                             \
                                                                        \
                data_type *data = ASSERT_PTR(userdata);                 \
                                                                        \
                assert(bus);                                            \
                assert(reply);                                          \
                                                                        \
                return sd_bus_message_append(reply, bus_type,           \
                                             get2(get1(data)));         \
        }

#define ident(x) (x)
#define BUS_DEFINE_PROPERTY_GET(function, bus_type, data_type, get1) \
        BUS_DEFINE_PROPERTY_GET2(function, bus_type, data_type, get1, ident)

#define ref(x) (*(x))
#define BUS_DEFINE_PROPERTY_GET_REF(function, bus_type, data_type, get) \
        BUS_DEFINE_PROPERTY_GET2(function, bus_type, data_type, ref, get)

#define BUS_DEFINE_PROPERTY_GET_ENUM(function, name, type)              \
        BUS_DEFINE_PROPERTY_GET_REF(function, "s", type, name##_to_string)

#define BUS_PROPERTY_DUAL_TIMESTAMP(name, offset, flags) \
        SD_BUS_PROPERTY(name, "t", bus_property_get_usec, (offset) + offsetof(struct dual_timestamp, realtime), (flags)), \
        SD_BUS_PROPERTY(name "Monotonic", "t", bus_property_get_usec, (offset) + offsetof(struct dual_timestamp, monotonic), (flags))
