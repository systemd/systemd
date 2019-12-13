/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "hashmap.h"
#include "macro.h"
#include "string-util.h"
#include "time-util.h"

typedef enum BusTransport {
        BUS_TRANSPORT_LOCAL,
        BUS_TRANSPORT_REMOTE,
        BUS_TRANSPORT_MACHINE,
        _BUS_TRANSPORT_MAX,
        _BUS_TRANSPORT_INVALID = -1
} BusTransport;

typedef int (*bus_property_set_t) (sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

struct bus_properties_map {
        const char *member;
        const char *signature;
        bus_property_set_t set;
        size_t offset;
};

enum {
        BUS_MAP_STRDUP          = 1 << 0, /* If set, each "s" message is duplicated. Thus, each pointer needs to be freed. */
        BUS_MAP_BOOLEAN_AS_BOOL = 1 << 1, /* If set, each "b" message is written to a bool pointer. If not set, "b" is written to a int pointer. */
};

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata);

int bus_message_map_all_properties(sd_bus_message *m, const struct bus_properties_map *map, unsigned flags, sd_bus_error *error, void *userdata);
int bus_map_all_properties(sd_bus *bus, const char *destination, const char *path, const struct bus_properties_map *map,
                           unsigned flags, sd_bus_error *error, sd_bus_message **reply, void *userdata);

int bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name);

typedef bool (*check_idle_t)(void *userdata);

int bus_event_loop_with_idle(sd_event *e, sd_bus *bus, const char *name, usec_t timeout, check_idle_t check_idle, void *userdata);

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error);

int bus_check_peercred(sd_bus *c);

int bus_test_polkit(sd_bus_message *call, int capability, const char *action, const char **details, uid_t good_user, bool *_challenge, sd_bus_error *e);

int bus_verify_polkit_async(sd_bus_message *call, int capability, const char *action, const char **details, bool interactive, uid_t good_user, Hashmap **registry, sd_bus_error *error);
void bus_verify_polkit_async_registry_free(Hashmap *registry);

int bus_connect_system_systemd(sd_bus **_bus);
int bus_connect_user_systemd(sd_bus **_bus);

int bus_connect_transport(BusTransport transport, const char *host, bool user, sd_bus **bus);
int bus_connect_transport_systemd(BusTransport transport, const char *host, bool user, sd_bus **bus);

typedef int (*bus_message_print_t) (const char *name, const char *expected_value, sd_bus_message *m, bool value, bool all);

int bus_print_property_value(const char *name, const char *expected_value, bool only_value, const char *value);
int bus_print_property_valuef(const char *name, const char *expected_value, bool only_value, const char *fmt, ...) _printf_(4,5);
int bus_message_print_all_properties(sd_bus_message *m, bus_message_print_t func, char **filter, bool value, bool all, Set **found_properties);
int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, bus_message_print_t func, char **filter, bool value, bool all, Set **found_properties);

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

#define bus_log_parse_error(r) \
        log_error_errno(r, "Failed to parse bus message: %m")

#define bus_log_create_error(r) \
        log_error_errno(r, "Failed to create bus message: %m")

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
                data_type *data = userdata;                             \
                                                                        \
                assert(bus);                                            \
                assert(reply);                                          \
                assert(data);                                           \
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

int bus_path_encode_unique(sd_bus *b, const char *prefix, const char *sender_id, const char *external_id, char **ret_path);
int bus_path_decode_unique(const char *path, const char *prefix, char **ret_sender, char **ret_external);

int bus_property_get_rlimit(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

int bus_track_add_name_many(sd_bus_track *t, char **l);

int bus_open_system_watch_bind_with_description(sd_bus **ret, const char *description);
static inline int bus_open_system_watch_bind(sd_bus **ret) {
        return bus_open_system_watch_bind_with_description(ret, NULL);
}

int bus_reply_pair_array(sd_bus_message *m, char **l);

extern const struct hash_ops bus_message_hash_ops;
