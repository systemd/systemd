/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>                      // IWYU pragma: export
#include <stdarg.h>                     // IWYU pragma: export
#include <sys/types.h>                  // IWYU pragma: export
#include <uchar.h>                      // IWYU pragma: export

#include "assert-util.h"                // IWYU pragma: export
#include "forward-fundamental.h"        // IWYU pragma: export

struct stat;
struct statfs;
struct statx;
struct statx_timestamp;
struct siphash;
struct tm;
struct dirent;
struct msghdr;
struct glob_t;
struct pollfd;
struct file_handle;
struct rlimit;
struct termios;
struct passwd;
struct shadow;
struct spwd;
struct group;
struct sgrp;
union sockaddr_union;
struct inotify_event;
struct signalfd_siginfo;
struct in_addr;
struct in6_addr;
struct ether_addr;
struct ucred;
struct sockaddr;
struct icmp6_hdr;

/* To forward declare FILE and DIR, we have to declare the internal struct names for them. Since these are
 * used for C++ symbol name mangling, they're effectively part of the ABI and won't actually change. */
typedef struct _IO_FILE FILE;
typedef struct __dirstream DIR;
typedef __socklen_t socklen_t;

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);

typedef compare_func_t comparison_fn_t;

/* This is the same as glibc's internal __compar_d_fn_t type. glibc exports a public comparison_fn_t, for the
 * external type __compar_fn_t, but doesn't do anything similar for __compar_d_fn_t. Let's hence do that
 * ourselves, picking a name that is obvious, but likely enough to not clash with glibc's choice of naming if
 * they should ever add one. */
typedef int (*comparison_userdata_fn_t)(const void *, const void *, void *);

struct hash_ops;
struct iovec_wrapper;

/* The base type for all hashmap and set types. Many functions in the implementation take (HashmapBase*)
 * parameters and are run-time polymorphic, though the API is not meant to be polymorphic (do not call
 * underscore-prefixed functions directly). */
typedef struct HashmapBase HashmapBase;

/* Specific hashmap/set types */
typedef struct Hashmap Hashmap;               /* Maps keys to values */
typedef struct OrderedHashmap OrderedHashmap; /* Like Hashmap, but also remembers entry insertion order */
typedef struct Set Set;                       /* Stores just keys */
typedef struct OrderedSet OrderedSet;         /* Like Set, but also remembers entry insertion order */

typedef struct IteratedCache IteratedCache;   /* Caches the iterated order of one of the above */
typedef struct Iterator Iterator;

typedef struct Prioq Prioq;
typedef struct RateLimit RateLimit;
typedef struct PidRef PidRef;
typedef struct SocketAddress SocketAddress;

typedef enum JobMode JobMode;
typedef enum RuntimeScope RuntimeScope;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;

struct crypt_device;

typedef enum AskPasswordFlags AskPasswordFlags;
typedef struct FDSet FDSet;
typedef struct UserRecord UserRecord;
typedef enum UserRecordLoadFlags UserRecordLoadFlags;
typedef enum UserStorage UserStorage;
typedef struct Fido2HmacSalt Fido2HmacSalt;
typedef struct Pkcs11EncryptedKey Pkcs11EncryptedKey;
typedef struct GroupRecord GroupRecord;
typedef struct ImagePolicy ImagePolicy;
typedef struct MountOptions MountOptions;
typedef struct CPUSet CPUSet;
typedef enum NamePolicy NamePolicy;
typedef struct Condition Condition;
typedef struct Table Table;
typedef struct Image Image;
typedef struct FirewallContext FirewallContext;
typedef enum Fido2EnrollFlags Fido2EnrollFlags;
typedef struct LookupPaths LookupPaths;
typedef struct LoopDevice LoopDevice;
typedef struct Tpm2PCRValue Tpm2PCRValue;
struct local_address;
typedef struct BPFProgram BPFProgram;
typedef struct VeritySettings VeritySettings;
typedef struct OpenFile OpenFile;
typedef struct CalendarSpec CalendarSpec;
typedef enum PagerFlags PagerFlags;
typedef enum CertificateSourceType CertificateSourceType;
typedef enum KeySourceType KeySourceType;
typedef enum BootEntryTokenType BootEntryTokenType;
typedef enum CatFlags CatFlags;
typedef enum BusTransport BusTransport;

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

typedef unsigned long loadavg_t;

typedef struct dual_timestamp dual_timestamp;
typedef struct triple_timestamp triple_timestamp;

union in_addr_union;
struct in_addr_data;
struct in_addr_prefix;
struct hw_addr_data;

typedef void (*_sd_destroy_t)(void *userdata);

typedef union sd_id128 sd_id128_t;

typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;

typedef int (*sd_event_handler_t)(sd_event_source *s, void *userdata);
typedef int (*sd_event_io_handler_t)(sd_event_source *s, int fd, uint32_t revents, void *userdata);
typedef int (*sd_event_time_handler_t)(sd_event_source *s, uint64_t usec, void *userdata);
typedef int (*sd_event_signal_handler_t)(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata);
typedef int (*sd_event_inotify_handler_t)(sd_event_source *s, const struct inotify_event *event, void *userdata);
typedef _sd_destroy_t sd_event_destroy_t;

typedef struct sd_json_variant sd_json_variant;
typedef enum sd_json_format_flags_t sd_json_format_flags_t;
typedef enum sd_json_dispatch_flags_t sd_json_dispatch_flags_t;

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_error_map sd_bus_error_map;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_track sd_bus_track;
typedef struct sd_bus_vtable sd_bus_vtable;

typedef int (*sd_bus_message_handler_t)(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_property_get_t) (sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_property_set_t) (sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_object_find_t) (sd_bus *bus, const char *path, const char *interface, void *userdata, void **ret_found, sd_bus_error *ret_error);
typedef int (*sd_bus_node_enumerator_t) (sd_bus *bus, const char *prefix, void *userdata, char ***ret_nodes, sd_bus_error *ret_error);
typedef int (*sd_bus_track_handler_t) (sd_bus_track *track, void *userdata);
typedef _sd_destroy_t sd_bus_destroy_t;

typedef struct sd_device sd_device;
typedef struct sd_device_enumerator sd_device_enumerator;
typedef struct sd_device_monitor sd_device_monitor;
typedef enum sd_device_action_t sd_device_action_t;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;

typedef int (*sd_netlink_message_handler_t)(sd_netlink *nl, sd_netlink_message *m, void *userdata);
typedef _sd_destroy_t sd_netlink_destroy_t;

typedef struct sd_network_monitor sd_network_monitor;

typedef struct sd_ipv4ll sd_ipv4ll;
typedef struct sd_dhcp_client sd_dhcp_client;
typedef struct sd_dhcp_lease sd_dhcp_lease;
typedef struct sd_dhcp_route sd_dhcp_route;
typedef struct sd_dns_resolver sd_dns_resolver;
typedef struct sd_dhcp_server sd_dhcp_server;
typedef enum sd_dhcp_lease_server_type_t sd_dhcp_lease_server_type_t;
typedef struct sd_ndisc sd_ndisc;
typedef struct sd_radv sd_radv;
typedef struct sd_dhcp6_client sd_dhcp6_client;
typedef struct sd_dhcp6_lease sd_dhcp6_lease;
typedef struct sd_lldp_tx sd_lldp_tx;
typedef struct sd_lldp_rx sd_lldp_rx;
typedef struct sd_lldp_neighbor sd_lldp_neighbor;

typedef struct ICMP6Packet ICMP6Packet;

typedef struct sd_varlink sd_varlink;
typedef enum sd_varlink_method_flags_t sd_varlink_method_flags_t;
typedef struct sd_varlink_server sd_varlink_server;

typedef struct sd_varlink_field sd_varlink_field;
typedef struct sd_varlink_symbol sd_varlink_symbol;
typedef struct sd_varlink_interface sd_varlink_interface;

typedef struct sd_journal sd_journal;

typedef struct sd_resolve sd_resolve;
typedef struct sd_resolve_query sd_resolve_query;

typedef struct sd_hwdb sd_hwdb;

/* Argument list for parsers of specific configuration settings. */
#define CONFIG_PARSER_ARGUMENTS                 \
        const char *unit,                       \
        const char *filename,                   \
        unsigned line,                          \
        const char *section,                    \
        unsigned section_line,                  \
        const char *lvalue,                     \
        int ltype,                              \
        const char *rvalue,                     \
        void *data,                             \
        void *userdata

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(CONFIG_PARSER_ARGUMENTS);

/* A macro declaring a function prototype, following the typedef above, simply because it's so cumbersomely long
 * otherwise. (And current emacs gets irritatingly slow when editing files that contain lots of very long function
 * prototypes on the same screen…) */
#define CONFIG_PARSER_PROTOTYPE(name) int name(CONFIG_PARSER_ARGUMENTS)

typedef struct ConfigTableItem ConfigTableItem;
typedef struct ConfigSection ConfigSection;

#define AT_FDCWD                -100
#define AT_EMPTY_PATH           0x1000
#define AT_SYMLINK_FOLLOW       0x400
#define AT_SYMLINK_NOFOLLOW	0x100

#define MODE_INVALID ((mode_t) -1)

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define NSEC_INFINITY ((nsec_t) UINT64_MAX)

#define	EXIT_FAILURE	1
#define	EXIT_SUCCESS	0

/*
 * MAX_ERRNO is defined as 4095 in linux/err.h
 * We use the same value here.
 */
#define ERRNO_MAX 4095

/* strerror(3) says that glibc uses a maximum length of 1024 bytes. */
#define ERRNO_BUF_LEN 1024

#define free_and_replace_full(a, b, free_func)  \
        ({                                      \
                typeof(a)* _a = &(a);           \
                typeof(b)* _b = &(b);           \
                free_func(*_a);                 \
                *_a = *_b;                      \
                *_b = NULL;                     \
                0;                              \
        })

/* This is similar to free_and_replace_full(), but NULL is not assigned to 'b', and its reference counter is
 * increased. */
#define unref_and_replace_full(a, b, ref_func, unref_func)      \
        ({                                       \
                typeof(a)* _a = &(a);            \
                typeof(b) _b = ref_func(b);      \
                unref_func(*_a);                 \
                *_a = _b;                        \
                0;                               \
        })

#define _DEFINE_TRIVIAL_REF_FUNC(type, name, scope)             \
        scope type *name##_ref(type *p) {                       \
                if (!p)                                         \
                        return NULL;                            \
                                                                \
                /* For type check. */                           \
                unsigned *q = &p->n_ref;                        \
                assert(*q > 0);                                 \
                assert_se(*q < UINT_MAX);                       \
                                                                \
                (*q)++;                                         \
                return p;                                       \
        }

#define _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, scope) \
        scope type *name##_unref(type *p) {                      \
                if (!p)                                          \
                        return NULL;                             \
                                                                 \
                assert(p->n_ref > 0);                            \
                p->n_ref--;                                      \
                if (p->n_ref > 0)                                \
                        return NULL;                             \
                                                                 \
                return free_func(p);                             \
        }

#define DEFINE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name,)
#define DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name)     \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, static)
#define DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name)      \
        _DEFINE_TRIVIAL_REF_FUNC(type, name, _public_)

#define DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func,)
#define DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func)        \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, static)
#define DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func)         \
        _DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func, _public_)

#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PRIVATE_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PRIVATE_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(type, name, free_func)    \
        DEFINE_PUBLIC_TRIVIAL_REF_FUNC(type, name);                    \
        DEFINE_PUBLIC_TRIVIAL_UNREF_FUNC(type, name, free_func);

#define saturate_add(x, y, limit)                                       \
        ({                                                              \
                typeof(limit) _x = (x);                                 \
                typeof(limit) _y = (y);                                 \
                _x > (limit) || _y >= (limit) - _x ? (limit) : _x + _y; \
        })

static inline size_t size_add(size_t x, size_t y) {
        return saturate_add(x, y, SIZE_MAX);
}

#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))

/* Pointers range from NULL to POINTER_MAX */
#define POINTER_MAX ((void*) UINTPTR_MAX)

/* Returns the number of chars needed to format variables of the specified type as a decimal string. Adds in
 * extra space for a negative '-' prefix for signed types. Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                           \
        ((size_t) IS_SIGNED_INTEGER_TYPE(type) + 1U +                   \
            (sizeof(type) <= 1 ? 3U :                                   \
             sizeof(type) <= 2 ? 5U :                                   \
             sizeof(type) <= 4 ? 10U :                                  \
             sizeof(type) <= 8 ? (IS_SIGNED_INTEGER_TYPE(type) ? 19U : 20U) : sizeof(int[-2*(sizeof(type) > 8)])))
