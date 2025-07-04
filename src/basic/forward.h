/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* IWYU pragma: always_keep */

#include <errno.h>              /* IWYU pragma: export */
#include <inttypes.h>           /* IWYU pragma: export */
#include <limits.h>             /* IWYU pragma: export */
#include <paths.h>              /* IWYU pragma: export */
#include <stdarg.h>             /* IWYU pragma: export */
#include <stdbool.h>            /* IWYU pragma: export */
#include <stddef.h>             /* IWYU pragma: export */
#include <stdint.h>             /* IWYU pragma: export */
#include <sys/types.h>          /* IWYU pragma: export */
#include <uchar.h>              /* IWYU pragma: export */

#include "assert-util.h"        /* IWYU pragma: export */
#include "cleanup-util.h"       /* IWYU pragma: export */
#include "macro.h"              /* IWYU pragma: export */

/* Generic types */

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

/* Libc/Linux forward declarations */

struct dirent;
struct ether_addr;
struct fiemap;
struct file_handle;
struct glob_t;
struct group;
struct icmp6_hdr;
struct in_addr;
struct in6_addr;
struct inotify_event;
struct iovec;
struct mount_attr;
struct msghdr;
struct passwd;
struct pollfd;
struct rlimit;
struct sgrp;
struct shadow;
struct signalfd_siginfo;
struct siphash;
struct sockaddr;
struct spwd;
struct stat;
struct statfs;
struct statx_timestamp;
struct statx;
struct termios;
struct tm;
struct ucred;

/* To forward declare FILE and DIR, we have to declare the internal struct names for them. Since these are
 * used for C++ symbol name mangling, they're effectively part of the ABI and won't actually change. */
typedef struct _IO_FILE FILE;
typedef struct __dirstream DIR;

/* 3rd-party library forward declarations */

enum bpf_map_type;

struct fdisk_context;
struct fdisk_table;
struct crypt_device;

/* basic/ forward declarations */

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);
typedef compare_func_t comparison_fn_t;
typedef int (*comparison_userdata_fn_t)(const void *, const void *, void *);

struct hash_ops;
struct hw_addr_data;
struct in_addr_data;
struct iovec_wrapper;
union in_addr_union;
union sockaddr_union;

typedef enum CGroupFlags CGroupFlags;
typedef enum CGroupMask CGroupMask;
typedef enum ChaseFlags ChaseFlags;
typedef enum ExtractFlags ExtractFlags;
typedef enum Glyph Glyph;
typedef enum ImageClass ImageClass;
typedef enum JobMode JobMode;
typedef enum RuntimeScope RuntimeScope;
typedef enum TimestampStyle TimestampStyle;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;

typedef struct Hashmap Hashmap;
typedef struct HashmapBase HashmapBase;
typedef struct IteratedCache IteratedCache;
typedef struct Iterator Iterator;
typedef struct OrderedHashmap OrderedHashmap;
typedef struct OrderedSet OrderedSet;
typedef struct Set Set;

typedef struct dual_timestamp dual_timestamp;
typedef struct triple_timestamp triple_timestamp;
typedef struct ConfFile ConfFile;
typedef struct LockFile LockFile;
typedef struct PidRef PidRef;
typedef struct Prioq Prioq;
typedef struct RateLimit RateLimit;
typedef struct SocketAddress SocketAddress;

/* libsystemd/ and libsystemd-network/ forward declarations */

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

enum ENUM_TYPE_S64(sd_json_format_flags_t);
enum ENUM_TYPE_S64(sd_json_dispatch_flags_t);
enum ENUM_TYPE_S64(sd_json_variant_type_t);
enum ENUM_TYPE_S64(sd_json_parse_flags_t);

typedef enum sd_json_format_flags_t sd_json_format_flags_t;
typedef enum sd_json_dispatch_flags_t sd_json_dispatch_flags_t;
typedef enum sd_json_variant_type_t sd_json_variant_type_t;
typedef enum sd_json_parse_flags_t sd_json_parse_flags_t;

typedef struct sd_json_variant sd_json_variant;

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_error_map sd_bus_error_map;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_track sd_bus_track;
typedef struct sd_bus_vtable sd_bus_vtable;

typedef int (*sd_bus_message_handler_t)(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_property_get_t)(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_property_set_t)(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *ret_error);
typedef int (*sd_bus_object_find_t)(sd_bus *bus, const char *path, const char *interface, void *userdata, void **ret_found, sd_bus_error *ret_error);
typedef int (*sd_bus_node_enumerator_t)(sd_bus *bus, const char *prefix, void *userdata, char ***ret_nodes, sd_bus_error *ret_error);
typedef int (*sd_bus_track_handler_t)(sd_bus_track *track, void *userdata);
typedef _sd_destroy_t sd_bus_destroy_t;

enum ENUM_TYPE_S64(sd_device_action_t);

typedef enum sd_device_action_t sd_device_action_t;

typedef struct sd_device sd_device;
typedef struct sd_device_enumerator sd_device_enumerator;
typedef struct sd_device_monitor sd_device_monitor;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;

typedef int (*sd_netlink_message_handler_t)(sd_netlink *nl, sd_netlink_message *m, void *userdata);
typedef _sd_destroy_t sd_netlink_destroy_t;

typedef struct sd_network_monitor sd_network_monitor;

enum ENUM_TYPE_S64(sd_dhcp_lease_server_type_t);
enum ENUM_TYPE_S64(sd_lldp_rx_event_t);
enum ENUM_TYPE_S64(sd_lldp_multicast_mode_t);
enum ENUM_TYPE_S64(sd_ndisc_event_t);

typedef enum sd_dhcp_lease_server_type_t sd_dhcp_lease_server_type_t;
typedef enum sd_lldp_rx_event_t sd_lldp_rx_event_t;
typedef enum sd_lldp_multicast_mode_t sd_lldp_multicast_mode_t;
typedef enum sd_ndisc_event_t sd_ndisc_event_t;

typedef struct sd_ipv4ll sd_ipv4ll;
typedef struct sd_dhcp_client sd_dhcp_client;
typedef struct sd_dhcp_lease sd_dhcp_lease;
typedef struct sd_dhcp_route sd_dhcp_route;
typedef struct sd_dns_resolver sd_dns_resolver;
typedef struct sd_dhcp_server sd_dhcp_server;
typedef struct sd_ndisc sd_ndisc;
typedef struct sd_radv sd_radv;
typedef struct sd_dhcp6_client sd_dhcp6_client;
typedef struct sd_dhcp6_lease sd_dhcp6_lease;
typedef struct sd_lldp_tx sd_lldp_tx;
typedef struct sd_lldp_rx sd_lldp_rx;
typedef struct sd_lldp_neighbor sd_lldp_neighbor;

typedef struct ICMP6Packet ICMP6Packet;

enum ENUM_TYPE_S64(sd_varlink_method_flags_t);
enum ENUM_TYPE_S64(sd_varlink_interface_flags_t);
enum ENUM_TYPE_S64(sd_varlink_symbol_type_t);
enum ENUM_TYPE_S64(sd_varlink_field_type_t);
enum ENUM_TYPE_S64(sd_varlink_field_direction_t);
enum ENUM_TYPE_S64(sd_varlink_field_flags_t);
enum ENUM_TYPE_S64(sd_varlink_idl_format_flags_t);
enum ENUM_TYPE_S64(sd_varlink_reply_flags_t);
enum ENUM_TYPE_S64(sd_varlink_server_flags_t);
enum ENUM_TYPE_S64(sd_varlink_invocation_flags_t);

typedef enum sd_varlink_method_flags_t sd_varlink_method_flags_t;
typedef enum sd_varlink_interface_flags_t sd_varlink_interface_flags_t;
typedef enum sd_varlink_symbol_type_t sd_varlink_symbol_type_t;
typedef enum sd_varlink_field_type_t sd_varlink_field_type_t;
typedef enum sd_varlink_field_direction_t sd_varlink_field_direction_t;
typedef enum sd_varlink_field_flags_t sd_varlink_field_flags_t;
typedef enum sd_varlink_idl_format_flags_t sd_varlink_idl_format_flags_t;
typedef enum sd_varlink_reply_flags_t sd_varlink_reply_flags_t;
typedef enum sd_varlink_server_flags_t sd_varlink_server_flags_t;
typedef enum sd_varlink_invocation_flags_t sd_varlink_invocation_flags_t;

typedef struct sd_varlink sd_varlink;
typedef struct sd_varlink_server sd_varlink_server;
typedef struct sd_varlink_field sd_varlink_field;
typedef struct sd_varlink_symbol sd_varlink_symbol;
typedef struct sd_varlink_interface sd_varlink_interface;

typedef struct sd_journal sd_journal;

typedef struct sd_resolve sd_resolve;
typedef struct sd_resolve_query sd_resolve_query;

typedef struct sd_hwdb sd_hwdb;

/* shared/ forward declarations */

typedef int (*copy_progress_bytes_t)(uint64_t n_bytes, void *userdata);
typedef int (*copy_progress_path_t)(const char *path, const struct stat *st, void *userdata);

struct local_address;
struct in_addr_prefix;
struct in_addr_full;

typedef enum AskPasswordFlags AskPasswordFlags;
typedef enum BootEntryTokenType BootEntryTokenType;
typedef enum BusPrintPropertyFlags BusPrintPropertyFlags;
typedef enum BusTransport BusTransport;
typedef enum CatFlags CatFlags;
typedef enum CertificateSourceType CertificateSourceType;
typedef enum DnsCacheMode DnsCacheMode;
typedef enum DnsOverTlsMode DnsOverTlsMode;
typedef enum DnssecMode DnssecMode;
typedef enum Fido2EnrollFlags Fido2EnrollFlags;
typedef enum KeySourceType KeySourceType;
typedef enum LabelFixFlags LabelFixFlags;
typedef enum MountInNamespaceFlags MountInNamespaceFlags;
typedef enum NamePolicy NamePolicy;
typedef enum OutputFlags OutputFlags;
typedef enum OutputMode OutputMode;
typedef enum PagerFlags PagerFlags;
typedef enum PatternCompileCase PatternCompileCase;
typedef enum RemoveFlags RemoveFlags;
typedef enum ResolveSupport ResolveSupport;
typedef enum TPM2Flags TPM2Flags;
typedef enum Tpm2Support Tpm2Support;
typedef enum Tpm2UserspaceEventType Tpm2UserspaceEventType;
typedef enum UnitFileFlags UnitFileFlags;
typedef enum UnitFilePresetMode UnitFilePresetMode;
typedef enum UnitFileState UnitFileState;
typedef enum UnitType UnitType;
typedef enum UserDBFlags UserDBFlags;
typedef enum UserRecordLoadFlags UserRecordLoadFlags;
typedef enum UserStorage UserStorage;

typedef struct Bitmap Bitmap;
typedef struct BPFProgram BPFProgram;
typedef struct BusObjectImplementation BusObjectImplementation;
typedef struct CalendarSpec CalendarSpec;
typedef struct Condition Condition;
typedef struct ConfigSection ConfigSection;
typedef struct ConfigTableItem ConfigTableItem;
typedef struct CPUSet CPUSet;
typedef struct FDSet FDSet;
typedef struct Fido2HmacSalt Fido2HmacSalt;
typedef struct FirewallContext FirewallContext;
typedef struct GroupRecord GroupRecord;
typedef struct Image Image;
typedef struct ImagePolicy ImagePolicy;
typedef struct InstallInfo InstallInfo;
typedef struct LookupPaths LookupPaths;
typedef struct LoopDevice LoopDevice;
typedef struct MachineBindUserContext MachineBindUserContext;
typedef struct MachineCredentialContext MachineCredentialContext;
typedef struct MountOptions MountOptions;
typedef struct OpenFile OpenFile;
typedef struct Pkcs11EncryptedKey Pkcs11EncryptedKey;
typedef struct Table Table;
typedef struct Tpm2Context Tpm2Context;
typedef struct Tpm2Handle Tpm2Handle;
typedef struct Tpm2PCRValue Tpm2PCRValue;
typedef struct UnitInfo UnitInfo;
typedef struct UserRecord UserRecord;
typedef struct VeritySettings VeritySettings;

/* Constants */

/* We duplicate various commonly used constants here so we can keep most static inline functions without
 * having to include the full header that provides these constants. */

#define AT_FDCWD                -100
#define AT_EMPTY_PATH           0x1000
#define AT_SYMLINK_FOLLOW       0x400
#define AT_SYMLINK_NOFOLLOW     0x100

#define MODE_INVALID            ((mode_t) -1)

#define UID_INVALID             ((uid_t) -1)
#define GID_INVALID             ((gid_t) -1)

#define USEC_INFINITY           ((usec_t) UINT64_MAX)
#define NSEC_INFINITY           ((nsec_t) UINT64_MAX)

/* MAX_ERRNO is defined as 4095 in linux/err.h. We use the same value here. */
#define ERRNO_MAX               4095
