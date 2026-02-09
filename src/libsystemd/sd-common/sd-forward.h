/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* IWYU pragma: always_keep */

#include "basic-forward.h"            /* IWYU pragma: export */

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

typedef int (*sd_varlink_method_t)(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

typedef struct sd_journal sd_journal;

typedef struct sd_resolve sd_resolve;
typedef struct sd_resolve_query sd_resolve_query;

typedef struct sd_hwdb sd_hwdb;
