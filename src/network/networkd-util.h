/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-lease.h"
#include "sd-netlink.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "network-util.h"
#include "string-util.h"

typedef struct Link Link;

typedef enum NetworkConfigSource {
        NETWORK_CONFIG_SOURCE_FOREIGN, /* configured by kernel */
        NETWORK_CONFIG_SOURCE_STATIC,
        NETWORK_CONFIG_SOURCE_IPV4LL,
        NETWORK_CONFIG_SOURCE_DHCP4,
        NETWORK_CONFIG_SOURCE_DHCP6,
        NETWORK_CONFIG_SOURCE_DHCP_PD,
        NETWORK_CONFIG_SOURCE_NDISC,
        NETWORK_CONFIG_SOURCE_RUNTIME, /* through D-Bus method */
        _NETWORK_CONFIG_SOURCE_MAX,
        _NETWORK_CONFIG_SOURCE_INVALID = -EINVAL,
} NetworkConfigSource;

typedef enum NetworkConfigState {
        NETWORK_CONFIG_STATE_REQUESTING  = 1 << 0, /* request is queued */
        NETWORK_CONFIG_STATE_CONFIGURING = 1 << 1, /* e.g. address_configure() is called, but no response is received yet */
        NETWORK_CONFIG_STATE_CONFIGURED  = 1 << 2, /* e.g. address_configure() is called and received a response from kernel.
                                                    * Note that address may not be ready yet, so please use address_is_ready()
                                                    * to check whether the address can be usable or not. */
        NETWORK_CONFIG_STATE_MARKED      = 1 << 3, /* used GC'ing the old config */
        NETWORK_CONFIG_STATE_REMOVING    = 1 << 4, /* e.g. address_remove() is called, but no response is received yet */
} NetworkConfigState;

static inline usec_t sec_to_usec(uint32_t sec, usec_t timestamp_usec) {
        return
                sec == 0 ? 0 :
                sec == UINT32_MAX ? USEC_INFINITY :
                usec_add(timestamp_usec, sec * USEC_PER_SEC);
}

static inline usec_t sec16_to_usec(uint16_t sec, usec_t timestamp_usec) {
        return sec_to_usec(sec == UINT16_MAX ? UINT32_MAX : (uint32_t) sec, timestamp_usec);
}

static inline uint32_t usec_to_sec(usec_t usec, usec_t now_usec) {
        return MIN(DIV_ROUND_UP(usec_sub_unsigned(usec, now_usec), USEC_PER_SEC), UINT32_MAX);
}

CONFIG_PARSER_PROTOTYPE(config_parse_link_local_address_family);
CONFIG_PARSER_PROTOTYPE(config_parse_address_family_with_kernel);
CONFIG_PARSER_PROTOTYPE(config_parse_ip_masquerade);
CONFIG_PARSER_PROTOTYPE(config_parse_mud_url);

const char *network_config_source_to_string(NetworkConfigSource s) _const_;

int network_config_state_to_string_alloc(NetworkConfigState s, char **ret);

#define DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(type, name)               \
        static inline void name##_update_state(                         \
                        type *t,                                        \
                        NetworkConfigState mask,                        \
                        NetworkConfigState value) {                     \
                                                                        \
                assert(t);                                              \
                                                                        \
                t->state = (t->state & ~mask) | (value & mask);         \
        }                                                               \
        static inline bool name##_exists(type *t) {                     \
                assert(t);                                              \
                                                                        \
                if ((t->state & (NETWORK_CONFIG_STATE_CONFIGURING |     \
                                 NETWORK_CONFIG_STATE_CONFIGURED)) == 0) \
                        return false; /* Not assigned yet. */           \
                if (FLAGS_SET(t->state, NETWORK_CONFIG_STATE_REMOVING)) \
                        return false; /* Already removing. */           \
                return true;                                            \
        }                                                               \
        static inline void name##_enter_requesting(type *t) {           \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_REQUESTING,    \
                                    NETWORK_CONFIG_STATE_REQUESTING);   \
        }                                                               \
        static inline void name##_cancel_requesting(type *t) {          \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_REQUESTING,    \
                                    0);                                 \
        }                                                               \
        static inline bool name##_is_requesting(type *t) {              \
                return FLAGS_SET(t->state, NETWORK_CONFIG_STATE_REQUESTING); \
        }                                                               \
        static inline void name##_enter_configuring(type *t) {          \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_REQUESTING |   \
                                    NETWORK_CONFIG_STATE_CONFIGURING |  \
                                    NETWORK_CONFIG_STATE_REMOVING,      \
                                    NETWORK_CONFIG_STATE_CONFIGURING);  \
        }                                                               \
        static inline void name##_enter_configured(type *t) {           \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_CONFIGURING |  \
                                    NETWORK_CONFIG_STATE_CONFIGURED,    \
                                    NETWORK_CONFIG_STATE_CONFIGURED);   \
        }                                                               \
        static inline void name##_mark(type *t) {                       \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_MARKED,        \
                                    NETWORK_CONFIG_STATE_MARKED);       \
        }                                                               \
        static inline void name##_unmark(type *t) {                     \
                name##_update_state(t, NETWORK_CONFIG_STATE_MARKED, 0); \
        }                                                               \
        static inline bool name##_is_marked(type *t) {                  \
                assert(t);                                              \
                return FLAGS_SET(t->state, NETWORK_CONFIG_STATE_MARKED); \
        }                                                               \
        static inline void name##_enter_removing(type *t) {             \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_MARKED |       \
                                    NETWORK_CONFIG_STATE_REMOVING,      \
                                    NETWORK_CONFIG_STATE_REMOVING);     \
        }                                                               \
        static inline void name##_enter_removed(type *t) {              \
                name##_update_state(t,                                  \
                                    NETWORK_CONFIG_STATE_CONFIGURED |   \
                                    NETWORK_CONFIG_STATE_REMOVING,      \
                                    0);                                 \
        }

const char *address_family_to_string(AddressFamily b) _const_;
AddressFamily address_family_from_string(const char *s) _pure_;

AddressFamily link_local_address_family_from_string(const char *s) _pure_;

const char *routing_policy_rule_address_family_to_string(AddressFamily b) _const_;
AddressFamily routing_policy_rule_address_family_from_string(const char *s) _pure_;

const char *nexthop_address_family_to_string(AddressFamily b) _const_;
AddressFamily nexthop_address_family_from_string(const char *s) _pure_;

const char *duplicate_address_detection_address_family_to_string(AddressFamily b) _const_;
AddressFamily duplicate_address_detection_address_family_from_string(const char *s) _pure_;

AddressFamily dhcp_deprecated_address_family_from_string(const char *s) _pure_;

const char *dhcp_lease_server_type_to_string(sd_dhcp_lease_server_type_t t) _const_;
sd_dhcp_lease_server_type_t dhcp_lease_server_type_from_string(const char *s) _pure_;

int log_link_message_full_errno(Link *link, sd_netlink_message *m, int level, int err, const char *msg);
#define log_link_message_error_errno(link, m, err, msg)   log_link_message_full_errno(link, m, LOG_ERR, err, msg)
#define log_link_message_warning_errno(link, m, err, msg) log_link_message_full_errno(link, m, LOG_WARNING, err, msg)
#define log_link_message_notice_errno(link, m, err, msg)  log_link_message_full_errno(link, m, LOG_NOTICE, err, msg)
#define log_link_message_info_errno(link, m, err, msg)    log_link_message_full_errno(link, m, LOG_INFO, err, msg)
#define log_link_message_debug_errno(link, m, err, msg)   log_link_message_full_errno(link, m, LOG_DEBUG, err, msg)
#define log_message_full_errno(m, level, err, msg)        log_link_message_full_errno(NULL, m, level, err, msg)
#define log_message_error_errno(m, err, msg)              log_message_full_errno(m, LOG_ERR, err, msg)
#define log_message_warning_errno(m, err, msg)            log_message_full_errno(m, LOG_WARNING, err, msg)
#define log_message_notice_errno(m, err, msg)             log_message_full_errno(m, LOG_NOTICE, err, msg)
#define log_message_info_errno(m, err, msg)               log_message_full_errno(m, LOG_INFO, err, msg)
#define log_message_debug_errno(m, err, msg)              log_message_full_errno(m, LOG_DEBUG, err, msg)
