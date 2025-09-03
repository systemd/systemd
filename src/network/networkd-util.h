/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "network-util.h"
#include "networkd-forward.h"
#include "time-util.h"

typedef enum NetworkConfigSource {
        NETWORK_CONFIG_SOURCE_FOREIGN, /* configured by kernel */
        NETWORK_CONFIG_SOURCE_STATIC,
        NETWORK_CONFIG_SOURCE_IPV4LL,
        NETWORK_CONFIG_SOURCE_DHCP4,
        NETWORK_CONFIG_SOURCE_DHCP6,
        NETWORK_CONFIG_SOURCE_DHCP_PD,
        NETWORK_CONFIG_SOURCE_NDISC,
        NETWORK_CONFIG_SOURCE_RUNTIME, /* through D-Bus method */
        NETWORK_CONFIG_SOURCE_MODEM_MANAGER,
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
CONFIG_PARSER_PROTOTYPE(config_parse_ip_masquerade);
CONFIG_PARSER_PROTOTYPE(config_parse_mud_url);

DECLARE_STRING_TABLE_LOOKUP(network_config_source, NetworkConfigSource);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING_FALLBACK(network_config_state, NetworkConfigState);

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
        static inline bool name##_exists(const type *t) {               \
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
        static inline bool name##_is_requesting(const type *t) {        \
                assert(t);                                              \
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
        static inline bool name##_is_marked(const type *t) {            \
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

DECLARE_STRING_TABLE_LOOKUP(address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(link_local_address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP(routing_policy_rule_address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP(nexthop_address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP(duplicate_address_detection_address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_deprecated_address_family, AddressFamily);

DECLARE_STRING_TABLE_LOOKUP(dhcp_lease_server_type, sd_dhcp_lease_server_type_t);

bool link_should_mark_config(Link *link, bool only_static, NetworkConfigSource source, uint8_t protocol);

#define _log_link_message_full_errno(link, link_u, message, error_msg, length, level, level_u, error, error_u, format, ...) \
        ({                                                              \
                Link *link_u = (link);                                  \
                int level_u = (level);                                  \
                int error_u = (error);                                  \
                int length = 0;                                         \
                                                                        \
                const char *error_msg = NULL;                           \
                if (message)                                            \
                        length = sd_netlink_message_read_string(message, NLMSGERR_ATTR_MSG, &error_msg); \
                                                                        \
                error_msg && length > 0 ?                               \
                        log_link_full_errno(link_u, level_u, error_u, format ": %s%s %m", ##__VA_ARGS__, \
                                            error_msg, error_msg[length - 1] == '.' ? "" : ".") : \
                        log_link_full_errno(link_u, level_u, error_u, format ": %m", ##__VA_ARGS__); \
        })


#define log_link_message_full_errno(link, message, level, error, format, ...) \
        _log_link_message_full_errno(link, UNIQ_T(lnk, UNIQ), message, UNIQ_T(emsg, UNIQ), UNIQ_T(len, UNIQ), level, UNIQ_T(lvl, UNIQ), error, UNIQ_T(err, UNIQ), format, ##__VA_ARGS__)

#define log_link_message_error_errno(link, m, err, fmt, ...)   log_link_message_full_errno(link, m, LOG_ERR, err, fmt, ##__VA_ARGS__)
#define log_link_message_warning_errno(link, m, err, fmt, ...) log_link_message_full_errno(link, m, LOG_WARNING, err, fmt, ##__VA_ARGS__)
#define log_link_message_notice_errno(link, m, err, fmt, ...)  log_link_message_full_errno(link, m, LOG_NOTICE, err, fmt, ##__VA_ARGS__)
#define log_link_message_info_errno(link, m, err, fmt, ...)    log_link_message_full_errno(link, m, LOG_INFO, err, fmt, ##__VA_ARGS__)
#define log_link_message_debug_errno(link, m, err, fmt, ...)   log_link_message_full_errno(link, m, LOG_DEBUG, err, fmt, ##__VA_ARGS__)
#define log_message_full_errno(m, level, err, fmt, ...)        log_link_message_full_errno(NULL, m, level, err, fmt, ##__VA_ARGS__)
#define log_message_error_errno(m, err, fmt, ...)              log_message_full_errno(m, LOG_ERR, err, fmt, ##__VA_ARGS__)
#define log_message_warning_errno(m, err, fmt, ...)            log_message_full_errno(m, LOG_WARNING, err, fmt, ##__VA_ARGS__)
#define log_message_notice_errno(m, err, fmt, ...)             log_message_full_errno(m, LOG_NOTICE, err, fmt, ##__VA_ARGS__)
#define log_message_info_errno(m, err, fmt, ...)               log_message_full_errno(m, LOG_INFO, err, fmt, ##__VA_ARGS__)
#define log_message_debug_errno(m, err, fmt, ...)              log_message_full_errno(m, LOG_DEBUG, err, fmt, ##__VA_ARGS__)
