/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;
typedef struct Link Link;

/* From ModemManager-enums.h */
typedef enum {
        MM_BEARER_IP_FAMILY_NONE   = 0,
        MM_BEARER_IP_FAMILY_IPV4   = 1 << 0,
        MM_BEARER_IP_FAMILY_IPV6   = 1 << 1,
        MM_BEARER_IP_FAMILY_IPV4V6 = 1 << 2,
        MM_BEARER_IP_FAMILY_ANY    = 0xFFFFFFFF,
} MMBearerIpFamily;

typedef enum {
        MM_BEARER_TYPE_UNKNOWN        = 0,
        MM_BEARER_TYPE_DEFAULT        = 1,
        MM_BEARER_TYPE_DEFAULT_ATTACH = 2,
        MM_BEARER_TYPE_DEDICATED      = 3,
} MMBearerType;

typedef enum {
        MM_MODEM_STATE_FAILED        = -1,
        MM_MODEM_STATE_UNKNOWN       = 0,
        MM_MODEM_STATE_INITIALIZING  = 1,
        MM_MODEM_STATE_LOCKED        = 2,
        MM_MODEM_STATE_DISABLED      = 3,
        MM_MODEM_STATE_DISABLING     = 4,
        MM_MODEM_STATE_ENABLING      = 5,
        MM_MODEM_STATE_ENABLED       = 6,
        MM_MODEM_STATE_SEARCHING     = 7,
        MM_MODEM_STATE_REGISTERED    = 8,
        MM_MODEM_STATE_DISCONNECTING = 9,
        MM_MODEM_STATE_CONNECTING    = 10,
        MM_MODEM_STATE_CONNECTED     = 11,
} MMModemState;

typedef enum { /*< underscore_name=mm_modem_state_failed_reason >*/
        MM_MODEM_STATE_FAILED_REASON_NONE                  = 0,
        MM_MODEM_STATE_FAILED_REASON_UNKNOWN               = 1,
        MM_MODEM_STATE_FAILED_REASON_SIM_MISSING           = 2,
        MM_MODEM_STATE_FAILED_REASON_SIM_ERROR             = 3,
        MM_MODEM_STATE_FAILED_REASON_UNKNOWN_CAPABILITIES  = 4,
        MM_MODEM_STATE_FAILED_REASON_ESIM_WITHOUT_PROFILES = 5,
        __MM_MODEM_STATE_FAILED_REASON_MAX                 = 6,
} MMModemStateFailedReason;

typedef enum {
        MM_BEARER_IP_METHOD_UNKNOWN = 0,
        MM_BEARER_IP_METHOD_PPP     = 1,
        MM_BEARER_IP_METHOD_STATIC  = 2,
        MM_BEARER_IP_METHOD_DHCP    = 3,
} MMBearerIpMethod;

typedef enum { /*< underscore_name=mm_modem_port_type >*/
        MM_MODEM_PORT_TYPE_UNKNOWN = 1,
        MM_MODEM_PORT_TYPE_NET     = 2,
        MM_MODEM_PORT_TYPE_AT      = 3,
        MM_MODEM_PORT_TYPE_QCDM    = 4,
        MM_MODEM_PORT_TYPE_GPS     = 5,
        MM_MODEM_PORT_TYPE_QMI     = 6,
        MM_MODEM_PORT_TYPE_MBIM    = 7,
        MM_MODEM_PORT_TYPE_AUDIO   = 8,
        MM_MODEM_PORT_TYPE_IGNORED = 9,
        MM_MODEM_PORT_TYPE_XMMRPC  = 10,
} MMModemPortType;

typedef enum { /*< underscore_name=mm_bearer_allowed_auth >*/
        MM_BEARER_ALLOWED_AUTH_UNKNOWN  = 0,
        /* bits 0..4 order match Ericsson device bitmap */
        MM_BEARER_ALLOWED_AUTH_NONE     = 1 << 0,
        MM_BEARER_ALLOWED_AUTH_PAP      = 1 << 1,
        MM_BEARER_ALLOWED_AUTH_CHAP     = 1 << 2,
        MM_BEARER_ALLOWED_AUTH_MSCHAP   = 1 << 3,
        MM_BEARER_ALLOWED_AUTH_MSCHAPV2 = 1 << 4,
        MM_BEARER_ALLOWED_AUTH_EAP      = 1 << 5,
} MMBearerAllowedAuth;

typedef enum {
        MODEM_RECONNECT_DONE,           /* No reconnect is required, e.g. connected. */
        MODEM_RECONNECT_SCHEDULED,      /* Reconnect is in progress. */
        MODEM_RECONNECT_WAITING,        /* Waiting for modem to recover. */
} ModemReconnectState;

int manager_notify_mm_bus_connected(Manager *manager);
int manager_match_mm_signals(Manager *manager);
int link_modem_reconfigure(Link *link);
