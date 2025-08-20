/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/net_tstamp.h>

#include "conf-parser.h"

typedef enum HwTsTxMode {
        HWTS_TX_MODE_OFF = HWTSTAMP_TX_OFF,
        HWTS_TX_MODE_ON = HWTSTAMP_TX_ON,
        HWTS_TX_MODE_ONESTEP_SYNC = HWTSTAMP_TX_ONESTEP_SYNC,
        HWTS_TX_MODE_ONESTEP_P2P = HWTSTAMP_TX_ONESTEP_P2P,
        _HWTS_TX_MODE_INVALID = -1,
} HwTsTxMode;

const char *hwts_tx_mode_to_string(HwTsTxMode type) _const_;
HwTsTxMode hwts_tx_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_hwts_tx_mode);

typedef enum HwTsRxMode {
        HWTS_RX_MODE_NONE = HWTSTAMP_FILTER_NONE,
        HWTS_RX_MODE_ALL = HWTSTAMP_FILTER_ALL,
        HWTS_RX_MODE_PTP_V1_L4_EVENT = HWTSTAMP_FILTER_PTP_V1_L4_EVENT,
        HWTS_RX_MODE_PTP_V1_L4_SYNC = HWTSTAMP_FILTER_PTP_V1_L4_SYNC,
        HWTS_RX_MODE_PTP_V1_L4_DELAY_REQ = HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ,
        HWTS_RX_MODE_PTP_V2_L4_EVENT = HWTSTAMP_FILTER_PTP_V2_L4_EVENT,
        HWTS_RX_MODE_PTP_V2_L4_SYNC = HWTSTAMP_FILTER_PTP_V2_L4_SYNC,
        HWTS_RX_MODE_PTP_V2_L4_DELAY_REQ = HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ,
        HWTS_RX_MODE_PTP_V2_L2_EVENT = HWTSTAMP_FILTER_PTP_V2_L2_EVENT,
        HWTS_RX_MODE_PTP_V2_L2_SYNC = HWTSTAMP_FILTER_PTP_V2_L2_SYNC,
        HWTS_RX_MODE_PTP_V2_L2_DELAY_REQ = HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ,
        HWTS_RX_MODE_PTP_V2_EVENT = HWTSTAMP_FILTER_PTP_V2_EVENT,
        HWTS_RX_MODE_PTP_V2_SYNC = HWTSTAMP_FILTER_PTP_V2_SYNC,
        HWTS_RX_MODE_PTP_V2_DELAY_REQ = HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
        HWTS_RX_MODE_NTP_ALL = HWTSTAMP_FILTER_NTP_ALL,
        _HWTS_RX_MODE_INVALID = -1,
} HwTsRxMode;

const char *hwts_rx_mode_to_string(HwTsRxMode type) _const_;
HwTsRxMode hwts_rx_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_hwts_rx_mode);

typedef struct Link Link;
int link_hwts_configure(Link *link);
