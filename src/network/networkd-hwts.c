/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "fd-util.h"
#include "log.h"
#include "networkd-hwts.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "string-table.h"

static const char *const hwts_tx_mode_table[] = {
        [HWTS_TX_MODE_OFF] = "off",
        [HWTS_TX_MODE_ON] = "on",
        [HWTS_TX_MODE_ONESTEP_SYNC] = "onestep-sync",
        [HWTS_TX_MODE_ONESTEP_P2P] = "onestep-p2p",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(hwts_tx_mode, HwTsTxMode, HWTS_TX_MODE_ON);
DEFINE_CONFIG_PARSE_ENUM(
        config_parse_hwts_tx_mode, hwts_tx_mode, HwTsTxMode, "Failed to parse TransmitMode= setting.");

static const char *const hwts_rx_mode_table[] = {
        [HWTS_RX_MODE_NONE] = "none",
        [HWTS_RX_MODE_ALL] = "all",
        [HWTS_RX_MODE_PTP_V1_L4_EVENT] = "ptpv1-l4-event",
        [HWTS_RX_MODE_PTP_V1_L4_SYNC] = "ptpv1-l4-sync",
        [HWTS_RX_MODE_PTP_V1_L4_DELAY_REQ] = "ptpv1-l4-delay-req",
        [HWTS_RX_MODE_PTP_V2_L4_EVENT] = "ptpv2-l4-even",
        [HWTS_RX_MODE_PTP_V2_L4_SYNC] = "ptpv2-l4-sync",
        [HWTS_RX_MODE_PTP_V2_L4_DELAY_REQ] = "ptpv2-l4-delay-req",
        [HWTS_RX_MODE_PTP_V2_L2_EVENT] = "ptpv2-l2-event",
        [HWTS_RX_MODE_PTP_V2_L2_SYNC] = "ptpv2-l2-sync",
        [HWTS_RX_MODE_PTP_V2_L2_DELAY_REQ] = "ptpv2-l2-delay-req",
        [HWTS_RX_MODE_PTP_V2_EVENT] = "ptpv2-event",
        [HWTS_RX_MODE_PTP_V2_SYNC] = "ptpv2-sync",
        [HWTS_RX_MODE_PTP_V2_DELAY_REQ] = "ptpv2-delay-req",
        [HWTS_RX_MODE_NTP_ALL] = "ntp-all",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(hwts_rx_mode, HwTsRxMode, HWTS_RX_MODE_ALL);
DEFINE_CONFIG_PARSE_ENUM(
        config_parse_hwts_rx_mode, hwts_rx_mode, HwTsRxMode, "Failed to parse ReceiveMode= setting.");

int link_hwts_configure(Link *link) {
        struct hwtstamp_config cfg = { 0 };
        struct ifreq ifreq = { 0 };
        _cleanup_close_ int fd = -1;
        bool use_default;
        int rx, tx;

        assert(link && link->network);

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        if (fd < 0) {
                log_link_error_errno(link, errno, "Failed to create socket");
                return -errno;
        }

        rx = link->network->hwts_rx_mode;
        tx = link->network->hwts_tx_mode;
        use_default = (rx == _HWTS_RX_MODE_INVALID) && (tx == _HWTS_TX_MODE_INVALID);

        /* This dance is required to ensure that we disable hardware
         * time-stamping when requested to do so with a reload */
        if (rx == _HWTS_TX_MODE_INVALID)
                rx = 0;
        if (tx == _HWTS_TX_MODE_INVALID)
                tx = 0;

        cfg.flags = 0;
        cfg.rx_filter = rx;
        cfg.tx_type = tx;

        strncpy(ifreq.ifr_name, link->ifname, sizeof(ifreq.ifr_name) - 1);
        ifreq.ifr_data = (char *) &cfg;

        if (ioctl(fd, SIOCSHWTSTAMP, &ifreq) != 0) {
                if (!use_default) {
                        log_link_error_errno(link, errno, "Failed to configure hardware timestamping");
                        return -errno;
                }
        }

        if (!use_default)
                log_link_info(
                        link, "Hardware timestamping configured, rx: %d, tx: %d", cfg.rx_filter, cfg.tx_type);
        return 0;
}
