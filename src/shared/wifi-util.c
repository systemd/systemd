/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "string-table.h"
#include "string-util.h"
#include "wifi-util.h"

int wifi_get_interface(sd_netlink *genl, int ifindex, enum nl80211_iftype *ret_iftype, char **ret_ssid) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        _cleanup_free_ char *ssid = NULL;
        const char *family;
        uint32_t iftype;
        size_t len;
        int r;

        assert(genl);
        assert(ifindex > 0);

        r = sd_genl_message_new(genl, NL80211_GENL_NAME, NL80211_CMD_GET_INTERFACE, &m);
        if (r < 0)
                return log_debug_errno(r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_IFINDEX, ifindex);
        if (r < 0)
                return log_debug_errno(r, "Could not append NL80211_ATTR_IFINDEX attribute: %m");

        r = sd_netlink_call(genl, m, 0, &reply);
        if (r == -ENODEV) {
                /* For obsolete WEXT driver. */
                log_debug_errno(r, "Failed to request information about wifi interface %d. "
                                "The device doesn't seem to have nl80211 interface. Ignoring.",
                                ifindex);
                goto nodata;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to request information about wifi interface %d: %m", ifindex);
        if (!reply) {
                log_debug("No reply received to request for information about wifi interface %d, ignoring.", ifindex);
                goto nodata;
        }

        r = sd_netlink_message_get_errno(reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to get information about wifi interface %d: %m", ifindex);

        r = sd_genl_message_get_family_name(genl, reply, &family);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine genl family: %m");
        if (!streq(family, NL80211_GENL_NAME)) {
                log_debug("Received message of unexpected genl family '%s', ignoring.", family);
                goto nodata;
        }

        r = sd_netlink_message_read_u32(reply, NL80211_ATTR_IFTYPE, &iftype);
        if (r < 0)
                return log_debug_errno(r, "Failed to get NL80211_ATTR_IFTYPE attribute: %m");

        r = sd_netlink_message_read_data_suffix0(reply, NL80211_ATTR_SSID, &len, (void**) &ssid);
        if (r < 0 && r != -ENODATA)
                return log_debug_errno(r, "Failed to get NL80211_ATTR_SSID attribute: %m");
        if (r >= 0) {
                if (len == 0) {
                        log_debug("SSID has zero length, ignoring it.");
                        ssid = mfree(ssid);
                } else if (strlen_ptr(ssid) != len) {
                        log_debug("SSID contains NUL characters, ignoring it.");
                        ssid = mfree(ssid);
                }
        }

        if (ret_iftype)
                *ret_iftype = iftype;

        if (ret_ssid)
                *ret_ssid = TAKE_PTR(ssid);

        return 1;

nodata:
        if (ret_iftype)
                *ret_iftype = 0;
        if (ret_ssid)
                *ret_ssid = NULL;
        return 0;
}

int wifi_get_station(sd_netlink *genl, int ifindex, struct ether_addr *ret_bssid) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        const char *family;
        int r;

        assert(genl);
        assert(ifindex > 0);
        assert(ret_bssid);

        r = sd_genl_message_new(genl, NL80211_GENL_NAME, NL80211_CMD_GET_STATION, &m);
        if (r < 0)
                return log_debug_errno(r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_set_flags(m, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
        if (r < 0)
                return log_debug_errno(r, "Failed to set dump flag: %m");

        r = sd_netlink_message_append_u32(m, NL80211_ATTR_IFINDEX, ifindex);
        if (r < 0)
                return log_debug_errno(r, "Could not append NL80211_ATTR_IFINDEX attribute: %m");

        r = sd_netlink_call(genl, m, 0, &reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to request information about wifi station: %m");
        if (!reply) {
                log_debug("No reply received to request for information about wifi station, ignoring.");
                goto nodata;
        }

        r = sd_netlink_message_get_errno(reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to get information about wifi station: %m");

        r = sd_genl_message_get_family_name(genl, reply, &family);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine genl family: %m");
        if (!streq(family, NL80211_GENL_NAME)) {
                log_debug("Received message of unexpected genl family '%s', ignoring.", family);
                goto nodata;
        }

        r = sd_netlink_message_read_ether_addr(reply, NL80211_ATTR_MAC, ret_bssid);
        if (r == -ENODATA)
                goto nodata;
        if (r < 0)
                return log_debug_errno(r, "Failed to get NL80211_ATTR_MAC attribute: %m");

        return 1;

nodata:
        *ret_bssid = ETHER_ADDR_NULL;
        return 0;
}

static const char * const nl80211_iftype_table[NUM_NL80211_IFTYPES] = {
        [NL80211_IFTYPE_ADHOC]      = "ad-hoc",
        [NL80211_IFTYPE_STATION]    = "station",
        [NL80211_IFTYPE_AP]         = "ap",
        [NL80211_IFTYPE_AP_VLAN]    = "ap-vlan",
        [NL80211_IFTYPE_WDS]        = "wds",
        [NL80211_IFTYPE_MONITOR]    = "monitor",
        [NL80211_IFTYPE_MESH_POINT] = "mesh-point",
        [NL80211_IFTYPE_P2P_CLIENT] = "p2p-client",
        [NL80211_IFTYPE_P2P_GO]     = "p2p-go",
        [NL80211_IFTYPE_P2P_DEVICE] = "p2p-device",
        [NL80211_IFTYPE_OCB]        = "ocb",
        [NL80211_IFTYPE_NAN]        = "nan",
};

DEFINE_STRING_TABLE_LOOKUP(nl80211_iftype, enum nl80211_iftype);

static const char * const nl80211_cmd_table[__NL80211_CMD_AFTER_LAST] = {
        [NL80211_CMD_GET_WIPHY] = "get_wiphy",
        [NL80211_CMD_SET_WIPHY] = "set_wiphy",
        [NL80211_CMD_NEW_WIPHY] = "new_wiphy",
        [NL80211_CMD_DEL_WIPHY] = "del_wiphy",
        [NL80211_CMD_GET_INTERFACE] = "get_interface",
        [NL80211_CMD_SET_INTERFACE] = "set_interface",
        [NL80211_CMD_NEW_INTERFACE] = "new_interface",
        [NL80211_CMD_DEL_INTERFACE] = "del_interface",
        [NL80211_CMD_GET_KEY] = "get_key",
        [NL80211_CMD_SET_KEY] = "set_key",
        [NL80211_CMD_NEW_KEY] = "new_key",
        [NL80211_CMD_DEL_KEY] = "del_key",
        [NL80211_CMD_GET_BEACON] = "get_beacon",
        [NL80211_CMD_SET_BEACON] = "set_beacon",
        [NL80211_CMD_START_AP] = "start_ap",
        [NL80211_CMD_STOP_AP] = "stop_ap",
        [NL80211_CMD_GET_STATION] = "get_station",
        [NL80211_CMD_SET_STATION] = "set_station",
        [NL80211_CMD_NEW_STATION] = "new_station",
        [NL80211_CMD_DEL_STATION] = "del_station",
        [NL80211_CMD_GET_MPATH] = "get_mpath",
        [NL80211_CMD_SET_MPATH] = "set_mpath",
        [NL80211_CMD_NEW_MPATH] = "new_mpath",
        [NL80211_CMD_DEL_MPATH] = "del_mpath",
        [NL80211_CMD_SET_BSS] = "set_bss",
        [NL80211_CMD_SET_REG] = "set_reg",
        [NL80211_CMD_REQ_SET_REG] = "req_set_reg",
        [NL80211_CMD_GET_MESH_CONFIG] = "get_mesh_config",
        [NL80211_CMD_SET_MESH_CONFIG] = "set_mesh_config",
        [NL80211_CMD_SET_MGMT_EXTRA_IE] = "set_mgmt_extra_ie",
        [NL80211_CMD_GET_REG] = "get_reg",
        [NL80211_CMD_GET_SCAN] = "get_scan",
        [NL80211_CMD_TRIGGER_SCAN] = "trigger_scan",
        [NL80211_CMD_NEW_SCAN_RESULTS] = "new_scan_results",
        [NL80211_CMD_SCAN_ABORTED] = "scan_aborted",
        [NL80211_CMD_REG_CHANGE] = "reg_change",
        [NL80211_CMD_AUTHENTICATE] = "authenticate",
        [NL80211_CMD_ASSOCIATE] = "associate",
        [NL80211_CMD_DEAUTHENTICATE] = "deauthenticate",
        [NL80211_CMD_DISASSOCIATE] = "disassociate",
        [NL80211_CMD_MICHAEL_MIC_FAILURE] = "michael_mic_failure",
        [NL80211_CMD_REG_BEACON_HINT] = "reg_beacon_hint",
        [NL80211_CMD_JOIN_IBSS] = "join_ibss",
        [NL80211_CMD_LEAVE_IBSS] = "leave_ibss",
        [NL80211_CMD_TESTMODE] = "testmode",
        [NL80211_CMD_CONNECT] = "connect",
        [NL80211_CMD_ROAM] = "roam",
        [NL80211_CMD_DISCONNECT] = "disconnect",
        [NL80211_CMD_SET_WIPHY_NETNS] = "set_wiphy_netns",
        [NL80211_CMD_GET_SURVEY] = "get_survey",
        [NL80211_CMD_NEW_SURVEY_RESULTS] = "new_survey_results",
        [NL80211_CMD_SET_PMKSA] = "set_pmksa",
        [NL80211_CMD_DEL_PMKSA] = "del_pmksa",
        [NL80211_CMD_FLUSH_PMKSA] = "flush_pmksa",
        [NL80211_CMD_REMAIN_ON_CHANNEL] = "remain_on_channel",
        [NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL] = "cancel_remain_on_channel",
        [NL80211_CMD_SET_TX_BITRATE_MASK] = "set_tx_bitrate_mask",
        [NL80211_CMD_REGISTER_FRAME] = "register_frame",
        [NL80211_CMD_FRAME] = "frame",
        [NL80211_CMD_FRAME_TX_STATUS] = "frame_tx_status",
        [NL80211_CMD_SET_POWER_SAVE] = "set_power_save",
        [NL80211_CMD_GET_POWER_SAVE] = "get_power_save",
        [NL80211_CMD_SET_CQM] = "set_cqm",
        [NL80211_CMD_NOTIFY_CQM] = "notify_cqm",
        [NL80211_CMD_SET_CHANNEL] = "set_channel",
        [NL80211_CMD_SET_WDS_PEER] = "set_wds_peer",
        [NL80211_CMD_FRAME_WAIT_CANCEL] = "frame_wait_cancel",
        [NL80211_CMD_JOIN_MESH] = "join_mesh",
        [NL80211_CMD_LEAVE_MESH] = "leave_mesh",
        [NL80211_CMD_UNPROT_DEAUTHENTICATE] = "unprot_deauthenticate",
        [NL80211_CMD_UNPROT_DISASSOCIATE] = "unprot_disassociate",
        [NL80211_CMD_NEW_PEER_CANDIDATE] = "new_peer_candidate",
        [NL80211_CMD_GET_WOWLAN] = "get_wowlan",
        [NL80211_CMD_SET_WOWLAN] = "set_wowlan",
        [NL80211_CMD_START_SCHED_SCAN] = "start_sched_scan",
        [NL80211_CMD_STOP_SCHED_SCAN] = "stop_sched_scan",
        [NL80211_CMD_SCHED_SCAN_RESULTS] = "sched_scan_results",
        [NL80211_CMD_SCHED_SCAN_STOPPED] = "sched_scan_stopped",
        [NL80211_CMD_SET_REKEY_OFFLOAD] = "set_rekey_offload",
        [NL80211_CMD_PMKSA_CANDIDATE] = "pmksa_candidate",
        [NL80211_CMD_TDLS_OPER] = "tdls_oper",
        [NL80211_CMD_TDLS_MGMT] = "tdls_mgmt",
        [NL80211_CMD_UNEXPECTED_FRAME] = "unexpected_frame",
        [NL80211_CMD_PROBE_CLIENT] = "probe_client",
        [NL80211_CMD_REGISTER_BEACONS] = "register_beacons",
        [NL80211_CMD_UNEXPECTED_4ADDR_FRAME] = "unexpected_4addr_frame",
        [NL80211_CMD_SET_NOACK_MAP] = "set_noack_map",
        [NL80211_CMD_CH_SWITCH_NOTIFY] = "ch_switch_notify",
        [NL80211_CMD_START_P2P_DEVICE] = "start_p2p_device",
        [NL80211_CMD_STOP_P2P_DEVICE] = "stop_p2p_device",
        [NL80211_CMD_CONN_FAILED] = "conn_failed",
        [NL80211_CMD_SET_MCAST_RATE] = "set_mcast_rate",
        [NL80211_CMD_SET_MAC_ACL] = "set_mac_acl",
        [NL80211_CMD_RADAR_DETECT] = "radar_detect",
        [NL80211_CMD_GET_PROTOCOL_FEATURES] = "get_protocol_features",
        [NL80211_CMD_UPDATE_FT_IES] = "update_ft_ies",
        [NL80211_CMD_FT_EVENT] = "ft_event",
        [NL80211_CMD_CRIT_PROTOCOL_START] = "crit_protocol_start",
        [NL80211_CMD_CRIT_PROTOCOL_STOP] = "crit_protocol_stop",
        [NL80211_CMD_GET_COALESCE] = "get_coalesce",
        [NL80211_CMD_SET_COALESCE] = "set_coalesce",
        [NL80211_CMD_CHANNEL_SWITCH] = "channel_switch",
        [NL80211_CMD_VENDOR] = "vendor",
        [NL80211_CMD_SET_QOS_MAP] = "set_qos_map",
        [NL80211_CMD_ADD_TX_TS] = "add_tx_ts",
        [NL80211_CMD_DEL_TX_TS] = "del_tx_ts",
        [NL80211_CMD_GET_MPP] = "get_mpp",
        [NL80211_CMD_JOIN_OCB] = "join_ocb",
        [NL80211_CMD_LEAVE_OCB] = "leave_ocb",
        [NL80211_CMD_CH_SWITCH_STARTED_NOTIFY] = "ch_switch_started_notify",
        [NL80211_CMD_TDLS_CHANNEL_SWITCH] = "tdls_channel_switch",
        [NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH] = "tdls_cancel_channel_switch",
        [NL80211_CMD_WIPHY_REG_CHANGE] = "wiphy_reg_change",
        [NL80211_CMD_ABORT_SCAN] = "abort_scan",
        [NL80211_CMD_START_NAN] = "start_nan",
        [NL80211_CMD_STOP_NAN] = "stop_nan",
        [NL80211_CMD_ADD_NAN_FUNCTION] = "add_nan_function",
        [NL80211_CMD_DEL_NAN_FUNCTION] = "del_nan_function",
        [NL80211_CMD_CHANGE_NAN_CONFIG] = "change_nan_config",
        [NL80211_CMD_NAN_MATCH] = "nan_match",
        [NL80211_CMD_SET_MULTICAST_TO_UNICAST] = "set_multicast_to_unicast",
        [NL80211_CMD_UPDATE_CONNECT_PARAMS] = "update_connect_params",
        [NL80211_CMD_SET_PMK] = "set_pmk",
        [NL80211_CMD_DEL_PMK] = "del_pmk",
        [NL80211_CMD_PORT_AUTHORIZED] = "port_authorized",
        [NL80211_CMD_RELOAD_REGDB] = "reload_regdb",
        [NL80211_CMD_EXTERNAL_AUTH] = "external_auth",
        [NL80211_CMD_STA_OPMODE_CHANGED] = "sta_opmode_changed",
        [NL80211_CMD_CONTROL_PORT_FRAME] = "control_port_frame",
        [NL80211_CMD_GET_FTM_RESPONDER_STATS] = "get_ftm_responder_stats",
        [NL80211_CMD_PEER_MEASUREMENT_START] = "peer_measurement_start",
        [NL80211_CMD_PEER_MEASUREMENT_RESULT] = "peer_measurement_result",
        [NL80211_CMD_PEER_MEASUREMENT_COMPLETE] = "peer_measurement_complete",
        [NL80211_CMD_NOTIFY_RADAR] = "notify_radar",
        [NL80211_CMD_UPDATE_OWE_INFO] = "update_owe_info",
        [NL80211_CMD_PROBE_MESH_LINK] = "probe_mesh_link",
        [NL80211_CMD_SET_TID_CONFIG] = "set_tid_config",
        [NL80211_CMD_UNPROT_BEACON] = "unprot_beacon",
        [NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS] = "control_port_frame_tx_status",
        [NL80211_CMD_SET_SAR_SPECS] = "set_sar_specs",
        [NL80211_CMD_OBSS_COLOR_COLLISION] = "obss_color_collision",
        [NL80211_CMD_COLOR_CHANGE_REQUEST] = "color_change_request",
        [NL80211_CMD_COLOR_CHANGE_STARTED] = "color_change_started",
        [NL80211_CMD_COLOR_CHANGE_ABORTED] = "color_change_aborted",
        [NL80211_CMD_COLOR_CHANGE_COMPLETED] = "color_change_completed",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(nl80211_cmd, int);
