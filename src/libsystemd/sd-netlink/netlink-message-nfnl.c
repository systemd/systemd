/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_addrlabel.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/nexthop.h>
#include <stdbool.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "format-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "socket-util.h"

static int nft_message_new(sd_netlink *nfnl, sd_netlink_message **ret, int family, uint16_t msg_type, uint16_t flags) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(nfnl, &m, NFNL_SUBSYS_NFTABLES << 8 | msg_type);
        if (r < 0)
                return r;

        m->hdr->nlmsg_flags |= flags;

        *(struct nfgenmsg*) NLMSG_DATA(m->hdr) = (struct nfgenmsg) {
                .nfgen_family = family,
                .version = NFNETLINK_V0,
                .res_id = nfnl->serial,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int nfnl_message_batch(sd_netlink *nfnl, sd_netlink_message **ret, uint16_t msg_type) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = message_new(nfnl, &m, NFNL_SUBSYS_NONE << 8 | msg_type);
        if (r < 0)
                return r;

        *(struct nfgenmsg*) NLMSG_DATA(m->hdr) = (struct nfgenmsg) {
                .nfgen_family = AF_UNSPEC,
                .version = NFNETLINK_V0,
                .res_id = NFNL_SUBSYS_NFTABLES,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

int sd_nfnl_message_batch_begin(sd_netlink *nfnl, sd_netlink_message **ret) {
        return nfnl_message_batch(nfnl, ret, NFNL_MSG_BATCH_BEGIN);
}

int sd_nfnl_message_batch_end(sd_netlink *nfnl, sd_netlink_message **ret) {
        return nfnl_message_batch(nfnl, ret, NFNL_MSG_BATCH_END);
}

int sd_nfnl_nft_message_new_basechain(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table,
                const char *chain,
                const char *type,
                uint8_t hook,
                int prio) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_NEWCHAIN, NLM_F_CREATE);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_CHAIN_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_CHAIN_NAME, chain);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_CHAIN_TYPE, type);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_CHAIN_HOOK);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_HOOK_HOOKNUM, htobe32(hook));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_HOOK_PRIORITY, htobe32(prio));
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

int sd_nfnl_nft_message_del_table(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_DELTABLE, NLM_F_CREATE);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_TABLE_NAME, table);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

int sd_nfnl_nft_message_new_table(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_TABLE_NAME, table);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

int sd_nfnl_nft_message_new_rule(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table,
                const char *chain) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_NEWRULE, NLM_F_CREATE);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_RULE_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_RULE_CHAIN, chain);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

int sd_nfnl_nft_message_new_set(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table,
                const char *set_name,
                uint32_t set_id,
                uint32_t klen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_NEWSET, NLM_F_CREATE);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_NAME, set_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_SET_ID, ++set_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_SET_KEY_LEN, htobe32(klen));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

int sd_nfnl_nft_message_new_setelems_begin(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table,
                const char *set_name) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_NEWSETELEM, NLM_F_CREATE);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_SET, set_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

int sd_nfnl_nft_message_del_setelems_begin(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *table,
                const char *set_name) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, family, NFT_MSG_DELSETELEM, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_SET, set_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

static int sd_nfnl_add_data(sd_netlink_message *m, uint16_t attr, const void *data, uint32_t dlen) {
        int r;

        r = sd_netlink_message_open_container(m, attr);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, NFTA_DATA_VALUE, data, dlen);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* attr */
}

int sd_nfnl_nft_message_add_setelem(
                sd_netlink_message *m,
                uint32_t num,
                const void *key,
                uint32_t klen,
                const void *data,
                uint32_t dlen) {

        int r;

        r = sd_netlink_message_open_array(m, num);
        if (r < 0)
                return r;

        r = sd_nfnl_add_data(m, NFTA_SET_ELEM_KEY, key, klen);
        if (r < 0)
                goto cancel;

        if (data) {
                r = sd_nfnl_add_data(m, NFTA_SET_ELEM_DATA, data, dlen);
                if (r < 0)
                        goto cancel;
        }

        return 0;

cancel:
        sd_netlink_message_cancel_array(m);
        return r;
}

int sd_nfnl_nft_message_add_setelem_end(sd_netlink_message *m) {
        return sd_netlink_message_close_container(m); /* NFTA_SET_ELEM_LIST_ELEMENTS */
}

int sd_nfnl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_NETFILTER);
}
