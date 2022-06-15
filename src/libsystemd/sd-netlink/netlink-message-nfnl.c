/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include "sd-netlink.h"

#include "netlink-internal.h"
#include "netlink-types.h"
#include "nfproto-util.h"

static int nft_message_new(sd_netlink *nfnl, sd_netlink_message **ret, int nfproto, uint16_t msg_type, uint16_t flags) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(nfproto_is_valid(nfproto), -EINVAL);
        assert_return(NFNL_MSG_TYPE(msg_type) == msg_type, -EINVAL);

        r = message_new(nfnl, &m, NFNL_SUBSYS_NFTABLES << 8 | msg_type);
        if (r < 0)
                return r;

        m->hdr->nlmsg_flags |= flags;

        *(struct nfgenmsg*) NLMSG_DATA(m->hdr) = (struct nfgenmsg) {
                .nfgen_family = nfproto,
                .version = NFNETLINK_V0,
                .res_id = nfnl->serial,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int nfnl_message_batch(sd_netlink *nfnl, sd_netlink_message **ret, uint16_t msg_type) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(NFNL_MSG_TYPE(msg_type) == msg_type, -EINVAL);

        r = message_new(nfnl, &m, NFNL_SUBSYS_NONE << 8 | msg_type);
        if (r < 0)
                return r;

        *(struct nfgenmsg*) NLMSG_DATA(m->hdr) = (struct nfgenmsg) {
                .nfgen_family = NFPROTO_UNSPEC,
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
                int nfproto,
                const char *table,
                const char *chain,
                const char *type,
                uint8_t hook,
                int prio) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_NEWCHAIN, NLM_F_CREATE);
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

int sd_nfnl_nft_message_new_table(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int nfproto,
                const char *table) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL);
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
                int nfproto,
                const char *table,
                const char *chain) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_NEWRULE, NLM_F_CREATE);
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
                int nfproto,
                const char *table,
                const char *set_name,
                uint32_t set_id,
                uint32_t klen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_NEWSET, NLM_F_CREATE);
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

int sd_nfnl_nft_message_new_setelems(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int add, /* boolean */
                int nfproto,
                const char *table,
                const char *set_name) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        if (add)
                r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_NEWSETELEM, NLM_F_CREATE);
        else
                r = nft_message_new(nfnl, &m, nfproto, NFT_MSG_DELSETELEM, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_TABLE, table);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_SET_ELEM_LIST_SET, set_name);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

static int nft_message_append_data(
                sd_netlink_message *m,
                uint16_t attr,
                const void *data,
                size_t data_len) {

        int r;

        r = sd_netlink_message_open_container(m, attr);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_data(m, NFTA_DATA_VALUE, data, data_len);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* attr */
}

int sd_nfnl_nft_message_append_setelem(
                sd_netlink_message *m,
                uint32_t index,
                const void *key,
                size_t key_len,
                const void *data,
                size_t data_len,
                uint32_t flags) {

        int r;

        r = sd_netlink_message_open_array(m, index);
        if (r < 0)
                return r;

        r = nft_message_append_data(m, NFTA_SET_ELEM_KEY, key, key_len);
        if (r < 0)
                goto cancel;

        if (data) {
                r = nft_message_append_data(m, NFTA_SET_ELEM_DATA, data, data_len);
                if (r < 0)
                        goto cancel;
        }

        if (flags != 0) {
                r = sd_netlink_message_append_u32(m, NFTA_SET_ELEM_FLAGS, htobe32(flags));
                if (r < 0)
                        goto cancel;
        }

        return sd_netlink_message_close_container(m); /* array */

cancel:
        (void) sd_netlink_message_cancel_array(m);
        return r;
}

int sd_nfnl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_NETFILTER);
}
