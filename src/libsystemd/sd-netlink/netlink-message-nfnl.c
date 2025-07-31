/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "iovec-util.h"
#include "log.h"
#include "netlink-internal.h"
#include "netlink-util.h"

bool nfproto_is_valid(int nfproto) {
        return IN_SET(nfproto,
                      NFPROTO_UNSPEC,
                      NFPROTO_INET,
                      NFPROTO_IPV4,
                      NFPROTO_ARP,
                      NFPROTO_NETDEV,
                      NFPROTO_BRIDGE,
                      NFPROTO_IPV6);
}

int sd_nfnl_message_new(sd_netlink *nfnl, sd_netlink_message **ret, int nfproto, uint16_t subsys, uint16_t msg_type, uint16_t flags) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(nfproto_is_valid(nfproto), -EINVAL);
        assert_return(NFNL_MSG_TYPE(msg_type) == msg_type, -EINVAL);

        r = message_new(nfnl, &m, subsys << 8 | msg_type, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return r;

        m->hdr->nlmsg_flags |= flags;

        *(struct nfgenmsg*) NLMSG_DATA(m->hdr) = (struct nfgenmsg) {
                .nfgen_family = nfproto,
                .version = NFNETLINK_V0,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int nfnl_message_set_res_id(sd_netlink_message *m, uint16_t res_id) {
        struct nfgenmsg *nfgen;

        assert(m);
        assert(m->hdr);

        nfgen = NLMSG_DATA(m->hdr);
        nfgen->res_id = htobe16(res_id);

        return 0;
}

static int nfnl_message_get_subsys(sd_netlink_message *m, uint16_t *ret) {
        uint16_t t;
        int r;

        assert(m);
        assert(ret);

        r = sd_netlink_message_get_type(m, &t);
        if (r < 0)
                return r;

        *ret = NFNL_SUBSYS_ID(t);
        return 0;
}

static int nfnl_message_new_batch(sd_netlink *nfnl, sd_netlink_message **ret, uint16_t subsys, uint16_t msg_type) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(NFNL_MSG_TYPE(msg_type) == msg_type, -EINVAL);

        r = sd_nfnl_message_new(nfnl, &m, NFPROTO_UNSPEC, NFNL_SUBSYS_NONE, msg_type, 0);
        if (r < 0)
                return r;

        r = nfnl_message_set_res_id(m, subsys);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

int sd_nfnl_send_batch(
                sd_netlink *nfnl,
                sd_netlink_message **messages,
                size_t n_messages,
                uint32_t **ret_serials) {

        /* iovs refs batch_begin and batch_end, hence, free iovs first, then free batch_begin and batch_end. */
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *batch_begin = NULL, *batch_end = NULL;
        _cleanup_free_ struct iovec *iovs = NULL;
        _cleanup_free_ uint32_t *serials = NULL;
        uint16_t subsys;
        ssize_t k;
        size_t c = 0;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(!netlink_pid_changed(nfnl), -ECHILD);
        assert_return(messages, -EINVAL);
        assert_return(n_messages > 0, -EINVAL);

        iovs = new(struct iovec, n_messages + 2);
        if (!iovs)
                return -ENOMEM;

        if (ret_serials) {
                serials = new(uint32_t, n_messages);
                if (!serials)
                        return -ENOMEM;
        }

        r = nfnl_message_get_subsys(messages[0], &subsys);
        if (r < 0)
                return r;

        r = nfnl_message_new_batch(nfnl, &batch_begin, subsys, NFNL_MSG_BATCH_BEGIN);
        if (r < 0)
                return r;

        netlink_seal_message(nfnl, batch_begin);
        iovs[c++] = IOVEC_MAKE(batch_begin->hdr, batch_begin->hdr->nlmsg_len);

        for (size_t i = 0; i < n_messages; i++) {
                uint16_t s;

                r = nfnl_message_get_subsys(messages[i], &s);
                if (r < 0)
                        return r;

                if (s != subsys)
                        return -EINVAL;

                netlink_seal_message(nfnl, messages[i]);
                if (serials)
                        serials[i] = message_get_serial(messages[i]);

                /* It seems that the kernel accepts an arbitrary number. Let's set the lower 16 bits of the
                 * serial of the first message. */
                nfnl_message_set_res_id(messages[i], (uint16_t) (message_get_serial(batch_begin) & UINT16_MAX));

                iovs[c++] = IOVEC_MAKE(messages[i]->hdr, messages[i]->hdr->nlmsg_len);
        }

        r = nfnl_message_new_batch(nfnl, &batch_end, subsys, NFNL_MSG_BATCH_END);
        if (r < 0)
                return r;

        netlink_seal_message(nfnl, batch_end);
        iovs[c++] = IOVEC_MAKE(batch_end->hdr, batch_end->hdr->nlmsg_len);

        assert(c == n_messages + 2);
        k = writev(nfnl->fd, iovs, n_messages + 2);
        if (k < 0)
                return -errno;

        if (ret_serials)
                *ret_serials = TAKE_PTR(serials);

        return 0;
}

int sd_nfnl_call_batch(
                sd_netlink *nfnl,
                sd_netlink_message **messages,
                size_t n_messages,
                uint64_t usec,
                sd_netlink_message ***ret_messages) {

        _cleanup_free_ sd_netlink_message **replies = NULL;
        _cleanup_free_ uint32_t *serials = NULL;
        int r;

        assert_return(nfnl, -EINVAL);
        assert_return(!netlink_pid_changed(nfnl), -ECHILD);
        assert_return(messages, -EINVAL);
        assert_return(n_messages > 0, -EINVAL);

        if (ret_messages) {
                replies = new0(sd_netlink_message*, n_messages);
                if (!replies)
                        return -ENOMEM;
        }

        r = sd_nfnl_send_batch(nfnl, messages, n_messages, &serials);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n_messages; i++)
                RET_GATHER(r,
                           sd_netlink_read(nfnl, serials[i], usec, ret_messages ? replies + i : NULL));
        if (r < 0)
                return r;

        if (ret_messages)
                *ret_messages = TAKE_PTR(replies);

        return 0;
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

        r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN, NLM_F_CREATE);
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

        r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL);
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

        r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE, NLM_F_CREATE);
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

        r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWSET, NLM_F_CREATE);
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
                r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWSETELEM, NLM_F_CREATE);
        else
                r = sd_nfnl_message_new(nfnl, &m, nfproto, NFNL_SUBSYS_NFTABLES, NFT_MSG_DELSETELEM, 0);
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

        r = sd_netlink_message_append_container_data(m, NFTA_SET_ELEM_KEY, NFTA_DATA_VALUE, key, key_len);
        if (r < 0)
                goto cancel;

        if (data) {
                r = sd_netlink_message_append_container_data(m, NFTA_SET_ELEM_DATA, NFTA_DATA_VALUE, data, data_len);
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
