/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "fd-util.h"
#include "iovec-util.h"
#include "memory-util.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "strv.h"

static int parse_newlink_message(
                  sd_netlink_message *message,
                  char **ret_name,
                  char ***ret_altnames) {

        _cleanup_strv_free_ char **altnames = NULL;
        int r, ifindex;

        assert(message);

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0)
                return r;
        if (type != RTM_NEWLINK)
                return -EPROTO;

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return r;
        if (ifindex <= 0)
                return -EPROTO;

        if (ret_altnames) {
                r = sd_netlink_message_read_strv(message, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &altnames);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        if (ret_name) {
                r = sd_netlink_message_read_string_strdup(message, IFLA_IFNAME, ret_name);
                if (r < 0)
                        return r;
        }

        if (ret_altnames)
                *ret_altnames = TAKE_PTR(altnames);

        return ifindex;
}

int rtnl_get_ifname_full(sd_netlink **rtnl, int ifindex, char **ret_name, char ***ret_altnames) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *our_rtnl = NULL;
        int r;

        assert(ifindex > 0);

        /* This is similar to if_indextoname(), but also optionally provides alternative names. */

        if (!rtnl)
                rtnl = &our_rtnl;
        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_GETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, &reply);
        if (r < 0)
                return r;

        return parse_newlink_message(reply, ret_name, ret_altnames);
}

int rtnl_resolve_ifname_full(
                  sd_netlink **rtnl,
                  ResolveInterfaceNameFlag flags,
                  const char *name,
                  char **ret_name,
                  char ***ret_altnames) {

        _cleanup_(sd_netlink_unrefp) sd_netlink *our_rtnl = NULL;
        int r;

        assert(name);
        assert(flags > 0);

        /* This is similar to if_nametoindex(), but also resolves alternative names and decimal formatted
         * ifindex too. Returns ifindex, and optionally provides the main interface name and alternative
         * names. */

        if (!rtnl)
                rtnl = &our_rtnl;
        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        /* First, use IFLA_IFNAME */
        if (FLAGS_SET(flags, RESOLVE_IFNAME_MAIN) && ifname_valid(name)) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;

                r = sd_rtnl_message_new_link(*rtnl, &message, RTM_GETLINK, 0);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_string(message, IFLA_IFNAME, name);
                if (r < 0)
                        return r;

                r = sd_netlink_call(*rtnl, message, 0, &reply);
                if (r >= 0)
                        return parse_newlink_message(reply, ret_name, ret_altnames);
                if (r != -ENODEV)
                        return r;
        }

        /* Next, try IFLA_ALT_IFNAME */
        if (FLAGS_SET(flags, RESOLVE_IFNAME_ALTERNATIVE) &&
            ifname_valid_full(name, IFNAME_VALID_ALTERNATIVE)) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;

                r = sd_rtnl_message_new_link(*rtnl, &message, RTM_GETLINK, 0);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_string(message, IFLA_ALT_IFNAME, name);
                if (r < 0)
                        return r;

                r = sd_netlink_call(*rtnl, message, 0, &reply);
                if (r >= 0)
                        return parse_newlink_message(reply, ret_name, ret_altnames);
                /* The kernels older than 76c9ac0ee878f6693d398d3a95ccaf85e1f597a6 (v5.5) return -EINVAL. */
                if (!IN_SET(r, -ENODEV, -EINVAL))
                        return r;
        }

        /* Finally, assume the string is a decimal formatted ifindex. */
        if (FLAGS_SET(flags, RESOLVE_IFNAME_NUMERIC)) {
                int ifindex;

                ifindex = parse_ifindex(name);
                if (ifindex <= 0)
                        return -ENODEV;

                return rtnl_get_ifname_full(rtnl, ifindex, ret_name, ret_altnames);
        }

        return -ENODEV;
}

static int set_link_name(sd_netlink **rtnl, int ifindex, const char *name) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);
        assert(name);

        /* Assign the requested name. */

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_SETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(message, IFLA_IFNAME, name);
        if (r < 0)
                return r;

        return sd_netlink_call(*rtnl, message, 0, NULL);
}

int rtnl_rename_link(sd_netlink **rtnl, const char *orig_name, const char *new_name) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *our_rtnl = NULL;
        int r, ifindex;

        assert(orig_name);
        assert(new_name);

        /* This does not check alternative names. Callers must check the requested name is not used as an
         * alternative name. */

        if (streq(orig_name, new_name))
                return 0;

        if (!ifname_valid(new_name))
                return -EINVAL;

        if (!rtnl)
                rtnl = &our_rtnl;
        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        ifindex = rtnl_resolve_ifname(rtnl, orig_name);
        if (ifindex < 0)
                return ifindex;

        return set_link_name(rtnl, ifindex, new_name);
}

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name, char* const *alternative_names) {
        _cleanup_strv_free_ char **original_altnames = NULL, **new_altnames = NULL;
        bool altname_deleted = false;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        if (isempty(name) && strv_isempty(alternative_names))
                return 0;

        if (name && !ifname_valid(name))
                return -EINVAL;

        /* If the requested name is already assigned as an alternative name, then first drop it. */
        r = rtnl_get_link_alternative_names(rtnl, ifindex, &original_altnames);
        if (r < 0)
                log_debug_errno(r, "Failed to get alternative names on network interface %i, ignoring: %m",
                                ifindex);

        if (name) {
                if (strv_contains(original_altnames, name)) {
                        r = rtnl_delete_link_alternative_names(rtnl, ifindex, STRV_MAKE(name));
                        if (r < 0)
                                return log_debug_errno(r, "Failed to remove '%s' from alternative names on network interface %i: %m",
                                                       name, ifindex);

                        altname_deleted = true;
                }

                r = set_link_name(rtnl, ifindex, name);
                if (r < 0)
                        goto fail;
        }

        /* Filter out already assigned names from requested alternative names. Also, dedup the request. */
        STRV_FOREACH(a, alternative_names) {
                if (streq_ptr(name, *a))
                        continue;

                if (strv_contains(original_altnames, *a))
                        continue;

                if (strv_contains(new_altnames, *a))
                        continue;

                if (!ifname_valid_full(*a, IFNAME_VALID_ALTERNATIVE))
                        continue;

                r = strv_extend(&new_altnames, *a);
                if (r < 0)
                        return r;
        }

        strv_sort(new_altnames);

        /* Finally, assign alternative names. */
        r = rtnl_set_link_alternative_names(rtnl, ifindex, new_altnames);
        if (r == -EEXIST) /* Already assigned to another interface? */
                STRV_FOREACH(a, new_altnames) {
                        r = rtnl_set_link_alternative_names(rtnl, ifindex, STRV_MAKE(*a));
                        if (r < 0)
                                log_debug_errno(r, "Failed to assign '%s' as an alternative name on network interface %i, ignoring: %m",
                                                *a, ifindex);
                }
        else if (r < 0)
                log_debug_errno(r, "Failed to assign alternative names on network interface %i, ignoring: %m", ifindex);

        return 0;

fail:
        if (altname_deleted) {
                int q = rtnl_set_link_alternative_names(rtnl, ifindex, STRV_MAKE(name));
                if (q < 0)
                        log_debug_errno(q, "Failed to restore '%s' as an alternative name on network interface %i, ignoring: %m",
                                        name, ifindex);
        }

        return r;
}

int rtnl_set_link_properties(
                sd_netlink **rtnl,
                int ifindex,
                const char *alias,
                const struct hw_addr_data *hw_addr,
                uint32_t txqueues,
                uint32_t rxqueues,
                uint32_t txqueuelen,
                uint32_t mtu,
                uint32_t gso_max_size,
                size_t gso_max_segments) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        if (!alias &&
            (!hw_addr || hw_addr->length == 0) &&
            txqueues == 0 &&
            rxqueues == 0 &&
            txqueuelen == UINT32_MAX &&
            mtu == 0 &&
            gso_max_size == 0 &&
            gso_max_segments == 0)
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_SETLINK, ifindex);
        if (r < 0)
                return r;

        if (alias) {
                r = sd_netlink_message_append_string(message, IFLA_IFALIAS, alias);
                if (r < 0)
                        return r;
        }

        if (hw_addr && hw_addr->length > 0) {
                r = netlink_message_append_hw_addr(message, IFLA_ADDRESS, hw_addr);
                if (r < 0)
                        return r;
        }

        if (txqueues > 0) {
                r = sd_netlink_message_append_u32(message, IFLA_NUM_TX_QUEUES, txqueues);
                if (r < 0)
                        return r;
        }

        if (rxqueues > 0) {
                r = sd_netlink_message_append_u32(message, IFLA_NUM_RX_QUEUES, rxqueues);
                if (r < 0)
                        return r;
        }

        if (txqueuelen < UINT32_MAX) {
                r = sd_netlink_message_append_u32(message, IFLA_TXQLEN, txqueuelen);
                if (r < 0)
                        return r;
        }

        if (mtu != 0) {
                r = sd_netlink_message_append_u32(message, IFLA_MTU, mtu);
                if (r < 0)
                        return r;
        }

        if (gso_max_size > 0) {
                r = sd_netlink_message_append_u32(message, IFLA_GSO_MAX_SIZE, gso_max_size);
                if (r < 0)
                        return r;
        }

        if (gso_max_segments > 0) {
                r = sd_netlink_message_append_u32(message, IFLA_GSO_MAX_SEGS, gso_max_segments);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_call(*rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int rtnl_update_link_alternative_names(
                sd_netlink **rtnl,
                uint16_t nlmsg_type,
                int ifindex,
                char* const *alternative_names) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);
        assert(IN_SET(nlmsg_type, RTM_NEWLINKPROP, RTM_DELLINKPROP));

        if (strv_isempty(alternative_names))
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, nlmsg_type, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(message, IFLA_PROP_LIST);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_strv(message, IFLA_ALT_IFNAME, (const char**) alternative_names);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int rtnl_set_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names) {
        return rtnl_update_link_alternative_names(rtnl, RTM_NEWLINKPROP, ifindex, alternative_names);
}

int rtnl_delete_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names) {
        return rtnl_update_link_alternative_names(rtnl, RTM_DELLINKPROP, ifindex, alternative_names);
}

int rtnl_set_link_alternative_names_by_ifname(
                sd_netlink **rtnl,
                const char *ifname,
                char* const *alternative_names) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifname);

        if (strv_isempty(alternative_names))
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_NEWLINKPROP, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(message, IFLA_IFNAME, ifname);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(message, IFLA_PROP_LIST);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_strv(message, IFLA_ALT_IFNAME, (const char**) alternative_names);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(message);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int rtnl_get_link_info(
                sd_netlink **rtnl,
                int ifindex,
                unsigned short *ret_iftype,
                unsigned *ret_flags,
                char **ret_kind,
                struct hw_addr_data *ret_hw_addr,
                struct hw_addr_data *ret_permanent_hw_addr) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *message = NULL, *reply = NULL;
        struct hw_addr_data addr = HW_ADDR_NULL, perm_addr = HW_ADDR_NULL;
        _cleanup_free_ char *kind = NULL;
        unsigned short iftype;
        unsigned flags;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        if (!ret_iftype && !ret_flags && !ret_kind && !ret_hw_addr && !ret_permanent_hw_addr)
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_GETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, &reply);
        if (r == -EINVAL)
                return -ENODEV; /* The device does not exist */
        if (r < 0)
                return r;

        if (ret_iftype) {
                r = sd_rtnl_message_link_get_type(reply, &iftype);
                if (r < 0)
                        return r;
        }

        if (ret_flags) {
                r = sd_rtnl_message_link_get_flags(reply, &flags);
                if (r < 0)
                        return r;
        }

        if (ret_kind) {
                r = sd_netlink_message_enter_container(reply, IFLA_LINKINFO);
                if (r >= 0) {
                        r = sd_netlink_message_read_string_strdup(reply, IFLA_INFO_KIND, &kind);
                        if (r < 0 && r != -ENODATA)
                                return r;

                        r = sd_netlink_message_exit_container(reply);
                        if (r < 0)
                                return r;
                }
        }

        if (ret_hw_addr) {
                r = netlink_message_read_hw_addr(reply, IFLA_ADDRESS, &addr);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        if (ret_permanent_hw_addr) {
                r = netlink_message_read_hw_addr(reply, IFLA_PERM_ADDRESS, &perm_addr);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        if (ret_iftype)
                *ret_iftype = iftype;
        if (ret_flags)
                *ret_flags = flags;
        if (ret_kind)
                *ret_kind = TAKE_PTR(kind);
        if (ret_hw_addr)
                *ret_hw_addr = addr;
        if (ret_permanent_hw_addr)
                *ret_permanent_hw_addr = perm_addr;
        return 0;
}

int rtnl_log_parse_error(int r) {
        return log_error_errno(r, "Failed to parse netlink message: %m");
}

int rtnl_log_create_error(int r) {
        return log_error_errno(r, "Failed to create netlink message: %m");
}

void rtattr_append_attribute_internal(struct rtattr *rta, unsigned short type, const void *data, size_t data_length) {
        size_t padding_length;
        uint8_t *padding;

        assert(rta);
        assert(!data || data_length > 0);

        /* fill in the attribute */
        rta->rta_type = type;
        rta->rta_len = RTA_LENGTH(data_length);
        if (data)
                /* we don't deal with the case where the user lies about the type
                 * and gives us too little data (so don't do that)
                 */
                padding = mempcpy(RTA_DATA(rta), data, data_length);

        else
                /* if no data was passed, make sure we still initialize the padding
                   note that we can have data_length > 0 (used by some containers) */
                padding = RTA_DATA(rta);

        /* make sure also the padding at the end of the message is initialized */
        padding_length = (uint8_t *) rta + RTA_SPACE(data_length) - padding;
        memzero(padding, padding_length);
}

int rtattr_append_attribute(struct rtattr **rta, unsigned short type, const void *data, size_t data_length) {
        struct rtattr *new_rta, *sub_rta;
        size_t message_length;

        assert(rta);
        assert(!data || data_length > 0);

        /* get the new message size (with padding at the end) */
        message_length = RTA_ALIGN(rta ? (*rta)->rta_len : 0) + RTA_SPACE(data_length);

        /* buffer should be smaller than both one page or 8K to be accepted by the kernel */
        if (message_length > MIN(page_size(), 8192UL))
                return -ENOBUFS;

        /* realloc to fit the new attribute */
        new_rta = realloc(*rta, message_length);
        if (!new_rta)
                return -ENOMEM;
        *rta = new_rta;

        /* get pointer to the attribute we are about to add */
        sub_rta = (struct rtattr *) ((uint8_t *) *rta + RTA_ALIGN((*rta)->rta_len));

        rtattr_append_attribute_internal(sub_rta, type, data, data_length);

        /* update rta_len */
        (*rta)->rta_len = message_length;

        return 0;
}

bool netlink_pid_changed(sd_netlink *nl) {
        /* We don't support people creating an nl connection and
         * keeping it around over a fork(). Let's complain. */
        return ASSERT_PTR(nl)->original_pid != getpid_cached();
}

static int socket_open(int family) {
        int fd;

        fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, family);
        if (fd < 0)
                return -errno;

        return fd_move_above_stdio(fd);
}

int netlink_open_family(sd_netlink **ret, int family) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = socket_open(family);
        if (fd < 0)
                return fd;

        r = sd_netlink_open_fd(ret, fd);
        if (r < 0)
                return r;
        TAKE_FD(fd);

        return 0;
}

static bool serial_used(sd_netlink *nl, uint32_t serial) {
        assert(nl);

        return
                hashmap_contains(nl->reply_callbacks, UINT32_TO_PTR(serial)) ||
                hashmap_contains(nl->rqueue_by_serial, UINT32_TO_PTR(serial)) ||
                hashmap_contains(nl->rqueue_partial_by_serial, UINT32_TO_PTR(serial));
}

void netlink_seal_message(sd_netlink *nl, sd_netlink_message *m) {
        uint32_t picked;

        assert(nl);
        assert(!netlink_pid_changed(nl));
        assert(m);
        assert(m->hdr);

        /* Avoid collisions with outstanding requests */
        do {
                picked = nl->serial;

                /* Don't use seq == 0, as that is used for broadcasts, so we would get confused by replies to
                   such messages */
                nl->serial = nl->serial == UINT32_MAX ? 1 : nl->serial + 1;

        } while (serial_used(nl, picked));

        m->hdr->nlmsg_seq = picked;
        message_seal(m);
}

static int socket_writev_message(sd_netlink *nl, sd_netlink_message **m, size_t msgcount) {
        _cleanup_free_ struct iovec *iovs = NULL;
        ssize_t k;

        assert(nl);
        assert(m);
        assert(msgcount > 0);

        iovs = new(struct iovec, msgcount);
        if (!iovs)
                return -ENOMEM;

        for (size_t i = 0; i < msgcount; i++) {
                assert(m[i]->hdr);
                assert(m[i]->hdr->nlmsg_len > 0);

                iovs[i] = IOVEC_MAKE(m[i]->hdr, m[i]->hdr->nlmsg_len);
        }

        k = writev(nl->fd, iovs, msgcount);
        if (k < 0)
                return -errno;

        return k;
}

int sd_netlink_sendv(
                sd_netlink *nl,
                sd_netlink_message **messages,
                size_t msgcount,
                uint32_t **ret_serial) {

        _cleanup_free_ uint32_t *serials = NULL;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!netlink_pid_changed(nl), -ECHILD);
        assert_return(messages, -EINVAL);
        assert_return(msgcount > 0, -EINVAL);

        if (ret_serial) {
                serials = new(uint32_t, msgcount);
                if (!serials)
                        return -ENOMEM;
        }

        for (size_t i = 0; i < msgcount; i++) {
                assert_return(!messages[i]->sealed, -EPERM);

                netlink_seal_message(nl, messages[i]);
                if (serials)
                        serials[i] = message_get_serial(messages[i]);
        }

        r = socket_writev_message(nl, messages, msgcount);
        if (r < 0)
                return r;

        if (ret_serial)
                *ret_serial = TAKE_PTR(serials);

        return r;
}
