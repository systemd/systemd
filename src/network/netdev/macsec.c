/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_macsec.h>
#include <linux/genetlink.h>

#include "conf-parser.h"
#include "fileio.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "macsec.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-helpers.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static void security_association_clear(SecurityAssociation *sa) {
        if (!sa)
                return;

        explicit_bzero_safe(sa->key, sa->key_len);
        free(sa->key);
        free(sa->key_file);
}

static void security_association_init(SecurityAssociation *sa) {
        assert(sa);

        sa->activate = -1;
        sa->use_for_encoding = -1;
}

static ReceiveAssociation* macsec_receive_association_free(ReceiveAssociation *c) {
        if (!c)
                return NULL;

        if (c->macsec && c->section)
                ordered_hashmap_remove(c->macsec->receive_associations_by_section, c->section);

        config_section_free(c->section);
        security_association_clear(&c->sa);

        return mfree(c);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(ReceiveAssociation, macsec_receive_association_free);

static int macsec_receive_association_new_static(MACsec *s, const char *filename, unsigned section_line, ReceiveAssociation **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(macsec_receive_association_freep) ReceiveAssociation *c = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        c = ordered_hashmap_get(s->receive_associations_by_section, n);
        if (c) {
                *ret = TAKE_PTR(c);
                return 0;
        }

        c = new(ReceiveAssociation, 1);
        if (!c)
                return -ENOMEM;

        *c = (ReceiveAssociation) {
                .macsec = s,
                .section = TAKE_PTR(n),
        };

        security_association_init(&c->sa);

        r = ordered_hashmap_ensure_put(&s->receive_associations_by_section, &config_section_hash_ops, c->section, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

static ReceiveChannel* macsec_receive_channel_free(ReceiveChannel *c) {
        if (!c)
                return NULL;

        if (c->macsec) {
                if (c->sci.as_uint64 > 0)
                        ordered_hashmap_remove_value(c->macsec->receive_channels, &c->sci.as_uint64, c);

                if (c->section)
                        ordered_hashmap_remove(c->macsec->receive_channels_by_section, c->section);
        }

        config_section_free(c->section);

        return mfree(c);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(ReceiveChannel, macsec_receive_channel_free);

static int macsec_receive_channel_new(MACsec *s, uint64_t sci, ReceiveChannel **ret) {
        ReceiveChannel *c;

        assert(s);

        c = new(ReceiveChannel, 1);
        if (!c)
                return -ENOMEM;

        *c = (ReceiveChannel) {
                .macsec = s,
                .sci.as_uint64 = sci,
        };

        *ret = c;
        return 0;
}

static int macsec_receive_channel_new_static(MACsec *s, const char *filename, unsigned section_line, ReceiveChannel **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(macsec_receive_channel_freep) ReceiveChannel *c = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        c = ordered_hashmap_get(s->receive_channels_by_section, n);
        if (c) {
                *ret = TAKE_PTR(c);
                return 0;
        }

        r = macsec_receive_channel_new(s, 0, &c);
        if (r < 0)
                return r;

        c->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&s->receive_channels_by_section, &config_section_hash_ops, c->section, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

static TransmitAssociation* macsec_transmit_association_free(TransmitAssociation *a) {
        if (!a)
                return NULL;

        if (a->macsec && a->section)
                ordered_hashmap_remove(a->macsec->transmit_associations_by_section, a->section);

        config_section_free(a->section);
        security_association_clear(&a->sa);

        return mfree(a);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(TransmitAssociation, macsec_transmit_association_free);

static int macsec_transmit_association_new_static(MACsec *s, const char *filename, unsigned section_line, TransmitAssociation **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(macsec_transmit_association_freep) TransmitAssociation *a = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        a = ordered_hashmap_get(s->transmit_associations_by_section, n);
        if (a) {
                *ret = TAKE_PTR(a);
                return 0;
        }

        a = new(TransmitAssociation, 1);
        if (!a)
                return -ENOMEM;

        *a = (TransmitAssociation) {
                .macsec = s,
                .section = TAKE_PTR(n),
        };

        security_association_init(&a->sa);

        r = ordered_hashmap_ensure_put(&s->transmit_associations_by_section, &config_section_hash_ops, a->section, a);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(a);

        return 0;
}

static int netdev_macsec_create_message(NetDev *netdev, int command, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->ifindex > 0);

        r = sd_genl_message_new(netdev->manager->genl, MACSEC_GENL_NAME, command, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, MACSEC_ATTR_IFINDEX, netdev->ifindex);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int netdev_macsec_fill_message_sci(NetDev *netdev, MACsecSCI *sci, sd_netlink_message *m) {
        int r;

        assert(netdev);
        assert(m);
        assert(sci);

        r = sd_netlink_message_open_container(m, MACSEC_ATTR_RXSC_CONFIG);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u64(m, MACSEC_RXSC_ATTR_SCI, sci->as_uint64);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_macsec_fill_message_sa(NetDev *netdev, SecurityAssociation *a, sd_netlink_message *m) {
        int r;

        assert(netdev);
        assert(a);
        assert(m);

        r = sd_netlink_message_open_container(m, MACSEC_ATTR_SA_CONFIG);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, MACSEC_SA_ATTR_AN, a->association_number);
        if (r < 0)
                return r;

        if (a->packet_number > 0) {
                r = sd_netlink_message_append_u32(m, MACSEC_SA_ATTR_PN, a->packet_number);
                if (r < 0)
                        return r;
        }

        if (a->key_len > 0) {
                r = sd_netlink_message_append_data(m, MACSEC_SA_ATTR_KEYID, a->key_id, MACSEC_KEYID_LEN);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_data(m, MACSEC_SA_ATTR_KEY, a->key, a->key_len);
                if (r < 0)
                        return r;
        }

        if (a->activate >= 0) {
                r = sd_netlink_message_append_u8(m, MACSEC_SA_ATTR_ACTIVE, a->activate);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int macsec_receive_association_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev,
                                "MACsec receive secure association exists, using it without changing parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add receive secure association: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Receive secure association is configured");

        return 1;
}

static int netdev_macsec_configure_receive_association(NetDev *netdev, ReceiveAssociation *a) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(a);

        r = netdev_macsec_create_message(netdev, MACSEC_CMD_ADD_RXSA, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create netlink message: %m");

        r = netdev_macsec_fill_message_sa(netdev, &a->sa, m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to fill netlink message: %m");

        r = netdev_macsec_fill_message_sci(netdev, &a->sci, m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to fill netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_receive_association_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to configure receive secure association: %m");

        netdev_ref(netdev);

        return 0;
}

static int macsec_receive_channel_handler(sd_netlink *rtnl, sd_netlink_message *m, ReceiveChannel *c) {
        NetDev *netdev;
        int r;

        assert(c);
        assert(c->macsec);

        netdev = NETDEV(c->macsec);

        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_debug(netdev,
                                 "MACsec receive channel exists, using it without changing parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add receive secure channel: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Receive channel is configured");

        for (unsigned i = 0; i < c->n_rxsa; i++) {
                r = netdev_macsec_configure_receive_association(netdev, c->rxsa[i]);
                if (r < 0) {
                        log_netdev_warning_errno(netdev, r,
                                                 "Failed to configure receive security association: %m");
                        netdev_enter_failed(netdev);
                        return 1;
                }
        }

        return 1;
}

static void receive_channel_destroy_callback(ReceiveChannel *c) {
        assert(c);
        assert(c->macsec);

        netdev_unref(NETDEV(c->macsec));
}

static int netdev_macsec_configure_receive_channel(NetDev *netdev, ReceiveChannel *c) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(c);

        r = netdev_macsec_create_message(netdev, MACSEC_CMD_ADD_RXSC, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create netlink message: %m");

        r = netdev_macsec_fill_message_sci(netdev, &c->sci, m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to fill netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_receive_channel_handler,
                               receive_channel_destroy_callback, c);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to configure receive channel: %m");

        netdev_ref(netdev);

        return 0;
}

static int macsec_transmit_association_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev,
                                "MACsec transmit secure association exists, using it without changing parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add transmit secure association: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Transmit secure association is configured");

        return 1;
}

static int netdev_macsec_configure_transmit_association(NetDev *netdev, TransmitAssociation *a) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(a);

        r = netdev_macsec_create_message(netdev, MACSEC_CMD_ADD_TXSA, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create netlink message: %m");

        r = netdev_macsec_fill_message_sa(netdev, &a->sa, m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to fill netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_transmit_association_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to configure transmit secure association: %m");

        netdev_ref(netdev);

        return 0;
}

static int netdev_macsec_configure(NetDev *netdev, Link *link) {
        TransmitAssociation *a;
        ReceiveChannel *c;
        MACsec *s;
        int r;

        assert(netdev);
        s = MACSEC(netdev);
        assert(s);

        ORDERED_HASHMAP_FOREACH(a, s->transmit_associations_by_section) {
                r = netdev_macsec_configure_transmit_association(netdev, a);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH(c, s->receive_channels) {
                r = netdev_macsec_configure_receive_channel(netdev, c);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netdev_macsec_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        MACsec *v;
        int r;

        assert(netdev);
        assert(m);

        v = MACSEC(netdev);

        assert(v);

        if (v->port > 0) {
                r = sd_netlink_message_append_u16(m, IFLA_MACSEC_PORT, v->port);
                if (r < 0)
                        return r;
        }

        if (v->encrypt >= 0) {
                r = sd_netlink_message_append_u8(m, IFLA_MACSEC_ENCRYPT, v->encrypt);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, IFLA_MACSEC_ENCODING_SA, v->encoding_an);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_macsec_port(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        _cleanup_(macsec_receive_channel_free_or_set_invalidp) ReceiveChannel *c = NULL;
        MACsec *s = userdata;
        uint16_t port;
        void *dest;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* This parses port used to make Secure Channel Identifier (SCI) */

        if (streq(section, "MACsec"))
                dest = &s->port;
        else if (streq(section, "MACsecReceiveChannel")) {
                r = macsec_receive_channel_new_static(s, filename, section_line, &c);
                if (r < 0)
                        return log_oom();

                dest = &c->sci.port;
        } else {
                assert(streq(section, "MACsecReceiveAssociation"));

                r = macsec_receive_association_new_static(s, filename, section_line, &b);
                if (r < 0)
                        return log_oom();

                dest = &b->sci.port;
        }

        r = parse_ip_port(rvalue, &port);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse port '%s' for secure channel identifier. Ignoring assignment: %m",
                           rvalue);
                return 0;
        }

        unaligned_write_be16(dest, port);

        TAKE_PTR(b);
        TAKE_PTR(c);

        return 0;
}

int config_parse_macsec_hw_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        _cleanup_(macsec_receive_channel_free_or_set_invalidp) ReceiveChannel *c = NULL;
        MACsec *s = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "MACsecReceiveChannel"))
                r = macsec_receive_channel_new_static(s, filename, section_line, &c);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        r = parse_ether_addr(rvalue, b ? &b->sci.mac : &c->sci.mac);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MAC address for secure channel identifier. "
                           "Ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(b);
        TAKE_PTR(c);

        return 0;
}

int config_parse_macsec_packet_number(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        MACsec *s = userdata;
        uint32_t val, *dest;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "MACsecTransmitAssociation"))
                r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        dest = a ? &a->sa.packet_number : &b->sa.packet_number;

        r = safe_atou32(rvalue, &val);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse packet number. Ignoring assignment: %s", rvalue);
                return 0;
        }
        if (streq(section, "MACsecTransmitAssociation") && val == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid packet number. Ignoring assignment: %s", rvalue);
                return 0;
        }

        *dest = val;
        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

int config_parse_macsec_key(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        _cleanup_(erase_and_freep) void *p = NULL;
        MACsec *s = userdata;
        SecurityAssociation *dest;
        size_t l;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        (void) warn_file_is_world_accessible(filename, NULL, unit, line);

        if (streq(section, "MACsecTransmitAssociation"))
                r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        dest = a ? &a->sa : &b->sa;

        r = unhexmem_full(rvalue, strlen(rvalue), true, &p, &l);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse key. Ignoring assignment: %m");
                return 0;
        }

        if (l != 16) {
                /* See DEFAULT_SAK_LEN in drivers/net/macsec.c */
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid key length (%zu). Ignoring assignment", l);
                return 0;
        }

        explicit_bzero_safe(dest->key, dest->key_len);
        free_and_replace(dest->key, p);
        dest->key_len = l;

        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

int config_parse_macsec_key_file(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        _cleanup_free_ char *path = NULL;
        MACsec *s = userdata;
        char **dest;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "MACsecTransmitAssociation"))
                r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        dest = a ? &a->sa.key_file : &b->sa.key_file;

        if (isempty(rvalue)) {
                *dest = mfree(*dest);
                return 0;
        }

        path = strdup(rvalue);
        if (!path)
                return log_oom();

        if (path_simplify_and_warn(path, PATH_CHECK_ABSOLUTE, unit, filename, line, lvalue) < 0)
                return 0;

        free_and_replace(*dest, path);
        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

int config_parse_macsec_key_id(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        _cleanup_free_ void *p = NULL;
        MACsec *s = userdata;
        uint8_t *dest;
        size_t l;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "MACsecTransmitAssociation"))
                r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        r = unhexmem(rvalue, strlen(rvalue), &p, &l);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse KeyId=%s, ignoring assignment: %m", rvalue);
                return 0;
        }
        if (l > MACSEC_KEYID_LEN) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified KeyId= is larger then the allowed maximum (%zu > %u), ignoring: %s",
                           l, MACSEC_KEYID_LEN, rvalue);
                return 0;
        }

        dest = a ? a->sa.key_id : b->sa.key_id;
        memcpy_safe(dest, p, l);
        memzero(dest + l, MACSEC_KEYID_LEN - l);

        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

int config_parse_macsec_sa_activate(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        _cleanup_(macsec_receive_association_free_or_set_invalidp) ReceiveAssociation *b = NULL;
        MACsec *s = userdata;
        int *dest;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "MACsecTransmitAssociation"))
                r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        else
                r = macsec_receive_association_new_static(s, filename, section_line, &b);
        if (r < 0)
                return log_oom();

        dest = a ? &a->sa.activate : &b->sa.activate;

        if (isempty(rvalue))
                r = -1;
        else {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse activation mode of %s security association. "
                                   "Ignoring assignment: %s",
                                   streq(section, "MACsecTransmitAssociation") ? "transmit" : "receive",
                                   rvalue);
                        return 0;
                }
        }

        *dest = r;
        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

int config_parse_macsec_use_for_encoding(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(macsec_transmit_association_free_or_set_invalidp) TransmitAssociation *a = NULL;
        MACsec *s = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = macsec_transmit_association_new_static(s, filename, section_line, &a);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                a->sa.use_for_encoding = -1;
                TAKE_PTR(a);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s= setting. Ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        a->sa.use_for_encoding = r;
        if (a->sa.use_for_encoding > 0)
                a->sa.activate = true;

        TAKE_PTR(a);

        return 0;
}

static int macsec_read_key_file(NetDev *netdev, SecurityAssociation *sa) {
        _cleanup_(erase_and_freep) uint8_t *key = NULL;
        size_t key_len;
        int r;

        assert(netdev);
        assert(sa);

        if (!sa->key_file)
                return 0;

        r = read_full_file_full(
                        AT_FDCWD, sa->key_file, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE | READ_FULL_FILE_UNHEX | READ_FULL_FILE_WARN_WORLD_READABLE | READ_FULL_FILE_CONNECT_SOCKET,
                        NULL, (char **) &key, &key_len);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "Failed to read key from '%s', ignoring: %m",
                                              sa->key_file);

        if (key_len != 16)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid key length (%zu bytes), ignoring: %m", key_len);

        explicit_bzero_safe(sa->key, sa->key_len);
        free_and_replace(sa->key, key);
        sa->key_len = key_len;

        return 0;
}

static int macsec_receive_channel_verify(ReceiveChannel *c) {
        NetDev *netdev;
        int r;

        assert(c);
        assert(c->macsec);

        netdev = NETDEV(c->macsec);

        if (section_is_invalid(c->section))
                return -EINVAL;

        if (ether_addr_is_null(&c->sci.mac))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec receive channel without MAC address configured. "
                                              "Ignoring [MACsecReceiveChannel] section from line %u",
                                              c->section->filename, c->section->line);

        if (c->sci.port == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec receive channel without port configured. "
                                              "Ignoring [MACsecReceiveChannel] section from line %u",
                                              c->section->filename, c->section->line);

        r = ordered_hashmap_ensure_put(&c->macsec->receive_channels, &uint64_hash_ops, &c->sci.as_uint64, c);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -EEXIST)
                return log_netdev_error_errno(netdev, r,
                                              "%s: Multiple [MACsecReceiveChannel] sections have same SCI, "
                                              "Ignoring [MACsecReceiveChannel] section from line %u",
                                              c->section->filename, c->section->line);
        if (r < 0)
                return log_netdev_error_errno(netdev, r,
                                              "%s: Failed to store [MACsecReceiveChannel] section at hashmap, "
                                              "Ignoring [MACsecReceiveChannel] section from line %u",
                                              c->section->filename, c->section->line);
        return 0;
}

static int macsec_transmit_association_verify(TransmitAssociation *t) {
        NetDev *netdev;
        int r;

        assert(t);
        assert(t->macsec);

        netdev = NETDEV(t->macsec);

        if (section_is_invalid(t->section))
                return -EINVAL;

        if (t->sa.packet_number == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec transmit secure association without PacketNumber= configured. "
                                              "Ignoring [MACsecTransmitAssociation] section from line %u",
                                              t->section->filename, t->section->line);

        r = macsec_read_key_file(netdev, &t->sa);
        if (r < 0)
                return r;

        if (t->sa.key_len <= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec transmit secure association without key configured. "
                                              "Ignoring [MACsecTransmitAssociation] section from line %u",
                                              t->section->filename, t->section->line);

        return 0;
}

static int macsec_receive_association_verify(ReceiveAssociation *a) {
        ReceiveChannel *c;
        NetDev *netdev;
        int r;

        assert(a);
        assert(a->macsec);

        netdev = NETDEV(a->macsec);

        if (section_is_invalid(a->section))
                return -EINVAL;

        r = macsec_read_key_file(netdev, &a->sa);
        if (r < 0)
                return r;

        if (a->sa.key_len <= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec receive secure association without key configured. "
                                              "Ignoring [MACsecReceiveAssociation] section from line %u",
                                              a->section->filename, a->section->line);

        if (ether_addr_is_null(&a->sci.mac))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec receive secure association without MAC address configured. "
                                              "Ignoring [MACsecReceiveAssociation] section from line %u",
                                              a->section->filename, a->section->line);

        if (a->sci.port == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec receive secure association without port configured. "
                                              "Ignoring [MACsecReceiveAssociation] section from line %u",
                                              a->section->filename, a->section->line);

        c = ordered_hashmap_get(a->macsec->receive_channels, &a->sci.as_uint64);
        if (!c) {
                _cleanup_(macsec_receive_channel_freep) ReceiveChannel *new_channel = NULL;

                r = macsec_receive_channel_new(a->macsec, a->sci.as_uint64, &new_channel);
                if (r < 0)
                        return log_oom();

                r = ordered_hashmap_ensure_put(&a->macsec->receive_channels, &uint64_hash_ops, &new_channel->sci.as_uint64, new_channel);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_netdev_error_errno(netdev, r,
                                                      "%s: Failed to store receive channel at hashmap, "
                                                      "Ignoring [MACsecReceiveAssociation] section from line %u",
                                                      a->section->filename, a->section->line);
                c = TAKE_PTR(new_channel);
        }
        if (c->n_rxsa >= MACSEC_MAX_ASSOCIATION_NUMBER)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(ERANGE),
                                              "%s: Too many [MACsecReceiveAssociation] sections for the same receive channel, "
                                              "Ignoring [MACsecReceiveAssociation] section from line %u",
                                              a->section->filename, a->section->line);

        a->sa.association_number = c->n_rxsa;
        c->rxsa[c->n_rxsa++] = a;

        return 0;
}

static int netdev_macsec_verify(NetDev *netdev, const char *filename) {
        MACsec *v = MACSEC(netdev);
        TransmitAssociation *a;
        ReceiveAssociation *n;
        ReceiveChannel *c;
        uint8_t an, encoding_an;
        bool use_for_encoding;
        int r;

        assert(netdev);
        assert(v);
        assert(filename);

        ORDERED_HASHMAP_FOREACH(c, v->receive_channels_by_section) {
                r = macsec_receive_channel_verify(c);
                if (r < 0)
                        macsec_receive_channel_free(c);
        }

        an = 0;
        use_for_encoding = false;
        encoding_an = 0;
        ORDERED_HASHMAP_FOREACH(a, v->transmit_associations_by_section) {
                r = macsec_transmit_association_verify(a);
                if (r < 0) {
                        macsec_transmit_association_free(a);
                        continue;
                }

                if (an >= MACSEC_MAX_ASSOCIATION_NUMBER) {
                        log_netdev_error(netdev,
                                         "%s: Too many [MACsecTransmitAssociation] sections configured. "
                                         "Ignoring [MACsecTransmitAssociation] section from line %u",
                                         a->section->filename, a->section->line);
                        macsec_transmit_association_free(a);
                        continue;
                }

                a->sa.association_number = an++;

                if (a->sa.use_for_encoding > 0) {
                        if (use_for_encoding) {
                                log_netdev_warning(netdev,
                                                   "%s: Multiple security associations are set to be used for transmit channel."
                                                   "Disabling UseForEncoding= in [MACsecTransmitAssociation] section from line %u",
                                                   a->section->filename, a->section->line);
                                a->sa.use_for_encoding = false;
                        } else {
                                encoding_an = a->sa.association_number;
                                use_for_encoding = true;
                        }
                }
        }

        assert(encoding_an < MACSEC_MAX_ASSOCIATION_NUMBER);
        v->encoding_an = encoding_an;

        ORDERED_HASHMAP_FOREACH(n, v->receive_associations_by_section) {
                r = macsec_receive_association_verify(n);
                if (r < 0)
                        macsec_receive_association_free(n);
        }

        return 0;
}

static void macsec_init(NetDev *netdev) {
        MACsec *v;

        assert(netdev);

        v = MACSEC(netdev);

        assert(v);

        v->encrypt = -1;
}

static void macsec_done(NetDev *netdev) {
        MACsec *t;

        assert(netdev);

        t = MACSEC(netdev);

        assert(t);

        ordered_hashmap_free_with_destructor(t->receive_channels, macsec_receive_channel_free);
        ordered_hashmap_free_with_destructor(t->receive_channels_by_section, macsec_receive_channel_free);
        ordered_hashmap_free_with_destructor(t->transmit_associations_by_section, macsec_transmit_association_free);
        ordered_hashmap_free_with_destructor(t->receive_associations_by_section, macsec_receive_association_free);
}

const NetDevVTable macsec_vtable = {
        .object_size = sizeof(MACsec),
        .init = macsec_init,
        .sections = NETDEV_COMMON_SECTIONS "MACsec\0MACsecReceiveChannel\0MACsecTransmitAssociation\0MACsecReceiveAssociation\0",
        .fill_message_create = netdev_macsec_fill_message_create,
        .post_create = netdev_macsec_configure,
        .done = macsec_done,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_macsec_verify,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
