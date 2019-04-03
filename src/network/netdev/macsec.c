/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_macsec.h>
#include <linux/genetlink.h>

#include "conf-parser.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "macsec.h"
#include "memory-util.h"
#include "missing.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "sd-netlink.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static void macsec_receive_association_free(ReceiveAssociation *c) {
        if (!c)
                return;

        if (c->macsec && c->section)
                ordered_hashmap_remove(c->macsec->receive_associations_by_section, c->section);

        network_config_section_free(c->section);
        free(c->sa.key);

        free(c);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(ReceiveAssociation, macsec_receive_association_free);

static int macsec_receive_association_new_static(MACsec *s, const char *filename, unsigned section_line, ReceiveAssociation **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(macsec_receive_association_freep) ReceiveAssociation *c = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
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

        r = ordered_hashmap_ensure_allocated(&s->receive_associations_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = ordered_hashmap_put(s->receive_associations_by_section, c->section, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

static void macsec_receive_channel_free(ReceiveChannel *c) {
        if (!c)
                return;

        if (c->macsec && c->section)
                ordered_hashmap_remove(c->macsec->receive_channels_by_section, c->section);

        network_config_section_free(c->section);

        free(c);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(ReceiveChannel, macsec_receive_channel_free);

static int macsec_receive_channel_new_static(MACsec *s, const char *filename, unsigned section_line, ReceiveChannel **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(macsec_receive_channel_freep) ReceiveChannel *c = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        c = ordered_hashmap_get(s->receive_channels_by_section, n);
        if (c) {
                *ret = TAKE_PTR(c);
                return 0;
        }

        c = new(ReceiveChannel, 1);
        if (!c)
                return -ENOMEM;

        *c = (ReceiveChannel) {
                .macsec = s,
                .section = TAKE_PTR(n),
        };

        r = ordered_hashmap_ensure_allocated(&s->receive_channels_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = ordered_hashmap_put(s->receive_channels_by_section, c->section, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

static void macsec_transmit_association_free(TransmitAssociation *a) {
        if (!a)
                return;

        if (a->macsec && a->section)
                ordered_hashmap_remove(a->macsec->transmit_associations_by_section, a->section);

        network_config_section_free(a->section);
        free(a->sa.key);

        free(a);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(TransmitAssociation, macsec_transmit_association_free);

static int macsec_transmit_association_new_static(MACsec *s, const char *filename, unsigned section_line, TransmitAssociation **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(macsec_transmit_association_freep) TransmitAssociation *a = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
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

        r = ordered_hashmap_ensure_allocated(&s->transmit_associations_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = ordered_hashmap_put(s->transmit_associations_by_section, a->section, a);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(a);

        return 0;
}

static int netdev_macsec_fill_message(NetDev *netdev, int command, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->ifindex > 0);

        r = sd_genl_message_new(netdev->manager->genl, SD_GENL_MACSEC, command, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, MACSEC_ATTR_IFINDEX, netdev->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_ATTR_IFINDEX attribute: %m");

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
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_ATTR_RXSC_CONFIG attribute: %m");

        r = sd_netlink_message_append_u64(m, MACSEC_RXSC_ATTR_SCI, sci->as_uint64);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_RXSC_ATTR_SCI attribute: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_ATTR_RXSC_CONFIG attribute: %m");

        return 0;
}

static int netdev_macsec_fill_message_sa(NetDev *netdev, SecurityAssociation *a, sd_netlink_message *m) {
        int r;

        assert(netdev);
        assert(a);
        assert(m);

        r = sd_netlink_message_open_container(m, MACSEC_ATTR_SA_CONFIG);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_ATTR_SA_CONFIG attribute: %m");

        r = sd_netlink_message_append_u8(m, MACSEC_SA_ATTR_AN, a->association_number);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_SA_ATTR_AN attribute: %m");

        if (a->packet_number > 0) {
                r = sd_netlink_message_append_u32(m, MACSEC_SA_ATTR_PN, a->packet_number);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append MACSEC_SA_ATTR_PN attribute: %m");
        }

        if (a->key_len > 0) {
                r = sd_netlink_message_append_data(m, MACSEC_SA_ATTR_KEYID, a->key_id, MACSEC_KEYID_LEN);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append MACSEC_SA_ATTR_KEYID attribute: %m");

                r = sd_netlink_message_append_data(m, MACSEC_SA_ATTR_KEY, a->key, a->key_len);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append MACSEC_SA_ATTR_KEY attribute: %m");
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append MACSEC_ATTR_SA_CONFIG attribute: %m");

        return 0;
}

static int macsec_receive_association_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev,
                                "MACsec receive secure association exists, "
                                "using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add receive secure association: %m");
                netdev_drop(netdev);

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

        r = netdev_macsec_fill_message(netdev, MACSEC_CMD_ADD_RXSA, &m);
        if (r < 0)
                return r;

        r = netdev_macsec_fill_message_sa(netdev, &a->sa, m);
        if (r < 0)
                return r;

        r = netdev_macsec_fill_message_sci(netdev, &a->sci, m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_receive_association_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to configure receive secure association: %m");

        netdev_ref(netdev);

        return 0;
}

static int macsec_receive_channel_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_debug(netdev,
                                 "MACsec receive channel exists, "
                                 "using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add receive secure channel: %m");
                netdev_drop(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Receive channel is configured");

        return 1;
}

static int netdev_macsec_configure_receive_channel(NetDev *netdev, ReceiveChannel *c) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(netdev);
        assert(c);

        r = netdev_macsec_fill_message(netdev, MACSEC_CMD_ADD_RXSC, &m);
        if (r < 0)
                return r;

        r = netdev_macsec_fill_message_sci(netdev, &c->sci, m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_receive_channel_handler,
                               netdev_destroy_callback, netdev);
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
                                "MACsec transmit secure association exists, "
                                "using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r,
                                         "Failed to add transmit secure association: %m");
                netdev_drop(netdev);

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

        r = netdev_macsec_fill_message(netdev, MACSEC_CMD_ADD_TXSA, &m);
        if (r < 0)
                return r;

        r = netdev_macsec_fill_message_sa(netdev, &a->sa, m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, m, macsec_transmit_association_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to configure transmit secure association: %m");

        netdev_ref(netdev);

        return 0;
}

static int netdev_macsec_configure(NetDev *netdev, Link *link, sd_netlink_message *m) {
        ReceiveAssociation *n;
        TransmitAssociation *a;
        ReceiveChannel *c;
        Iterator i;
        MACsec *s;
        int r;

        assert(netdev);
        s = MACSEC(netdev);
        assert(s);

        ORDERED_HASHMAP_FOREACH(a, s->transmit_associations_by_section, i) {
                r = netdev_macsec_configure_transmit_association(netdev, a);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH(c, s->receive_channels_by_section, i) {
                r = netdev_macsec_configure_receive_channel(netdev, c);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH(n, s->receive_associations_by_section, i) {
                r = netdev_macsec_configure_receive_association(netdev, n);
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

        if (v->port > 0) {
                r = sd_netlink_message_append_u16(m, IFLA_MACSEC_PORT, v->port);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_MACSEC_PORT attribute: %m");
        }

        if (v->encrypt >= 0) {
                r = sd_netlink_message_append_u8(m, IFLA_MACSEC_ENCRYPT, v->encrypt);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_MACSEC_ENCRYPT attribute: %m");
        }

        return r;
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
        be16_t *dest;
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
                        return r;

                dest = &c->sci.port;
        } else {
                assert(streq(section, "MACsecReceiveAssociation"));

                r = macsec_receive_association_new_static(s, filename, section_line, &b);
                if (r < 0)
                        return r;

                dest = &b->sci.port;
        }

        r = parse_ip_port(rvalue, &port);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse port '%s' for secure channel identifier. Ignoring assignment: %m",
                           rvalue);
                return 0;
        }

        *dest = htobe16(port);

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
                return r;

        r = ether_addr_from_string(rvalue, b ? &b->sci.mac : &c->sci.mac);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
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
                return r;

        dest = a ? &a->sa.packet_number : &b->sa.packet_number;

        r = safe_atou32(rvalue, &val);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse packet number. Ignoring assignment: %s", rvalue);
                return 0;
        }
        if (streq(section, "MACsecTransmitAssociation") && val == 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
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
        _cleanup_free_ void *p;
        MACsec *s = userdata;
        SecurityAssociation *dest;
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
                return r;

        dest = a ? &a->sa : &b->sa;

        r = unhexmem(rvalue, strlen(rvalue), &p, &l);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse key. Ignoring assignment: %m");
                return 0;
        }
        if (l != 16) {
                /* See DEFAULT_SAK_LEN in drivers/net/macsec.c */
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid key length (%zu). Ignoring assignment", l);
                return 0;
        }

        free_and_replace(dest->key, p);
        dest->key_len = l;

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
        _cleanup_free_ void *p;
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
                return r;

        r = unhexmem(rvalue, strlen(rvalue), &p, &l);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse key id. Ignoring assignment: %s", rvalue);
                return 0;
        }
        if (l > MACSEC_KEYID_LEN) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "The size of key id is too large (%zu), maximum of %zu permitted. "
                           "Ignoring assignment: %s", l, (size_t) MACSEC_KEYID_LEN, rvalue);
                return 0;
        }

        dest = a ? a->sa.key_id : b->sa.key_id;
        memcpy_safe(dest, p, l);
        memzero(dest + l, MACSEC_KEYID_LEN - l);

        TAKE_PTR(a);
        TAKE_PTR(b);

        return 0;
}

static int macsec_receive_channel_verify(ReceiveChannel *c) {
        NetDev *netdev;

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

        return 0;
}

static int macsec_transmit_association_verify(TransmitAssociation *t) {
        NetDev *netdev;

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

        if (t->sa.key_len <= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: MACsec transmit secure association without key configured. "
                                              "Ignoring [MACsecTransmitAssociation] section from line %u",
                                              t->section->filename, t->section->line);

        return 0;
}

static int macsec_receive_association_verify(ReceiveAssociation *a) {
        NetDev *netdev;

        assert(a);
        assert(a->macsec);

        netdev = NETDEV(a->macsec);

        if (section_is_invalid(a->section))
                return -EINVAL;

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

        return 0;
}

static int netdev_macsec_verify(NetDev *netdev, const char *filename) {
        MACsec *v = MACSEC(netdev);
        TransmitAssociation *a;
        ReceiveAssociation *n;
        ReceiveChannel *c;
        Iterator i;
        int r;

        assert(netdev);
        assert(v);
        assert(filename);

        ORDERED_HASHMAP_FOREACH(c, v->receive_channels_by_section, i) {
                r = macsec_receive_channel_verify(c);
                if (r < 0)
                        macsec_receive_channel_free(c);
        }

        ORDERED_HASHMAP_FOREACH(a, v->transmit_associations_by_section, i) {
                r = macsec_transmit_association_verify(a);
                if (r < 0)
                        macsec_transmit_association_free(a);
        }

        ORDERED_HASHMAP_FOREACH(n, v->receive_associations_by_section, i) {
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

        ordered_hashmap_free_with_destructor(t->receive_channels_by_section, macsec_receive_channel_free);
        ordered_hashmap_free_with_destructor(t->transmit_associations_by_section, macsec_transmit_association_free);
        ordered_hashmap_free_with_destructor(t->receive_associations_by_section, macsec_receive_association_free);
}

const NetDevVTable macsec_vtable = {
        .object_size = sizeof(MACsec),
        .init = macsec_init,
        .sections = "Match\0NetDev\0MACsec\0MACsecReceiveChannel\0MACsecTransmitAssociation\0MACsecReceiveAssociation\0",
        .fill_message_create = netdev_macsec_fill_message_create,
        .post_create = netdev_macsec_configure,
        .done = macsec_done,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_macsec_verify,
};
