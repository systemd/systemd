/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <net/ethernet.h>
#include <arpa/inet.h>

#include "macro.h"
#include "lldp-tlv.h"

int sd_lldp_section_new(sd_lldp_section **ret) {
        sd_lldp_section *s;

        s = new0(sd_lldp_section, 1);
        if (!s)
                return -ENOMEM;

        *ret = s;

        return 0;
}

void sd_lldp_section_free(sd_lldp_section *m) {

        if (!m)
                return;

        free(m);
}

int sd_lldp_packet_new(sd_lldp_packet **ret) {
        sd_lldp_packet *m;

        m = new0(sd_lldp_packet, 1);
        if (!m)
                return -ENOMEM;

        LIST_HEAD_INIT(m->sections);
        m->n_ref = 1;

        *ret = m;

        return 0;
}

sd_lldp_packet *sd_lldp_packet_ref(sd_lldp_packet *m) {

        if (!m)
                return NULL;

        assert(m->n_ref > 0);
        m->n_ref++;

        return m;
}

sd_lldp_packet *sd_lldp_packet_unref(sd_lldp_packet *m) {
        sd_lldp_section *s, *n;

        if (!m)
                return NULL;

        assert(m->n_ref > 0);
        m->n_ref--;

        if (m->n_ref > 0)
                return m;

        LIST_FOREACH_SAFE(section, s, n, m->sections)
                sd_lldp_section_free(s);

        free(m);
        return NULL;
}

int sd_lldp_packet_append_bytes(sd_lldp_packet *m, const void *data, size_t data_length) {
        uint8_t *p;

        assert_return(m, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(data_length, -EINVAL);

        if (m->length + data_length > ETHER_MAX_LEN)
                return -ENOMEM;

        p = m->pdu + m->length;
        memcpy(p, data, data_length);
        m->length += data_length;

        return 0;
}

int sd_lldp_packet_append_u8(sd_lldp_packet *m, uint8_t data) {

        assert_return(m, -EINVAL);

        return sd_lldp_packet_append_bytes(m, &data, sizeof(uint8_t));
}

int sd_lldp_packet_append_u16(sd_lldp_packet *m, uint16_t data) {
        uint16_t type;

        assert_return(m, -EINVAL);

        type = htons(data);

        return sd_lldp_packet_append_bytes(m, &type, sizeof(uint16_t));
}

int sd_lldp_packet_append_u32(sd_lldp_packet *m, uint32_t data) {
        uint32_t type;

        assert_return(m, -EINVAL);

        type = htonl(data);

        return sd_lldp_packet_append_bytes(m, &type, sizeof(uint32_t));
}

int sd_lldp_packet_append_string(sd_lldp_packet *m, char *data, uint16_t size) {

        assert_return(m, -EINVAL);

        return sd_lldp_packet_append_bytes(m, data, size);
}

int sd_lldp_packet_open_container(sd_lldp_packet *m, uint16_t type) {

        assert_return(m, -EINVAL);

        m->container_pos = m->pdu + m->length;

        return sd_lldp_packet_append_u16(m, type << 9);
}

int sd_lldp_packet_close_container(sd_lldp_packet *m) {
        uint16_t type;

        assert_return(m, -EINVAL);
        assert_return(m->container_pos, -EINVAL);

        memcpy(&type, m->container_pos, sizeof(uint16_t));

        type |= htons(((m->pdu + m->length) - (m->container_pos + 2)) & 0x01ff);
        memcpy(m->container_pos, &type, sizeof(uint16_t));

        return 0;
}

static inline int lldp_packet_read_internal(sd_lldp_section *m, void **data) {

        assert_return(m->read_pos, -EINVAL);

        *data = m->read_pos;

        return 0;
}

int sd_lldp_packet_read_u8(sd_lldp_packet *m, uint8_t *data) {
        void *val = NULL;
        int r;

        assert_return(m, -EINVAL);

        r = lldp_packet_read_internal(m->container,  &val);
        if (r < 0)
                return r;

        memcpy(data, val, sizeof(uint8_t));

        m->container->read_pos ++;

        return 0;
}

int sd_lldp_packet_read_u16(sd_lldp_packet *m, uint16_t *data) {
        uint16_t t;
        void *val = NULL;
        int r;

        assert_return(m, -EINVAL);

        r = lldp_packet_read_internal(m->container, &val);
        if (r < 0)
                return r;

        memcpy(&t, val, sizeof(uint16_t));
        *data = ntohs(t);

        m->container->read_pos += 2;

        return 0;
}

int sd_lldp_packet_read_u32(sd_lldp_packet *m, uint32_t *data) {
        uint32_t t;
        void *val;
        int r;

        assert_return(m, -EINVAL);

        r = lldp_packet_read_internal(m->container, &val);
        if (r < 0)
                return r;

        memcpy(&t, val, sizeof(uint32_t));
        *data = ntohl(t);

        m->container->read_pos += 4;

        return r;
}

int sd_lldp_packet_read_string(sd_lldp_packet *m, char **data, uint16_t *data_length) {
        void *val = NULL;
        int r;

        assert_return(m, -EINVAL);

        r = lldp_packet_read_internal(m->container, &val);
        if (r < 0)
                return r;

        *data = (char *) val;
        *data_length = m->container->data + m->container->length - m->container->read_pos;

        m->container->read_pos += *data_length;

        return 0;
}

int sd_lldp_packet_read_bytes(sd_lldp_packet *m, uint8_t **data, uint16_t *data_length) {
        void *val = NULL;
        int r;

        assert_return(m, -EINVAL);

        r = lldp_packet_read_internal(m->container, &val);
        if (r < 0)
                return r;

        *data = (uint8_t *) val;
        *data_length = m->container->data + m->container->length - m->container->read_pos;

        m->container->read_pos += *data_length;

        return 0;
}

/* parse raw TLV packet */
int sd_lldp_packet_parse_pdu(sd_lldp_packet *m, uint16_t size) {
        sd_lldp_section *section, *tail;
        uint16_t t, l;
        uint8_t *p;
        int r;

        assert_return(m, -EINVAL);
        assert_return(size, -EINVAL);

        p = m->pdu;

        /* extract ethernet header */
        memcpy(&m->mac, p, ETH_ALEN);
        p += sizeof(struct ether_header);

        for (l = 0; l <= size; ) {
                r = sd_lldp_section_new(&section);
                if (r < 0)
                        return r;

                memcpy(&t, p, sizeof(uint16_t));

                section->type = ntohs(t) >> 9;
                section->length = ntohs(t) & 0x01ff;

                if (section->type == LLDP_TYPE_END || section->type >=_LLDP_TYPE_MAX) {
                        sd_lldp_section_free(section);
                        break;
                }

                p += 2;

                if (section->type == LLDP_TYPE_PRIVATE &&
                    section->length >= LLDP_OUI_LEN + 1) {
                        section->oui = p;
                        p += LLDP_OUI_LEN;
                        section->subtype = *p++;

                        section->length -= LLDP_OUI_LEN + 1;
                        l += LLDP_OUI_LEN + 1;
                }

                section->data = p;

                LIST_FIND_TAIL(section, m->sections, tail);
                LIST_INSERT_AFTER(section, m->sections, tail, section);

                p += section->length;
                l += (section->length + 2);
        }

        return 0;
}

int sd_lldp_packet_enter_container(sd_lldp_packet *m, uint16_t type) {
        sd_lldp_section *s;

        assert_return(m, -EINVAL);
        assert_return(type != LLDP_TYPE_PRIVATE, -EINVAL);

        LIST_FOREACH(section, s, m->sections)
                if (s->type == type)
                        break;
        if (!s)
                return -1;

        m->container = s;

        m->container->read_pos = s->data;
        if (!m->container->read_pos) {
                m->container = NULL;
                return -1;
        }

        return 0;
}

int sd_lldp_packet_enter_container_oui(sd_lldp_packet *m, const uint8_t *oui, uint8_t subtype) {
        sd_lldp_section *s;

        assert_return(m, -EINVAL);
        assert_return(oui, -EINVAL);

        LIST_FOREACH(section, s, m->sections) {
                if (s->type == LLDP_TYPE_PRIVATE &&
                    s->oui &&
                    s->subtype == subtype &&
                    !memcmp(s->oui, oui, LLDP_OUI_LEN))
                        break;
        }

        if (!s)
                return -1;

        m->container = s;

        m->container->read_pos = s->data;
        if (!m->container->read_pos) {
                m->container = NULL;
                return -1;
        }

        return 0;
}

int sd_lldp_packet_exit_container(sd_lldp_packet *m) {
        assert_return(m, -EINVAL);

        m->container = 0;

        return 0;
}

static int sd_lldp_packet_read_u16_m(sd_lldp_packet *m, uint16_t type, uint16_t *value) {
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container(m, type);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u16(m, value);
        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

static int sd_lldp_packet_read_string_m(sd_lldp_packet *m, uint16_t type, char **data, uint16_t *length) {
        char *s;
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container(m, type);
        if (r < 0)
                return r;

        r = sd_lldp_packet_read_string(m, &s, length);
        if (r < 0)
                goto out;

        *data = (char *) s;

 out:
        r2 = sd_lldp_packet_exit_container(m);

        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_chassis_id(sd_lldp_packet *m,
                                   uint8_t *type,
                                   uint8_t **data,
                                   uint16_t *length) {
        uint8_t subtype;
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container(m, LLDP_TYPE_CHASSIS_ID);
        if (r < 0)
                goto out2;

        r = sd_lldp_packet_read_u8(m, &subtype);
        if (r < 0)
                goto out1;

        switch (subtype) {
        case LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:

                r = sd_lldp_packet_read_bytes(m, data, length);
                if (r < 0)
                        goto out1;

                break;
        default:
                r = -EOPNOTSUPP;
                break;
        }

        *type = subtype;

 out1:
        r2 = sd_lldp_packet_exit_container(m);

 out2:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_port_id(sd_lldp_packet *m,
                                uint8_t *type,
                                uint8_t **data,
                                uint16_t *length) {
        uint8_t subtype;
        char *s;
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container(m, LLDP_TYPE_PORT_ID);
        if (r < 0)
                goto out2;

        r = sd_lldp_packet_read_u8(m, &subtype);
        if (r < 0)
                goto out1;

        switch (subtype) {
        case LLDP_PORT_SUBTYPE_PORT_COMPONENT:
        case LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
        case LLDP_PORT_SUBTYPE_INTERFACE_NAME:
        case LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:

                r = sd_lldp_packet_read_string(m, &s, length);
                if (r < 0)
                        goto out1;

                *data = (uint8_t *) s;

                break;
        case LLDP_PORT_SUBTYPE_MAC_ADDRESS:

                r = sd_lldp_packet_read_bytes(m, data, length);
                if (r < 0)
                        goto out1;

                break;
        default:
                r = -EOPNOTSUPP;
                break;
        }

        *type = subtype;

 out1:
        r2 = sd_lldp_packet_exit_container(m);

 out2:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_ttl(sd_lldp_packet *m, uint16_t *ttl) {
        return sd_lldp_packet_read_u16_m(m, LLDP_TYPE_TTL, ttl);
}

int sd_lldp_packet_read_system_name(sd_lldp_packet *m,
                                    char **data,
                                    uint16_t *length) {
        return sd_lldp_packet_read_string_m(m, LLDP_TYPE_SYSTEM_NAME, data, length);
}

int sd_lldp_packet_read_system_description(sd_lldp_packet *m,
                                           char **data,
                                           uint16_t *length) {
        return sd_lldp_packet_read_string_m(m, LLDP_TYPE_SYSTEM_DESCRIPTION, data, length);
}

int sd_lldp_packet_read_port_description(sd_lldp_packet *m,
                                         char **data,
                                         uint16_t *length) {
        return sd_lldp_packet_read_string_m(m, LLDP_TYPE_PORT_DESCRIPTION, data, length);
}

int sd_lldp_packet_read_system_capability(sd_lldp_packet *m, uint16_t *data) {
        return sd_lldp_packet_read_u16_m(m, LLDP_TYPE_SYSTEM_CAPABILITIES, data);
}

int sd_lldp_packet_read_port_vlan_id(sd_lldp_packet *m, uint16_t *id) {
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container_oui(m, LLDP_OUI_802_1, LLDP_OUI_SUBTYPE_802_1_PORT_VLAN_ID);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u16(m, id);
        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_port_protocol_vlan_id(sd_lldp_packet *m, uint8_t *flags, uint16_t *id) {
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container_oui(m, LLDP_OUI_802_1, LLDP_OUI_SUBTYPE_802_1_PORT_PROTOCOL_VLAN_ID);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u8(m, flags);
        if (r >= 0)
                r = sd_lldp_packet_read_u16(m, id);

        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_vlan_name(sd_lldp_packet *m, uint16_t *vlan_id, char **name, uint16_t *length) {
        int r, r2;
        uint8_t len = 0;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container_oui(m, LLDP_OUI_802_1, LLDP_OUI_SUBTYPE_802_1_VLAN_NAME);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u16(m, vlan_id);
        if (r >= 0)
                r = sd_lldp_packet_read_u8(m, &len);
        if (r >= 0)
                r = sd_lldp_packet_read_string(m, name, length);

        if (r >= 0 && len < *length)
                *length = len;

        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_management_vid(sd_lldp_packet *m, uint16_t *id) {
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container_oui(m, LLDP_OUI_802_1, LLDP_OUI_SUBTYPE_802_1_MANAGEMENT_VID);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u16(m, id);
        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_read_link_aggregation(sd_lldp_packet *m, uint8_t *status, uint32_t *id) {
        int r, r2;

        assert_return(m, -EINVAL);

        r = sd_lldp_packet_enter_container_oui(m, LLDP_OUI_802_1, LLDP_OUI_SUBTYPE_802_1_LINK_AGGREGATION);
        if (r < 0)
                goto out;

        r = sd_lldp_packet_read_u8(m, status);
        if (r >= 0)
                r = sd_lldp_packet_read_u32(m, id);

        r2 = sd_lldp_packet_exit_container(m);

 out:
        return r < 0 ? r : r2;
}

int sd_lldp_packet_get_destination_type(sd_lldp_packet *m, int *dest) {
        assert_return(m, -EINVAL);
        assert_return(dest, -EINVAL);

        /* 802.1AB-2009, Table 7-1 */
        if (!memcmp(&m->mac, LLDP_MAC_NEAREST_BRIDGE, ETH_ALEN))
                *dest = SD_LLDP_DESTINATION_TYPE_NEAREST_BRIDGE;
        else if (!memcmp(&m->mac, LLDP_MAC_NEAREST_NON_TPMR_BRIDGE, ETH_ALEN))
                *dest = SD_LLDP_DESTINATION_TYPE_NEAREST_NON_TPMR_BRIDGE;
        else if (!memcmp(&m->mac, LLDP_MAC_NEAREST_CUSTOMER_BRIDGE, ETH_ALEN))
                *dest = SD_LLDP_DESTINATION_TYPE_NEAREST_CUSTOMER_BRIDGE;
        else
                return -EINVAL;

        return 0;
}
