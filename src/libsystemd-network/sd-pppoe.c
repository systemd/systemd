/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen

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

/* See RFC 2516 */

#include <sys/ioctl.h>
#include <linux/ppp_defs.h>
#include <linux/ppp-ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_pppox.h>

#include "sd-pppoe.h"

#include "event-util.h"

#include "util.h"
#include "random-util.h"
#include "socket-util.h"
#include "async.h"
#include "utf8.h"

#define PPPOE_MAX_PACKET_SIZE 1484
#define PPPOE_MAX_PADR_RESEND 16

/* TODO: move this to socket-util.h without getting into
 * a mess with the includes */
union sockaddr_union_pppox {
        struct sockaddr sa;
        struct sockaddr_pppox pppox;
};

typedef enum PPPoEState {
        PPPOE_STATE_INITIALIZING,
        PPPOE_STATE_REQUESTING,
        PPPOE_STATE_RUNNING,
        PPPOE_STATE_STOPPED,
        _PPPOE_STATE_MAX,
        _PPPOE_STATE_INVALID = -1,
} PPPoEState;

typedef struct PPPoETags {
                char *service_name;
                char *ac_name;
                uint8_t *host_uniq;
                size_t host_uniq_len;
                uint8_t *cookie;
                size_t cookie_len;
} PPPoETags;

struct sd_pppoe {
        unsigned n_ref;

        PPPoEState state;
        uint64_t host_uniq;

        int ifindex;
        char *ifname;

        sd_event *event;
        int event_priority;
        int fd;
        sd_event_source *io;
        sd_event_source *timeout;
        int padr_resend_count;

        char *service_name;
        struct ether_addr peer_mac;
        be16_t session_id;

        int pppoe_fd;
        int channel;

        sd_pppoe_cb_t cb;
        void *userdata;

        PPPoETags tags;
};

#define PPPOE_PACKET_LENGTH(header) \
        be16toh((header)->length)

#define PPPOE_PACKET_TAIL(packet)                                                                               \
        (struct pppoe_tag*)((uint8_t*)(packet) + sizeof(struct pppoe_hdr) + PPPOE_PACKET_LENGTH(packet))

#define PPPOE_TAG_LENGTH(tag)  \
        be16toh((tag)->tag_len)

#define PPPOE_TAG_TYPE(tag) \
        (tag)->tag_type

#define PPPOE_TAG_NEXT(tag)                                                                      \
        (struct pppoe_tag *)((uint8_t *)(tag) + sizeof(struct pppoe_tag) + PPPOE_TAG_LENGTH(tag))

#define PPPOE_TAGS_FOREACH(tag, header)                                                                 \
        for (tag = (header)->tag;                                                                       \
             ((uint8_t *)(tag) + sizeof(struct pppoe_tag) < (uint8_t*)PPPOE_PACKET_TAIL(header)) &&     \
                (PPPOE_TAG_NEXT(tag) <= PPPOE_PACKET_TAIL(header)) &&                                   \
                (tag >= (header)->tag) &&                                                               \
                (PPPOE_TAG_TYPE(tag) != PTT_EOL);                                                           \
             tag = PPPOE_TAG_NEXT(tag))

static void pppoe_tags_clear(PPPoETags *tags) {
        free(tags->service_name);
        free(tags->ac_name);
        free(tags->host_uniq);
        free(tags->cookie);

        zero(*tags);
}

int sd_pppoe_set_ifindex(sd_pppoe *ppp, int ifindex) {
        assert_return(ppp, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        ppp->ifindex = ifindex;

        return 0;
}

int sd_pppoe_set_ifname(sd_pppoe *ppp, const char *ifname) {
        char *name;

        assert_return(ppp, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (strlen(ifname) > IFNAMSIZ)
                return -EINVAL;

        name = strdup(ifname);
        if (!name)
                return -ENOMEM;

        free(ppp->ifname);
        ppp->ifname = name;

        return 0;
}

int sd_pppoe_set_service_name(sd_pppoe *ppp, const char *service_name) {
        _cleanup_free_ char *name = NULL;

        assert_return(ppp, -EINVAL);

        if (service_name) {
                name = strdup(service_name);
                if (!name)
                        return -ENOMEM;
        }

        free(ppp->service_name);
        ppp->service_name = name;
        name = NULL;

        return 0;
}

int sd_pppoe_attach_event(sd_pppoe *ppp, sd_event *event, int priority) {
        int r;

        assert_return(ppp, -EINVAL);
        assert_return(!ppp->event, -EBUSY);

        if (event)
                ppp->event = sd_event_ref(event);
        else {
                r = sd_event_default(&ppp->event);
                if (r < 0)
                        return r;
        }

        ppp->event_priority = priority;

        return 0;
}

int sd_pppoe_detach_event(sd_pppoe *ppp) {
        assert_return(ppp, -EINVAL);

        ppp->event = sd_event_unref(ppp->event);

        return 0;
}

sd_pppoe *sd_pppoe_ref(sd_pppoe *ppp) {

        if (!ppp)
                return NULL;

        assert(ppp->n_ref > 0);
        ppp->n_ref++;

        return ppp;
}

sd_pppoe *sd_pppoe_unref(sd_pppoe *ppp) {

        if (!ppp)
                return NULL;

        assert(ppp->n_ref > 0);
        ppp->n_ref--;

        if (ppp->n_ref > 0)
                return NULL;

        pppoe_tags_clear(&ppp->tags);
        free(ppp->ifname);
        free(ppp->service_name);
        sd_pppoe_stop(ppp);
        sd_pppoe_detach_event(ppp);

        free(ppp);
        return NULL;
}

int sd_pppoe_new (sd_pppoe **ret) {
        sd_pppoe *ppp;

        assert_return(ret, -EINVAL);

        ppp = new0(sd_pppoe, 1);
        if (!ppp)
                return -ENOMEM;

        ppp->n_ref = 1;
        ppp->state = _PPPOE_STATE_INVALID;
        ppp->ifindex = -1;
        ppp->fd = -1;
        ppp->pppoe_fd = -1;
        ppp->padr_resend_count = PPPOE_MAX_PADR_RESEND;

        *ret = ppp;

        return 0;
}

int sd_pppoe_get_channel(sd_pppoe *ppp, int *channel) {
        assert_return(ppp, -EINVAL);
        assert_return(channel, -EINVAL);
        assert_return(ppp->pppoe_fd != -1, -EUNATCH);
        assert_return(ppp->state == PPPOE_STATE_RUNNING, -EUNATCH);

        *channel = ppp->channel;

        return 0;
}

int sd_pppoe_set_callback(sd_pppoe *ppp, sd_pppoe_cb_t cb, void *userdata) {
        assert_return(ppp, -EINVAL);

        ppp->cb = cb;
        ppp->userdata = userdata;

        return 0;
}

static void pppoe_tag_append(struct pppoe_hdr *packet, size_t packet_size, be16_t tag_type, const void *tag_data, uint16_t tag_len) {
        struct pppoe_tag *tag;

        assert(packet);
        assert(sizeof(struct pppoe_hdr) + PPPOE_PACKET_LENGTH(packet) + sizeof(struct pppoe_tag) + tag_len <= packet_size);
        assert(!(!tag_data ^ !tag_len));

        tag = PPPOE_PACKET_TAIL(packet);

        tag->tag_len = htobe16(tag_len);
        tag->tag_type = tag_type;
        if (tag_data)
                memcpy(tag->tag_data, tag_data, tag_len);

        packet->length = htobe16(PPPOE_PACKET_LENGTH(packet) + sizeof(struct pppoe_tag) + tag_len);
}

static int pppoe_send(sd_pppoe *ppp, uint8_t code) {
        union sockaddr_union link = {
                .ll = {
                        .sll_family = AF_PACKET,
                        .sll_protocol = htons(ETH_P_PPP_DISC),
                        .sll_halen = ETH_ALEN,
                },
        };
        _cleanup_free_ struct pppoe_hdr *packet = NULL;
        int r;

        assert(ppp);
        assert(ppp->fd != -1);
        assert(IN_SET(code, PADI_CODE, PADR_CODE, PADT_CODE));

        link.ll.sll_ifindex = ppp->ifindex;
        if (code == PADI_CODE)
                memset(&link.ll.sll_addr, 0xff, ETH_ALEN);
        else
                memcpy(&link.ll.sll_addr, &ppp->peer_mac, ETH_ALEN);

        packet = malloc0(PPPOE_MAX_PACKET_SIZE);
        if (!packet)
                return -ENOMEM;

        packet->ver = 0x1;
        packet->type = 0x1;
        packet->code = code;
        if (code == PADT_CODE)
                packet->sid = ppp->session_id;

        /* Service-Name */
        pppoe_tag_append(packet, PPPOE_MAX_PACKET_SIZE, PTT_SRV_NAME,
                         ppp->service_name, ppp->service_name ? strlen(ppp->service_name) : 0);

        /* AC-Cookie */
        if (code == PADR_CODE && ppp->tags.cookie)
                pppoe_tag_append(packet, PPPOE_MAX_PACKET_SIZE, PTT_AC_COOKIE,
                                 ppp->tags.cookie, ppp->tags.cookie_len);

        /* Host-Uniq */
        if (code != PADT_CODE) {
                ppp->host_uniq = random_u64();

                pppoe_tag_append(packet, PPPOE_MAX_PACKET_SIZE, PTT_HOST_UNIQ,
                                 &ppp->host_uniq, sizeof(ppp->host_uniq));
        }

        r = sendto(ppp->fd, packet, sizeof(struct pppoe_hdr) + PPPOE_PACKET_LENGTH(packet),
                   0, &link.sa, sizeof(link.ll));
        if (r < 0)
                return -errno;

        return 0;
}

static int pppoe_timeout(sd_event_source *s, uint64_t usec, void *userdata);

static int pppoe_arm_timeout(sd_pppoe *ppp) {
        _cleanup_event_source_unref_ sd_event_source *timeout = NULL;
        usec_t next_timeout = 0;
        int r;

        assert(ppp);

        r = sd_event_now(ppp->event, clock_boottime_or_monotonic(), &next_timeout);
        if (r < 0)
                return r;

        next_timeout += 500 * USEC_PER_MSEC;

        r = sd_event_add_time(ppp->event, &timeout, clock_boottime_or_monotonic(), next_timeout,
                              10 * USEC_PER_MSEC, pppoe_timeout, ppp);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(timeout, ppp->event_priority);
        if (r < 0)
                return r;

        sd_event_source_unref(ppp->timeout);
        ppp->timeout = timeout;
        timeout = NULL;

        return 0;
}

static int pppoe_send_initiation(sd_pppoe *ppp) {
        int r;

        r = pppoe_send(ppp, PADI_CODE);
        if (r < 0)
                return r;

        log_debug("PPPoE: sent DISCOVER (Service-Name: %s)",
                  strna(ppp->service_name));

        pppoe_arm_timeout(ppp);

        return r;
}

static int pppoe_send_request(sd_pppoe *ppp) {
        int r;

        r = pppoe_send(ppp, PADR_CODE);
        if (r < 0)
                return r;

        log_debug("PPPoE: sent REQUEST");

        ppp->padr_resend_count --;

        pppoe_arm_timeout(ppp);

        return 0;
}

static int pppoe_send_terminate(sd_pppoe *ppp) {
        int r;

        r = pppoe_send(ppp, PADT_CODE);
        if (r < 0)
                return r;

        log_debug("PPPoE: sent TERMINATE");

        return 0;
}

static int pppoe_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_pppoe *ppp = userdata;
        int r;

        assert(ppp);

        switch (ppp->state) {
        case PPPOE_STATE_INITIALIZING:
                r = pppoe_send_initiation(ppp);
                if (r < 0)
                        log_warning_errno(r, "PPPoE: sending PADI failed: %m");

                break;
        case PPPOE_STATE_REQUESTING:
                if (ppp->padr_resend_count <= 0) {
                        log_debug("PPPoE: PADR timed out, restarting PADI");

                        r = pppoe_send_initiation(ppp);
                        if (r < 0)
                                log_warning_errno(r, "PPPoE: sending PADI failed: %m");

                        ppp->padr_resend_count = PPPOE_MAX_PADR_RESEND;
                        ppp->state = PPPOE_STATE_INITIALIZING;
                } else {
                        r = pppoe_send_request(ppp);
                        if (r < 0)
                                log_warning_errno(r, "PPPoE: sending PADR failed: %m");
                }

                break;
        default:
                assert_not_reached("timeout in invalid state");
        }

        return 0;
}

static int pppoe_tag_parse_binary(struct pppoe_tag *tag, uint8_t **ret, size_t *length) {
        uint8_t *data;

        assert(ret);
        assert(length);

        data = memdup(tag->tag_data, PPPOE_TAG_LENGTH(tag));
        if (!data)
                return -ENOMEM;

        free(*ret);
        *ret = data;
        *length = PPPOE_TAG_LENGTH(tag);

        return 0;
}

static int pppoe_tag_parse_string(struct pppoe_tag *tag, char **ret) {
        char *string;

        assert(ret);

        string = strndup(tag->tag_data, PPPOE_TAG_LENGTH(tag));
        if (!string)
                return -ENOMEM;

        free(*ret);
        *ret = string;

        return 0;
}

static int pppoe_payload_parse(PPPoETags *tags, struct pppoe_hdr *header) {
        struct pppoe_tag *tag;
        int r;

        assert(tags);

        pppoe_tags_clear(tags);

        PPPOE_TAGS_FOREACH(tag, header) {
                switch (PPPOE_TAG_TYPE(tag)) {
                case PTT_SRV_NAME:
                        r = pppoe_tag_parse_string(tag, &tags->service_name);
                        if (r < 0)
                                return r;

                        break;
                case PTT_AC_NAME:
                        r = pppoe_tag_parse_string(tag, &tags->ac_name);
                        if (r < 0)
                                return r;

                        break;
                case PTT_HOST_UNIQ:
                        r = pppoe_tag_parse_binary(tag, &tags->host_uniq, &tags->host_uniq_len);
                        if (r < 0)
                                return r;

                        break;
                case PTT_AC_COOKIE:
                        r = pppoe_tag_parse_binary(tag, &tags->cookie, &tags->cookie_len);
                        if (r < 0)
                                return r;

                        break;
                case PTT_SRV_ERR:
                case PTT_SYS_ERR:
                case PTT_GEN_ERR:
                {
                        _cleanup_free_ char *error = NULL;

                        /* TODO: do something more sensible with the error messages */
                        r = pppoe_tag_parse_string(tag, &error);
                        if (r < 0)
                                return r;

                        if (strlen(error) > 0 && utf8_is_valid(error))
                                log_debug("PPPoE: error - '%s'", error);
                        else
                                log_debug("PPPoE: error");

                        break;
                }
                default:
                        log_debug("PPPoE: ignoring unknown PPPoE tag type: 0x%.2x", PPPOE_TAG_TYPE(tag));
                }
        }

        return 0;
}

static int pppoe_open_pppoe_socket(sd_pppoe *ppp) {
        int s;

        assert(ppp);
        assert(ppp->pppoe_fd == -1);

        s = socket(AF_PPPOX, SOCK_STREAM, 0);
        if (s < 0)
                return -errno;

        ppp->pppoe_fd = s;

        return 0;
}

static int pppoe_connect_pppoe_socket(sd_pppoe *ppp) {
        union sockaddr_union_pppox link = {
                .pppox = {
                        .sa_family = AF_PPPOX,
                        .sa_protocol = PX_PROTO_OE,
                },
        };
        int r, channel;

        assert(ppp);
        assert(ppp->pppoe_fd != -1);
        assert(ppp->session_id);
        assert(ppp->ifname);

        link.pppox.sa_addr.pppoe.sid = ppp->session_id;
        memcpy(link.pppox.sa_addr.pppoe.dev, ppp->ifname, strlen(ppp->ifname));
        memcpy(link.pppox.sa_addr.pppoe.remote, &ppp->peer_mac, ETH_ALEN);

        r = connect(ppp->pppoe_fd, &link.sa, sizeof(link.pppox));
        if (r < 0)
                return r;

        r = ioctl(ppp->pppoe_fd, PPPIOCGCHAN, &channel);
        if (r < 0)
                return -errno;

        ppp->channel = channel;

        return 0;
}

static int pppoe_handle_message(sd_pppoe *ppp, struct pppoe_hdr *packet, struct ether_addr *mac) {
        int r;

        assert(packet);

        if (packet->ver != 0x1 || packet->type != 0x1)
                return 0;

        r = pppoe_payload_parse(&ppp->tags, packet);
        if (r < 0)
                return 0;

        switch (ppp->state) {
        case PPPOE_STATE_INITIALIZING:
                if (packet->code != PADO_CODE)
                        return 0;

                if (ppp->tags.host_uniq_len != sizeof(ppp->host_uniq) ||
                    memcmp(ppp->tags.host_uniq, &ppp->host_uniq, sizeof(ppp->host_uniq)) != 0)
                        return 0;

                log_debug("PPPoE: got OFFER (Peer: "
                  "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx; "
                  "Service-Name: '%s'; AC-Name: '%s')",
                  mac->ether_addr_octet[0],
                  mac->ether_addr_octet[1],
                  mac->ether_addr_octet[2],
                  mac->ether_addr_octet[3],
                  mac->ether_addr_octet[4],
                  mac->ether_addr_octet[5],
                  strempty(ppp->tags.service_name),
                  strempty(ppp->tags.ac_name));

                memcpy(&ppp->peer_mac, mac, ETH_ALEN);

                r = pppoe_open_pppoe_socket(ppp);
                if (r < 0) {
                        log_warning("PPPoE: could not open socket");
                        return r;
                }

                r = pppoe_send_request(ppp);
                if (r < 0)
                        return 0;

                ppp->state = PPPOE_STATE_REQUESTING;

                break;
        case PPPOE_STATE_REQUESTING:
                if (packet->code != PADS_CODE)
                        return 0;

                if (ppp->tags.host_uniq_len != sizeof(ppp->host_uniq) ||
                    memcmp(ppp->tags.host_uniq, &ppp->host_uniq,
                           sizeof(ppp->host_uniq)) != 0)
                        return 0;

                if (memcmp(&ppp->peer_mac, mac, ETH_ALEN) != 0)
                        return 0;

                ppp->session_id = packet->sid;

                log_debug("PPPoE: got CONFIRMATION (Session ID: %"PRIu16")",
                          be16toh(ppp->session_id));

                r = pppoe_connect_pppoe_socket(ppp);
                if (r < 0) {
                        log_warning("PPPoE: could not connect socket");
                        return r;
                }

                ppp->state = PPPOE_STATE_RUNNING;

                ppp->timeout = sd_event_source_unref(ppp->timeout);
                assert(ppp->cb);
                ppp->cb(ppp, SD_PPPOE_EVENT_RUNNING, ppp->userdata);

                break;
        case PPPOE_STATE_RUNNING:
                if (packet->code != PADT_CODE)
                        return 0;

                if (memcmp(&ppp->peer_mac, mac, ETH_ALEN) != 0)
                        return 0;

                if (ppp->session_id != packet->sid)
                        return 0;

                log_debug("PPPoE: got TERMINATE");

                ppp->state = PPPOE_STATE_STOPPED;

                assert(ppp->cb);
                ppp->cb(ppp, SD_PPPOE_EVENT_STOPPED, ppp->userdata);

                break;
        case PPPOE_STATE_STOPPED:
                break;
        default:
                assert_not_reached("PPPoE: invalid state when receiving message");
        }

        return 0;
}

static int pppoe_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_pppoe *ppp = userdata;
        _cleanup_free_ struct pppoe_hdr *packet = NULL;
        union sockaddr_union link = {};
        socklen_t addrlen = sizeof(link);
        int buflen = 0, len, r;

        assert(ppp);
        assert(fd != -1);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0)
                return r;

        if (buflen < 0)
                /* this can't be right */
                return -EIO;

        packet = malloc0(buflen);
        if (!packet)
                return -ENOMEM;

        len = recvfrom(fd, packet, buflen, 0, &link.sa, &addrlen);
        if (len < 0) {
                log_warning_errno(r, "PPPoE: could not receive message from raw socket: %m");
                return 0;
        } else if ((size_t)len < sizeof(struct pppoe_hdr))
                return 0;
        else if ((size_t)len != sizeof(struct pppoe_hdr) + PPPOE_PACKET_LENGTH(packet))
                return 0;

        if (link.ll.sll_halen != ETH_ALEN)
                /* not ethernet? */
                return 0;

        r = pppoe_handle_message(ppp, packet, (struct ether_addr*)&link.ll.sll_addr);
        if (r < 0)
                return r;

        return 1;
}

int sd_pppoe_start(sd_pppoe *ppp) {
        union sockaddr_union link = {
                .ll = {
                        .sll_family = AF_PACKET,
                        .sll_protocol = htons(ETH_P_PPP_DISC),
                },
        };
        _cleanup_close_ int s = -1;
        _cleanup_event_source_unref_ sd_event_source *io = NULL;
        int r;

        assert_return(ppp, -EINVAL);
        assert_return(ppp->fd == -1, -EBUSY);
        assert_return(!ppp->io, -EBUSY);
        assert_return(ppp->ifindex > 0, -EUNATCH);
        assert_return(ppp->ifname, -EUNATCH);
        assert_return(ppp->event, -EUNATCH);
        assert_return(ppp->cb, -EUNATCH);

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        link.ll.sll_ifindex = ppp->ifindex;

        r = bind(s, &link.sa, sizeof(link.ll));
        if (r < 0)
                return r;

        r = sd_event_add_io(ppp->event, &io,
                            s, EPOLLIN, pppoe_receive_message,
                            ppp);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(io, ppp->event_priority);
        if (r < 0)
                return r;

        ppp->fd = s;
        s = -1;
        ppp->io = io;
        io = NULL;

        r = pppoe_send_initiation(ppp);
        if (r < 0)
                return r;

        ppp->state = PPPOE_STATE_INITIALIZING;

        return 0;
}

int sd_pppoe_stop(sd_pppoe *ppp) {
        assert_return(ppp, -EINVAL);

        if (ppp->state == PPPOE_STATE_RUNNING)
                pppoe_send_terminate(ppp);

        ppp->io = sd_event_source_unref(ppp->io);
        ppp->timeout = sd_event_source_unref(ppp->timeout);
        ppp->fd = asynchronous_close(ppp->fd);
        ppp->pppoe_fd = asynchronous_close(ppp->pppoe_fd);

        return 0;
}
