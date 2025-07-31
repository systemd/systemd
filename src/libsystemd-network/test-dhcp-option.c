/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>

#include "alloc-util.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "memory-util.h"
#include "tests.h"

struct option_desc {
        uint8_t sname[64];
        int snamelen;
        uint8_t file[128];
        int filelen;
        uint8_t options[128];
        int len;
        bool success;
        int filepos;
        int snamepos;
        int pos;
};

static bool verbose = false;

static struct option_desc option_tests[] = {
        { {}, 0, {}, 0, { 42, 5, 65, 66, 67, 68, 69 }, 7, false, },
        { {}, 0, {}, 0, { 42, 5, 65, 66, 67, 68, 69, 0, 0,
                          SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK }, 12, true, },
        { {}, 0, {}, 0, { 8, 255, 70, 71, 72 }, 5, false, },
        { {}, 0, {}, 0, { 0x35, 0x01, 0x05, 0x36, 0x04, 0x01, 0x00, 0xa8,
                          0xc0, 0x33, 0x04, 0x00, 0x01, 0x51, 0x80, 0x01,
                          0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0,
                          0xa8, 0x00, 0x01, 0x06, 0x04, 0xc0, 0xa8, 0x00,
                          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
          40, true, },
        { {}, 0, {}, 0, { SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_OFFER,
                          42, 3, 0, 0, 0 }, 8, true, },
        { {}, 0, {}, 0, { 42, 2, 1, 2, 44 }, 5, false, },

        { {}, 0,
          { 222, 3, 1, 2, 3, SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_NAK }, 8,
          { SD_DHCP_OPTION_OVERLOAD, 1, DHCP_OVERLOAD_FILE }, 3, true, },

        { { 1, 4, 1, 2, 3, 4, SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK }, 9,
          { 222, 3, 1, 2, 3 }, 5,
          { SD_DHCP_OPTION_OVERLOAD, 1,
            DHCP_OVERLOAD_FILE|DHCP_OVERLOAD_SNAME }, 3, true, },
};

static const char *dhcp_type(int type) {
        switch (type) {
        case DHCP_DISCOVER:
                return "DHCPDISCOVER";
        case DHCP_OFFER:
                return "DHCPOFFER";
        case DHCP_REQUEST:
                return "DHCPREQUEST";
        case DHCP_DECLINE:
                return "DHCPDECLINE";
        case DHCP_ACK:
                return "DHCPACK";
        case DHCP_NAK:
                return "DHCPNAK";
        case DHCP_RELEASE:
                return "DHCPRELEASE";
        default:
                return "unknown";
        }
}

static void test_invalid_buffer_length(void) {
        DHCPMessage message;

        assert_se(dhcp_option_parse(&message, 0, NULL, NULL, NULL) == -EINVAL);
        assert_se(dhcp_option_parse(&message, sizeof(DHCPMessage) - 1, NULL, NULL, NULL) == -EINVAL);
}

static void test_message_init(void) {
        _cleanup_free_ DHCPMessage *message = NULL;
        size_t optlen = 4, optoffset;
        size_t len = sizeof(DHCPMessage) + optlen;
        uint8_t *magic;

        message = malloc0(len);

        assert_se(dhcp_message_init(message, BOOTREQUEST, 0x12345678,
                                    ARPHRD_ETHER, ETH_ALEN, (uint8_t[16]){}, DHCP_DISCOVER,
                                    optlen, &optoffset) >= 0);

        assert_se(message->xid == htobe32(0x12345678));
        assert_se(message->op == BOOTREQUEST);

        magic = (uint8_t*)&message->magic;

        assert_se(magic[0] == 99);
        assert_se(magic[1] == 130);
        assert_se(magic[2] == 83);
        assert_se(magic[3] == 99);

        assert_se(dhcp_option_parse(message, len, NULL, NULL, NULL) >= 0);
}

static DHCPMessage *create_message(uint8_t *options, uint16_t optlen,
                uint8_t *file, uint8_t filelen,
                uint8_t *sname, uint8_t snamelen) {
        DHCPMessage *message;
        size_t len = sizeof(DHCPMessage) + optlen;

        message = malloc0(len);
        assert_se(message);

        memcpy_safe(&message->options, options, optlen);
        memcpy_safe(&message->file, file, filelen);
        memcpy_safe(&message->sname, sname, snamelen);

        return message;
}

static void test_ignore_opts(uint8_t *descoption, int *descpos, int *desclen) {
        assert_se(*descpos >= 0);

        while (*descpos < *desclen) {
                switch (descoption[*descpos]) {
                case SD_DHCP_OPTION_PAD:
                        *descpos += 1;
                        break;

                case SD_DHCP_OPTION_MESSAGE_TYPE:
                case SD_DHCP_OPTION_OVERLOAD:
                        *descpos += 3;
                        break;

                default:
                        return;
                }
        }
}

static int test_options_cb(uint8_t code, uint8_t len, const void *option, void *userdata) {
        struct option_desc *desc = userdata;
        uint8_t *descoption = NULL;
        int *desclen = NULL, *descpos = NULL;
        uint8_t optcode = 0;
        uint8_t optlen = 0;

        assert_se((!desc && !code && !len) || desc);

        if (!desc)
                return -EINVAL;

        assert_se(code != SD_DHCP_OPTION_PAD);
        assert_se(code != SD_DHCP_OPTION_END);
        assert_se(code != SD_DHCP_OPTION_MESSAGE_TYPE);
        assert_se(code != SD_DHCP_OPTION_OVERLOAD);

        while (desc->pos >= 0 || desc->filepos >= 0 || desc->snamepos >= 0) {

                if (desc->pos >= 0) {
                        descoption = &desc->options[0];
                        desclen = &desc->len;
                        descpos = &desc->pos;
                } else if (desc->filepos >= 0) {
                        descoption = &desc->file[0];
                        desclen = &desc->filelen;
                        descpos = &desc->filepos;
                } else if (desc->snamepos >= 0) {
                        descoption = &desc->sname[0];
                        desclen = &desc->snamelen;
                        descpos = &desc->snamepos;
                }

                assert_se(descoption && desclen && descpos);

                if (*desclen)
                        test_ignore_opts(descoption, descpos, desclen);

                if (*descpos < *desclen)
                        break;

                if (*descpos == *desclen)
                        *descpos = -1;
        }

        assert_se(descpos);
        assert_se(*descpos != -1);

        optcode = descoption[*descpos];
        optlen = descoption[*descpos + 1];

        if (verbose)
                printf("DHCP code %2d(%2d) len %2d(%2d) ", code, optcode,
                                len, optlen);

        assert_se(code == optcode);
        assert_se(len == optlen);

        for (unsigned i = 0; i < len; i++) {
                if (verbose)
                        printf("0x%02x(0x%02x) ",
                               ((uint8_t*) option)[i],
                               descoption[*descpos + 2 + i]);

                assert_se(((uint8_t*) option)[i] == descoption[*descpos + 2 + i]);
        }

        if (verbose)
                printf("\n");

        *descpos += optlen + 2;

        test_ignore_opts(descoption, descpos, desclen);

        if (desc->pos != -1 && desc->pos == desc->len)
                desc->pos = -1;

        if (desc->filepos != -1 && desc->filepos == desc->filelen)
                desc->filepos = -1;

        if (desc->snamepos != -1 && desc->snamepos == desc->snamelen)
                desc->snamepos = -1;

        return 0;
}

static void test_options(struct option_desc *desc) {
        uint8_t *options = NULL;
        uint8_t *file = NULL;
        uint8_t *sname = NULL;
        int optlen = 0;
        int filelen = 0;
        int snamelen = 0;
        int buflen = 0;
        _cleanup_free_ DHCPMessage *message = NULL;
        int res;

        if (desc) {
                file = &desc->file[0];
                filelen = desc->filelen;
                if (!filelen)
                        desc->filepos = -1;

                sname = &desc->sname[0];
                snamelen = desc->snamelen;
                if (!snamelen)
                        desc->snamepos = -1;

                options = &desc->options[0];
                optlen = desc->len;
                desc->pos = 0;
        }
        message = create_message(options, optlen, file, filelen,
                                 sname, snamelen);

        buflen = sizeof(DHCPMessage) + optlen;

        if (!desc) {
                assert_se((res = dhcp_option_parse(message, buflen, test_options_cb, NULL, NULL)) == -ENOMSG);
        } else if (desc->success) {
                assert_se((res = dhcp_option_parse(message, buflen, test_options_cb, desc, NULL)) >= 0);
                assert_se(desc->pos == -1 && desc->filepos == -1 && desc->snamepos == -1);
        } else
                assert_se((res = dhcp_option_parse(message, buflen, test_options_cb, desc, NULL)) < 0);

        if (verbose)
                printf("DHCP type %s\n", dhcp_type(res));
}

static void test_option_removal(struct option_desc *desc) {
        _cleanup_free_ DHCPMessage *message = create_message(&desc->options[0], desc->len, NULL, 0, NULL, 0);

        assert_se(dhcp_option_parse(message, sizeof(DHCPMessage) + desc->len, NULL, NULL, NULL) >= 0);
        assert_se((desc->len = dhcp_option_remove_option(message->options, desc->len, SD_DHCP_OPTION_MESSAGE_TYPE)) >= 0);
        assert_se(dhcp_option_parse(message, sizeof(DHCPMessage) + desc->len, NULL, NULL, NULL) < 0);
}

static uint8_t the_options[64] = {
        'A', 'B', 'C', 'D',
        160, 2, 0x11, 0x12,
        0,
        31, 8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0,
        55, 3, 0x51, 0x52, 0x53,
        17, 7, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        255
};

static void test_option_set(void) {
        _cleanup_free_ DHCPMessage *result = NULL;
        size_t offset = 0, len, pos;

        result = malloc0(sizeof(DHCPMessage) + 11);
        assert_se(result);

        result->options[0] = 'A';
        result->options[1] = 'B';
        result->options[2] = 'C';
        result->options[3] = 'D';

        assert_se(dhcp_option_append(result, 0, &offset, 0, SD_DHCP_OPTION_PAD,
                                     0, NULL) == -ENOBUFS);
        assert_se(offset == 0);

        offset = 4;
        assert_se(dhcp_option_append(result, 5, &offset, 0, SD_DHCP_OPTION_PAD,
                                     0, NULL) == -ENOBUFS);
        assert_se(offset == 4);
        assert_se(dhcp_option_append(result, 6, &offset, 0, SD_DHCP_OPTION_PAD,
                                     0, NULL) >= 0);
        assert_se(offset == 5);

        offset = pos = 4;
        len = 11;
        while (pos < len && the_options[pos] != SD_DHCP_OPTION_END) {
                assert_se(dhcp_option_append(result, len, &offset, DHCP_OVERLOAD_SNAME,
                                             the_options[pos],
                                             the_options[pos + 1],
                                             &the_options[pos + 2]) >= 0);

                if (the_options[pos] == SD_DHCP_OPTION_PAD)
                        pos++;
                else
                        pos += 2 + the_options[pos + 1];

                if (pos < len)
                        assert_se(offset == pos);
        }

        for (unsigned i = 0; i < 9; i++) {
                if (verbose)
                        printf("%2u: 0x%02x(0x%02x) (options)\n", i, result->options[i],
                               the_options[i]);
                assert_se(result->options[i] == the_options[i]);
        }

        if (verbose)
                printf("%2d: 0x%02x(0x%02x) (options)\n", 9, result->options[9],
                       (unsigned) SD_DHCP_OPTION_END);

        assert_se(result->options[9] == SD_DHCP_OPTION_END);

        if (verbose)
                printf("%2d: 0x%02x(0x%02x) (options)\n", 10, result->options[10],
                       (unsigned) SD_DHCP_OPTION_PAD);

        assert_se(result->options[10] == SD_DHCP_OPTION_PAD);

        for (unsigned i = 0; i < pos - 8; i++) {
                if (verbose)
                        printf("%2u: 0x%02x(0x%02x) (sname)\n", i, result->sname[i],
                               the_options[i + 9]);
                assert_se(result->sname[i] == the_options[i + 9]);
        }

        if (verbose)
                printf ("\n");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_invalid_buffer_length();
        test_message_init();

        test_options(NULL);

        FOREACH_ELEMENT(desc, option_tests)
                test_options(desc);

        test_option_set();

        FOREACH_ELEMENT(desc, option_tests) {
                if (!desc->success || desc->snamelen > 0 || desc->filelen > 0)
                        continue;
                test_option_removal(desc);
        }

        return 0;
}
