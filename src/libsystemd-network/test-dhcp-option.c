/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "alloc-util.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "ether-addr-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "sd-dhcp-protocol.h"
#include "tests.h"

struct opt_overrides {
        uint8_t code;
        uint8_t data[128];
        size_t len;
};

struct option_desc {
        uint8_t sname[64];
        size_t snamelen;
        uint8_t file[128];
        size_t filelen;
        uint8_t options[128];
        size_t len;
        bool success;
        struct opt_overrides overrides[16];
        size_t overrideslen;
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
        /* test RFC3396: option split across multiple options, cut at an arbitrary byte boundary.
         * Example here for a routing table, where the split is in the middle of the route.
         * In practice, this will happen when the routes don't fit in a single option, but the
         * behavior will likely be the same.
         */
        {
                .options = {
                        SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK,
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 4, 22, 172, 16, 0,
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 4, 0, 0, 0, 0,
                },
                .len = 15,
                .success = true,
                /* the whole option must be reconstituted, so let's override the payload */
                .overrides = {{
                        .code = SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                        .data = {22, 172, 16, 0, 0, 0, 0, 0},
                        .len = 8,
                }},
                .overrideslen = 1,
        },
        /* test draft-tojens-dhcp-option-concat-considerations: not all options should be
         * concatenated. Concatenation-requiring is already tested by the previous test.
         * test fixed-length options.
         */
        {
                .options = {
                        SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK,
                        SD_DHCP_OPTION_SUBNET_MASK, 4, 255, 255, 255, 0,
                        SD_DHCP_OPTION_SUBNET_MASK, 4, 255, 255, 255, 0,
                },
                .len = 15,
                .success = true,
                /* no overrides: option should not be concatenated */
        },
        /* test multiple of fixed-length */
        {
                .options = {
                        SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK,
                        SD_DHCP_OPTION_DOMAIN_NAME_SERVER, 3, 8, 8, 8,
                        SD_DHCP_OPTION_DOMAIN_NAME_SERVER, 5, 8, 1, 1, 1, 1,
                },
                .len = 15,
                .success = true,
                .overrides = {{
                        .code = SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                        .data = {8, 8, 8, 8, 1, 1, 1, 1},
                        .len = 8,
                }},
                .overrideslen = 1,
        },
        /* test arbitrary length */
        {
                .options = {
                        SD_DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK,
                        SD_DHCP_OPTION_HOST_NAME, 3, 'f', 'o', 'o',
                        SD_DHCP_OPTION_HOST_NAME, 3, 'b', 'a', 'r',
                        SD_DHCP_OPTION_HOST_NAME, 3, 'b', 'a', 'z',
                },
                .len = 18,
                .success = true,
                .overrides = {{
                        .code = SD_DHCP_OPTION_HOST_NAME,
                        .data = "foobarbaz",
                        .len = 9,
                }},
                .overrideslen = 1,
        },
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
                                    DHCP_DISCOVER, ARPHRD_ETHER, ETH_ALEN, (uint8_t[16]){},
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

static void test_ignore_opts(uint8_t *descoption, int *descpos, size_t *desclen) {
        assert_se(*descpos >= 0);

        while ((size_t)*descpos < *desclen) {
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

static int test_options_cb(uint8_t code, size_t len, const void *option, void *userdata) {
        struct option_desc *desc = userdata;
        uint8_t *descoption = NULL;
        size_t *desclen = NULL;
        int *descpos = NULL;
        uint8_t optcode = 0;
        uint8_t optlen = 0;
        size_t descoption_offset;

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

                if (*descpos < 0 || (size_t)*descpos < *desclen)
                        break;

                if ((size_t)*descpos == *desclen)
                        *descpos = -1;
        }

        assert_se(descpos);
        assert_se(*descpos != -1);

        optcode = descoption[*descpos];
        optlen = descoption[*descpos + 1];
        descoption_offset = *descpos + 2;

        for (size_t i = 0; i < desc->overrideslen; i++)
                if (desc->overrides[i].code == optcode) {
                        optlen = desc->overrides[i].len;
                        descoption = desc->overrides[i].data;
                        descoption_offset = 0;
                        break;
                }

        if (verbose)
                printf("DHCP code %2d(%2d) len %4zu(%2d) ", code, optcode,
                                len, optlen);

        assert_se(code == optcode);
        assert_se(len == optlen);

        for (size_t i = 0; i < len; i++) {
                if (verbose)
                        printf("0x%02x(0x%02x) ",
                               ((uint8_t*) option)[i],
                               descoption[descoption_offset + i]);

                assert_se(((uint8_t*) option)[i] == descoption[descoption_offset + i]);
        }

        if (verbose)
                printf("\n");

        *descpos += optlen + 2;

        test_ignore_opts(descoption, descpos, desclen);

        if (desc->pos != -1 && (size_t)desc->pos == desc->len)
                desc->pos = -1;

        if (desc->filepos != -1 && (size_t)desc->filepos == desc->filelen)
                desc->filepos = -1;

        if (desc->snamepos != -1 && (size_t)desc->snamepos == desc->snamelen)
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
        int r;

        assert_se(dhcp_option_parse(message, sizeof(DHCPMessage) + desc->len, NULL, NULL, NULL) >= 0);
        r = dhcp_option_remove_option(message->options, desc->len, SD_DHCP_OPTION_MESSAGE_TYPE);
        assert_se(r >= 0);
        desc->len = (size_t)r;
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

        for (size_t i = 0; i < 9; i++) {
                if (verbose)
                        printf("%2zu: 0x%02x(0x%02x) (options)\n", i, result->options[i],
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

struct long_option_test {
        const char *name;
        struct {
                uint8_t code;
                size_t len;
                uint8_t data[1024];
        } option;
        size_t max_optlen;
        bool use_file;
        bool success;
        uint8_t expected_option[500];
        size_t expected_optlen;
        uint8_t expected_file[128];
        size_t expected_filelen;
};

static struct long_option_test long_option_tests[] = {
        {
                .name = "test that a regular option can be serialized",
                .option.code = SD_DHCP_OPTION_SUBNET_MASK,
                .option.len = 4,
                .option.data = {255, 255, 255, 0},
                .max_optlen = 128,
                .success = true,
                .expected_option = {SD_DHCP_OPTION_SUBNET_MASK, 4, 255, 255, 255, 0},
                .expected_optlen = 6,
        },
        {
                .name = "test that a regular option fails if there is not enough space",
                .option.code = SD_DHCP_OPTION_SUBNET_MASK,
                .option.len = 4,
                .option.data = {255, 255, 255, 0},
                .max_optlen = 2,
                .success = false,
        },
        {
                .name = "test that a regular option fallbacks to the file buffer when allowed",
                .option.code = SD_DHCP_OPTION_SUBNET_MASK,
                .option.len = 4,
                .option.data = {255, 255, 255, 0},
                .max_optlen = 2,
                .use_file = true,
                .success = true,
                .expected_option = {SD_DHCP_OPTION_END, SD_DHCP_OPTION_PAD},
                .expected_optlen = 2,
                .expected_file = {SD_DHCP_OPTION_SUBNET_MASK, 4, 255, 255, 255, 0},
                .expected_filelen = 6,
        },
        {
                .name = "test that a mergeable long option is split across two options (RFC3396)",
                .option.code = SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                .option.len = 256, /* one byte short to fit in one option! */
                .option.data = {
                        24, 10, 0, 0, 1, 2, 3, 4, 24, 10, 0, 1, 1, 2, 3, 4,
                        24, 10, 0, 2, 1, 2, 3, 4, 24, 10, 0, 3, 1, 2, 3, 4,
                        24, 10, 0, 4, 1, 2, 3, 4, 24, 10, 0, 5, 1, 2, 3, 4,
                        24, 10, 0, 6, 1, 2, 3, 4, 24, 10, 0, 7, 1, 2, 3, 4,
                        24, 10, 0, 8, 1, 2, 3, 4, 24, 10, 0, 9, 1, 2, 3, 4,
                        24, 10, 0, 10, 1, 2, 3, 4, 24, 10, 0, 11, 1, 2, 3, 4,
                        24, 10, 0, 12, 1, 2, 3, 4, 24, 10, 0, 13, 1, 2, 3, 4,
                        24, 10, 0, 14, 1, 2, 3, 4, 24, 10, 0, 15, 1, 2, 3, 4,
                        24, 10, 0, 16, 1, 2, 3, 4, 24, 10, 0, 17, 1, 2, 3, 4,
                        24, 10, 0, 18, 1, 2, 3, 4, 24, 10, 0, 19, 1, 2, 3, 4,
                        24, 10, 0, 20, 1, 2, 3, 4, 24, 10, 0, 21, 1, 2, 3, 4,
                        24, 10, 0, 22, 1, 2, 3, 4, 24, 10, 0, 23, 1, 2, 3, 4,
                        24, 10, 0, 24, 1, 2, 3, 4, 24, 10, 0, 25, 1, 2, 3, 4,
                        24, 10, 0, 26, 1, 2, 3, 4, 24, 10, 0, 27, 1, 2, 3, 4,
                        24, 10, 0, 28, 1, 2, 3, 4, 24, 10, 0, 29, 1, 2, 3, 4,
                        24, 10, 0, 30, 1, 2, 3, 4, 24, 10, 0, 31, 1, 2, 3, 4,
                },
                .max_optlen = 500,
                .success = true,
                .expected_option = {
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 255,
                        24, 10, 0, 0, 1, 2, 3, 4, 24, 10, 0, 1, 1, 2, 3, 4,
                        24, 10, 0, 2, 1, 2, 3, 4, 24, 10, 0, 3, 1, 2, 3, 4,
                        24, 10, 0, 4, 1, 2, 3, 4, 24, 10, 0, 5, 1, 2, 3, 4,
                        24, 10, 0, 6, 1, 2, 3, 4, 24, 10, 0, 7, 1, 2, 3, 4,
                        24, 10, 0, 8, 1, 2, 3, 4, 24, 10, 0, 9, 1, 2, 3, 4,
                        24, 10, 0, 10, 1, 2, 3, 4, 24, 10, 0, 11, 1, 2, 3, 4,
                        24, 10, 0, 12, 1, 2, 3, 4, 24, 10, 0, 13, 1, 2, 3, 4,
                        24, 10, 0, 14, 1, 2, 3, 4, 24, 10, 0, 15, 1, 2, 3, 4,
                        24, 10, 0, 16, 1, 2, 3, 4, 24, 10, 0, 17, 1, 2, 3, 4,
                        24, 10, 0, 18, 1, 2, 3, 4, 24, 10, 0, 19, 1, 2, 3, 4,
                        24, 10, 0, 20, 1, 2, 3, 4, 24, 10, 0, 21, 1, 2, 3, 4,
                        24, 10, 0, 22, 1, 2, 3, 4, 24, 10, 0, 23, 1, 2, 3, 4,
                        24, 10, 0, 24, 1, 2, 3, 4, 24, 10, 0, 25, 1, 2, 3, 4,
                        24, 10, 0, 26, 1, 2, 3, 4, 24, 10, 0, 27, 1, 2, 3, 4,
                        24, 10, 0, 28, 1, 2, 3, 4, 24, 10, 0, 29, 1, 2, 3, 4,
                        24, 10, 0, 30, 1, 2, 3, 4, 24, 10, 0, 31, 1, 2, 3,
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 1,
                        4,
                },
                .expected_optlen = 260,
        },
        {
                .name = "test that a mergeable option is split across options and file if needed",
                .option.code = SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                .option.len = 8,
                .option.data = {24, 10, 0, 0, 1, 2, 3, 4},
                .max_optlen = 8,
                .use_file = true,
                .success = true,
                .expected_option = {
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 5, 24, 10, 0, 0, 1,
                        SD_DHCP_OPTION_END,
                },
                .expected_optlen = 8,
                .expected_file = {SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE, 3, 2, 3, 4},
                .expected_filelen = 5,
        },
};

static void test_option_append_long(struct long_option_test *desc) {
        _cleanup_free_ DHCPMessage *result = NULL;
        uint8_t overload = 0;
        size_t offset = 0;
        int r;

        if (verbose)
                printf(">>> %s\n", desc->name);

        result = malloc0(sizeof(DHCPMessage) + desc->max_optlen);
        assert_se(result);

        if (desc->use_file)
                overload |= DHCP_OVERLOAD_FILE;

        r = dhcp_option_append(result, desc->max_optlen, &offset, overload,
                               desc->option.code, desc->option.len, desc->option.data);
        if (verbose)
                printf("dhcp_option_append=%d, offset=%zu\n", r, offset);
        if (!desc->success) {
                assert_se(r < 0);
                return;
        }
        assert_se(r == 0);
        assert_se(offset == desc->expected_optlen + desc->expected_filelen);

        if (verbose)
                printf("opts: ");
        for (unsigned i = 0; i < desc->expected_optlen; i++) {
                if (verbose)
                        printf("0x%02x(0x%02x) ", result->options[i], desc->expected_option[i]);
                if (verbose && result->options[i] != desc->expected_option[i])
                        printf("\n");
                assert_se(result->options[i] == desc->expected_option[i]);
        }
        if (verbose)
                printf("\n");

        if (verbose)
                printf("file: ");
        for (unsigned i = 0; i < desc->expected_filelen; i++) {
                if (verbose)
                        printf("0x%02x(0x%02x) ", result->file[i], desc->expected_file[i]);
                if (verbose && result->file[i] != desc->expected_file[i])
                        printf("\n");
                assert_se(result->file[i] == desc->expected_file[i]);
        }
        if (verbose)
                printf("\n");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_invalid_buffer_length();
        test_message_init();

        test_options(NULL);

        FOREACH_ELEMENT(desc, option_tests)
                test_options(desc);

        FOREACH_ELEMENT(desc, long_option_tests)
                test_option_append_long(desc);

        test_option_set();

        FOREACH_ELEMENT(desc, option_tests) {
                if (!desc->success || desc->snamelen > 0 || desc->filelen > 0)
                        continue;
                test_option_removal(desc);
        }

        return 0;
}
