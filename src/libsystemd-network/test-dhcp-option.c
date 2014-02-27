
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "macro.h"

#include "dhcp-protocol.h"
#include "dhcp-internal.h"

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
                          DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK }, 12, true, },
        { {}, 0, {}, 0, { 8, 255, 70, 71, 72 }, 5, false, },
        { {}, 0, {}, 0, { 0x35, 0x01, 0x05, 0x36, 0x04, 0x01, 0x00, 0xa8,
                          0xc0, 0x33, 0x04, 0x00, 0x01, 0x51, 0x80, 0x01,
                          0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0,
                          0xa8, 0x00, 0x01, 0x06, 0x04, 0xc0, 0xa8, 0x00,
                          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
          40, true, },
        { {}, 0, {}, 0, { DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_OFFER,
                          42, 3, 0, 0, 0 }, 8, true, },
        { {}, 0, {}, 0, { 42, 2, 1, 2, 44 }, 5, false, },

        { {}, 0,
          { 222, 3, 1, 2, 3, DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_NAK }, 8,
          { DHCP_OPTION_OVERLOAD, 1, DHCP_OVERLOAD_FILE }, 3, true, },

        { { 1, 4, 1, 2, 3, 4, DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_ACK }, 9,
          { 222, 3, 1, 2, 3 }, 5,
          { DHCP_OPTION_OVERLOAD, 1,
            DHCP_OVERLOAD_FILE|DHCP_OVERLOAD_SNAME }, 3, true, },
};

static const char *dhcp_type(int type)
{
        switch(type) {
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

static void test_invalid_buffer_length(void)
{
        DHCPMessage message;

        assert_se(dhcp_option_parse(&message, 0, NULL, NULL) == -EINVAL);
        assert_se(dhcp_option_parse(&message, sizeof(DHCPMessage), NULL, NULL)
               == -EINVAL);
}

static void test_cookie(void)
{
        _cleanup_free_ DHCPMessage *message;
        size_t len = sizeof(DHCPMessage) + 4;
        uint8_t *opt;

        message = malloc0(len);

        opt = (uint8_t *)(message + 1);
        opt[0] = 0xff;

        assert_se(dhcp_option_parse(message, len, NULL, NULL) == -EINVAL);

        opt[0] = 99;
        opt[1] = 130;
        opt[2] = 83;
        opt[3] = 99;

        assert_se(dhcp_option_parse(message, len, NULL, NULL) == -ENOMSG);
}

static DHCPMessage *create_message(uint8_t *options, uint16_t optlen,
                uint8_t *file, uint8_t filelen,
                uint8_t *sname, uint8_t snamelen)
{
        DHCPMessage *message;
        size_t len = sizeof(DHCPMessage) + 4 + optlen;
        uint8_t *opt;

        message = malloc0(len);
        opt = (uint8_t *)(message + 1);

        opt[0] = 99;
        opt[1] = 130;
        opt[2] = 83;
        opt[3] = 99;

        if (options && optlen)
                memcpy(&opt[4], options, optlen);

        if (file && filelen <= 128)
                memcpy(&message->file, file, filelen);

        if (sname && snamelen <= 64)
                memcpy(&message->sname, sname, snamelen);

        return message;
}

static void test_ignore_opts(uint8_t *descoption, int *descpos, int *desclen)
{
        while (*descpos < *desclen) {
                switch(descoption[*descpos]) {
                case DHCP_OPTION_PAD:
                        *descpos += 1;
                        break;

                case DHCP_OPTION_MESSAGE_TYPE:
                case DHCP_OPTION_OVERLOAD:
                        *descpos += 3;
                        break;

                default:
                        return;
                }
        }
}

static int test_options_cb(uint8_t code, uint8_t len, const uint8_t *option,
                           void *user_data)
{
        struct option_desc *desc = user_data;
        uint8_t *descoption = NULL;
        int *desclen = NULL, *descpos = NULL;
        uint8_t optcode = 0;
        uint8_t optlen = 0;
        uint8_t i;

        assert_se((!desc && !code && !len) || desc);

        if (!desc)
                return -EINVAL;

        assert_se(code != DHCP_OPTION_PAD);
        assert_se(code != DHCP_OPTION_END);
        assert_se(code != DHCP_OPTION_MESSAGE_TYPE);
        assert_se(code != DHCP_OPTION_OVERLOAD);

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

        for (i = 0; i < len; i++) {

                if (verbose)
                        printf("0x%02x(0x%02x) ", option[i],
                                        descoption[*descpos + 2 + i]);

                assert_se(option[i] == descoption[*descpos + 2 + i]);
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

static void test_options(struct option_desc *desc)
{
        uint8_t *options = NULL;
        uint8_t *file = NULL;
        uint8_t *sname = NULL;
        int optlen = 0;
        int filelen = 0;
        int snamelen = 0;
        int buflen = 0;
        _cleanup_free_ DHCPMessage *message;
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

        buflen = sizeof(DHCPMessage) + 4 + optlen;

        if (!desc) {
                assert_se((res = dhcp_option_parse(message, buflen,
                                                test_options_cb,
                                                NULL)) == -ENOMSG);
        } else if (desc->success) {
                assert_se((res = dhcp_option_parse(message, buflen,
                                                test_options_cb,
                                                desc)) >= 0);
                assert_se(desc->pos == -1 && desc->filepos == -1 &&
                                desc->snamepos == -1);
        } else
                assert_se((res = dhcp_option_parse(message, buflen,
                                                test_options_cb,
                                                desc)) < 0);

        if (verbose)
                printf("DHCP type %s\n", dhcp_type(res));
}

static uint8_t result[64] = {
        'A', 'B', 'C', 'D',
};

static uint8_t options[64] = {
        'A', 'B', 'C', 'D',
        160, 2, 0x11, 0x12,
        0,
        31, 8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0,
        55, 3, 0x51, 0x52, 0x53,
        17, 7, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        255
};

static void test_option_set(void)
{
        size_t len, oldlen;
        int pos, i;
        uint8_t *opt;

        assert_se(dhcp_option_append(NULL, NULL, 0, 0, NULL) == -EINVAL);

        len = 0;
        opt = &result[0];
        assert_se(dhcp_option_append(&opt, NULL, 0, 0, NULL) == -EINVAL);
        assert_se(opt == &result[0] && len == 0);

        assert_se(dhcp_option_append(&opt, &len, DHCP_OPTION_PAD,
                                  0, NULL) == -ENOBUFS);
        assert_se(opt == &result[0] && len == 0);

        opt = &result[4];
        len = 1;
        assert_se(dhcp_option_append(&opt, &len, DHCP_OPTION_PAD,
                                    0, NULL) >= 0);
        assert_se(opt == &result[5] && len == 0);

        pos = 4;
        len = 60;
        while (pos < 64 && options[pos] != DHCP_OPTION_END) {
                opt = &result[pos];
                oldlen = len;

                assert_se(dhcp_option_append(&opt, &len, options[pos],
                                          options[pos + 1],
                                          &options[pos + 2]) >= 0);

                if (options[pos] == DHCP_OPTION_PAD) {
                        assert_se(opt == &result[pos + 1]);
                        assert_se(len == oldlen - 1);
                        pos++;
                } else {
                        assert_se(opt == &result[pos + 2 + options[pos + 1]]);
                        assert_se(len == oldlen - 2 - options[pos + 1]);
                        pos += 2 + options[pos + 1];
                }
        }

        for (i = 0; i < pos; i++) {
                if (verbose)
                        printf("%2d: 0x%02x(0x%02x)\n", i, result[i],
                               options[i]);
                assert_se(result[i] == options[i]);
        }

        if (verbose)
                printf ("\n");
}

int main(int argc, char *argv[])
{
        unsigned int i;

        test_invalid_buffer_length();
        test_cookie();

        test_options(NULL);

        for (i = 0; i < ELEMENTSOF(option_tests); i++)
                test_options(&option_tests[i]);

        test_option_set();

        return 0;
}
