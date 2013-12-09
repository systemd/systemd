
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <util.h>

#include "dhcp-protocol.h"
#include "dhcp-internal.h"

static void test_invalid_buffer_length(void)
{
        DHCPMessage message;

        assert(dhcp_option_parse(&message, 0, NULL, NULL) == -EINVAL);
        assert(dhcp_option_parse(&message, sizeof(DHCPMessage), NULL, NULL)
               == -EINVAL);
}

static void test_cookie(void)
{
        DHCPMessage *message;
        size_t len = sizeof(DHCPMessage) + 4;
        uint8_t *opt;

        message = malloc0(len);

        opt = (uint8_t *)(message + 1);
        opt[0] = 0xff;

        assert(dhcp_option_parse(message, len, NULL, NULL) == -EINVAL);

        opt[0] = 99;
        opt[1] = 130;
        opt[2] = 83;
        opt[3] = 99;

        assert(dhcp_option_parse(message, len, NULL, NULL) == -ENOMSG);

        free(message);
}

int main(int argc, char *argv[])
{
        test_invalid_buffer_length();
        test_cookie();

        return 0;
}
