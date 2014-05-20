/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "dhcp-internal.h"

int dhcp_option_append(uint8_t options[], size_t size, size_t *offset,
                       uint8_t code, size_t optlen, const void *optval) {
        assert(options);
        assert(offset);

        switch (code) {

        case DHCP_OPTION_PAD:
        case DHCP_OPTION_END:
                if (size - *offset < 1)
                        return -ENOBUFS;

                options[*offset] = code;
                *offset += 1;
                break;

        default:
                if (size - *offset < optlen + 2)
                        return -ENOBUFS;

                assert(optval);

                options[*offset] = code;
                options[*offset + 1] = optlen;
                memcpy(&options[*offset + 2], optval, optlen);

                *offset += optlen + 2;

                break;
        }

        return 0;
}

static int parse_options(const uint8_t *buf, size_t buflen, uint8_t *overload,
                         uint8_t *message_type, dhcp_option_cb_t cb,
                         void *user_data)
{
        const uint8_t *code = buf;
        const uint8_t *len;

        while (buflen > 0) {
                switch (*code) {
                case DHCP_OPTION_PAD:
                        buflen -= 1;
                        code++;
                        break;

                case DHCP_OPTION_END:
                        return 0;

                case DHCP_OPTION_MESSAGE_TYPE:
                        if (buflen < 3)
                                return -ENOBUFS;
                        buflen -= 3;

                        len = code + 1;
                        if (*len != 1)
                                return -EINVAL;

                        if (message_type)
                                *message_type = *(len + 1);

                        code += 3;

                        break;

                case DHCP_OPTION_OVERLOAD:
                        if (buflen < 3)
                                return -ENOBUFS;
                        buflen -= 3;

                        len = code + 1;
                        if (*len != 1)
                                return -EINVAL;

                        if (overload)
                                *overload = *(len + 1);

                        code += 3;

                        break;

                default:
                        if (buflen < 3)
                                return -ENOBUFS;

                        len = code + 1;

                        if (buflen < (size_t)*len + 2)
                                return -EINVAL;
                        buflen -= *len + 2;

                        if (cb)
                                cb(*code, *len, len + 1, user_data);

                        code += *len + 2;

                        break;
                }
        }

        if (buflen)
                return -EINVAL;

        return 0;
}

int dhcp_option_parse(DHCPMessage *message, size_t len,
                      dhcp_option_cb_t cb, void *user_data)
{
        uint8_t overload = 0;
        uint8_t message_type = 0;
        int res;

        if (!message)
                return -EINVAL;

        if (len < sizeof(DHCPMessage))
                return -EINVAL;

        len -= sizeof(DHCPMessage);

        res = parse_options(message->options, len, &overload, &message_type,
                            cb, user_data);
        if (res < 0)
                return res;

        if (overload & DHCP_OVERLOAD_FILE) {
                res = parse_options(message->file, sizeof(message->file),
                                NULL, &message_type, cb, user_data);
                if (res < 0)
                        return res;
        }

        if (overload & DHCP_OVERLOAD_SNAME) {
                res = parse_options(message->sname, sizeof(message->sname),
                                NULL, &message_type, cb, user_data);
                if (res < 0)
                        return res;
        }

        if (message_type)
                return message_type;

        return -ENOMSG;
}
