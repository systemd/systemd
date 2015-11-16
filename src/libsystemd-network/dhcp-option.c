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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dhcp-internal.h"

static int option_append(uint8_t options[], size_t size, size_t *offset,
                         uint8_t code, size_t optlen, const void *optval) {
        assert(options);
        assert(offset);

        if (code != DHCP_OPTION_END)
                /* always make sure there is space for an END option */
                size --;

        switch (code) {

        case DHCP_OPTION_PAD:
        case DHCP_OPTION_END:
                if (size < *offset + 1)
                        return -ENOBUFS;

                options[*offset] = code;
                *offset += 1;
                break;

        default:
                if (size < *offset + optlen + 2)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] = optlen;

                if (optlen) {
                        assert(optval);

                        memcpy(&options[*offset + 2], optval, optlen);
                }

                *offset += optlen + 2;

                break;
        }

        return 0;
}

int dhcp_option_append(DHCPMessage *message, size_t size, size_t *offset,
                       uint8_t overload,
                       uint8_t code, size_t optlen, const void *optval) {
        size_t file_offset = 0, sname_offset =0;
        bool file, sname;
        int r;

        assert(message);
        assert(offset);

        file = overload & DHCP_OVERLOAD_FILE;
        sname = overload & DHCP_OVERLOAD_SNAME;

        if (*offset < size) {
                /* still space in the options array */
                r = option_append(message->options, size, offset, code, optlen, optval);
                if (r >= 0)
                        return 0;
                else if (r == -ENOBUFS && (file || sname)) {
                        /* did not fit, but we have more buffers to try
                           close the options array and move the offset to its end */
                        r = option_append(message->options, size, offset, DHCP_OPTION_END, 0, NULL);
                        if (r < 0)
                                return r;

                        *offset = size;
                } else
                        return r;
        }

        if (overload & DHCP_OVERLOAD_FILE) {
                file_offset = *offset - size;

                if (file_offset < sizeof(message->file)) {
                        /* still space in the 'file' array */
                        r = option_append(message->file, sizeof(message->file), &file_offset, code, optlen, optval);
                        if (r >= 0) {
                                *offset = size + file_offset;
                                return 0;
                        } else if (r == -ENOBUFS && sname) {
                                /* did not fit, but we have more buffers to try
                                   close the file array and move the offset to its end */
                                r = option_append(message->options, size, offset, DHCP_OPTION_END, 0, NULL);
                                if (r < 0)
                                        return r;

                                *offset = size + sizeof(message->file);
                        } else
                                return r;
                }
        }

        if (overload & DHCP_OVERLOAD_SNAME) {
                sname_offset = *offset - size - (file ? sizeof(message->file) : 0);

                if (sname_offset < sizeof(message->sname)) {
                        /* still space in the 'sname' array */
                        r = option_append(message->sname, sizeof(message->sname), &sname_offset, code, optlen, optval);
                        if (r >= 0) {
                                *offset = size + (file ? sizeof(message->file) : 0) + sname_offset;
                                return 0;
                        } else {
                                /* no space, or other error, give up */
                                return r;
                        }
                }
        }

        return -ENOBUFS;
}

static int parse_options(const uint8_t options[], size_t buflen, uint8_t *overload,
                         uint8_t *message_type, dhcp_option_cb_t cb,
                         void *userdata) {
        uint8_t code, len;
        size_t offset = 0;

        while (offset < buflen) {
                switch (options[offset]) {
                case DHCP_OPTION_PAD:
                        offset++;

                        break;

                case DHCP_OPTION_END:
                        return 0;

                case DHCP_OPTION_MESSAGE_TYPE:
                        if (buflen < offset + 3)
                                return -ENOBUFS;

                        len = options[++offset];
                        if (len != 1)
                                return -EINVAL;

                        if (message_type)
                                *message_type = options[++offset];
                        else
                                offset++;

                        offset++;

                        break;

                case DHCP_OPTION_OVERLOAD:
                        if (buflen < offset + 3)
                                return -ENOBUFS;

                        len = options[++offset];
                        if (len != 1)
                                return -EINVAL;

                        if (overload)
                                *overload = options[++offset];
                        else
                                offset++;

                        offset++;

                        break;

                default:
                        if (buflen < offset + 3)
                                return -ENOBUFS;

                        code = options[offset];
                        len = options[++offset];

                        if (buflen < ++offset + len)
                                return -EINVAL;

                        if (cb)
                                cb(code, len, &options[offset], userdata);

                        offset += len;

                        break;
                }
        }

        if (offset < buflen)
                return -EINVAL;

        return 0;
}

int dhcp_option_parse(DHCPMessage *message, size_t len,
                      dhcp_option_cb_t cb, void *userdata) {
        uint8_t overload = 0;
        uint8_t message_type = 0;
        int r;

        if (!message)
                return -EINVAL;

        if (len < sizeof(DHCPMessage))
                return -EINVAL;

        len -= sizeof(DHCPMessage);

        r = parse_options(message->options, len, &overload, &message_type,
                          cb, userdata);
        if (r < 0)
                return r;

        if (overload & DHCP_OVERLOAD_FILE) {
                r = parse_options(message->file, sizeof(message->file),
                                NULL, &message_type, cb, userdata);
                if (r < 0)
                        return r;
        }

        if (overload & DHCP_OVERLOAD_SNAME) {
                r = parse_options(message->sname, sizeof(message->sname),
                                NULL, &message_type, cb, userdata);
                if (r < 0)
                        return r;
        }

        if (message_type)
                return message_type;

        return -ENOMSG;
}
