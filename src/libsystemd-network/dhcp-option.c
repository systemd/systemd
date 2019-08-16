/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "alloc-util.h"
#include "dhcp-internal.h"
#include "memory-util.h"
#include "strv.h"
#include "utf8.h"

static int option_append(uint8_t options[], size_t size, size_t *offset,
                         uint8_t code, size_t optlen, const void *optval) {
        assert(options);
        assert(offset);

        if (code != SD_DHCP_OPTION_END)
                /* always make sure there is space for an END option */
                size--;

        switch (code) {

        case SD_DHCP_OPTION_PAD:
        case SD_DHCP_OPTION_END:
                if (*offset + 1 > size)
                        return -ENOBUFS;

                options[*offset] = code;
                *offset += 1;
                break;

        case SD_DHCP_OPTION_USER_CLASS: {
                size_t total = 0;
                char **s;

                STRV_FOREACH(s, (char **) optval) {
                        size_t len = strlen(*s);

                        if (len > 255)
                                return -ENAMETOOLONG;

                        total += 1 + len;
                }

                if (*offset + 2 + total > size)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] =  total;
                *offset += 2;

                STRV_FOREACH(s, (char **) optval) {
                        size_t len = strlen(*s);

                        options[*offset] = len;

                        memcpy(&options[*offset + 1], *s, len);
                        *offset += 1 + len;
                }

                break;
        }
        default:
                if (*offset + 2 + optlen > size)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] = optlen;

                memcpy_safe(&options[*offset + 2], optval, optlen);
                *offset += 2 + optlen;

                break;
        }

        return 0;
}

int dhcp_option_append(DHCPMessage *message, size_t size, size_t *offset,
                       uint8_t overload,
                       uint8_t code, size_t optlen, const void *optval) {
        const bool use_file = overload & DHCP_OVERLOAD_FILE;
        const bool use_sname = overload & DHCP_OVERLOAD_SNAME;
        int r;

        assert(message);
        assert(offset);

        /* If *offset is in range [0, size), we are writing to ->options,
         * if *offset is in range [size, size + sizeof(message->file)) and use_file, we are writing to ->file,
         * if *offset is in range [size + use_file*sizeof(message->file), size + use_file*sizeof(message->file) + sizeof(message->sname))
         * and use_sname, we are writing to ->sname.
         */

        if (*offset < size) {
                /* still space in the options array */
                r = option_append(message->options, size, offset, code, optlen, optval);
                if (r >= 0)
                        return 0;
                else if (r == -ENOBUFS && (use_file || use_sname)) {
                        /* did not fit, but we have more buffers to try
                           close the options array and move the offset to its end */
                        r = option_append(message->options, size, offset, SD_DHCP_OPTION_END, 0, NULL);
                        if (r < 0)
                                return r;

                        *offset = size;
                } else
                        return r;
        }

        if (use_file) {
                size_t file_offset = *offset - size;

                if (file_offset < sizeof(message->file)) {
                        /* still space in the 'file' array */
                        r = option_append(message->file, sizeof(message->file), &file_offset, code, optlen, optval);
                        if (r >= 0) {
                                *offset = size + file_offset;
                                return 0;
                        } else if (r == -ENOBUFS && use_sname) {
                                /* did not fit, but we have more buffers to try
                                   close the file array and move the offset to its end */
                                r = option_append(message->options, size, offset, SD_DHCP_OPTION_END, 0, NULL);
                                if (r < 0)
                                        return r;

                                *offset = size + sizeof(message->file);
                        } else
                                return r;
                }
        }

        if (use_sname) {
                size_t sname_offset = *offset - size - use_file*sizeof(message->file);

                if (sname_offset < sizeof(message->sname)) {
                        /* still space in the 'sname' array */
                        r = option_append(message->sname, sizeof(message->sname), &sname_offset, code, optlen, optval);
                        if (r >= 0) {
                                *offset = size + use_file*sizeof(message->file) + sname_offset;
                                return 0;
                        } else
                                /* no space, or other error, give up */
                                return r;
                }
        }

        return -ENOBUFS;
}

static int parse_options(const uint8_t options[], size_t buflen, uint8_t *overload,
                         uint8_t *message_type, char **error_message, dhcp_option_callback_t cb,
                         void *userdata) {
        uint8_t code, len;
        const uint8_t *option;
        size_t offset = 0;

        while (offset < buflen) {
                code = options[offset ++];

                switch (code) {
                case SD_DHCP_OPTION_PAD:
                        continue;

                case SD_DHCP_OPTION_END:
                        return 0;
                }

                if (buflen < offset + 1)
                        return -ENOBUFS;

                len = options[offset ++];

                if (buflen < offset + len)
                        return -EINVAL;

                option = &options[offset];

                switch (code) {
                case SD_DHCP_OPTION_MESSAGE_TYPE:
                        if (len != 1)
                                return -EINVAL;

                        if (message_type)
                                *message_type = *option;

                        break;

                case SD_DHCP_OPTION_ERROR_MESSAGE:
                        if (len == 0)
                                return -EINVAL;

                        if (error_message) {
                                _cleanup_free_ char *string = NULL;

                                /* Accept a trailing NUL byte */
                                if (memchr(option, 0, len - 1))
                                        return -EINVAL;

                                string = memdup_suffix0((const char *) option, len);
                                if (!string)
                                        return -ENOMEM;

                                if (!ascii_is_valid(string))
                                        return -EINVAL;

                                free_and_replace(*error_message, string);
                        }

                        break;
                case SD_DHCP_OPTION_OVERLOAD:
                        if (len != 1)
                                return -EINVAL;

                        if (overload)
                                *overload = *option;

                        break;

                default:
                        if (cb)
                                cb(code, len, option, userdata);

                        break;
                }

                offset += len;
        }

        if (offset < buflen)
                return -EINVAL;

        return 0;
}

int dhcp_option_parse(DHCPMessage *message, size_t len, dhcp_option_callback_t cb, void *userdata, char **_error_message) {
        _cleanup_free_ char *error_message = NULL;
        uint8_t overload = 0;
        uint8_t message_type = 0;
        int r;

        if (!message)
                return -EINVAL;

        if (len < sizeof(DHCPMessage))
                return -EINVAL;

        len -= sizeof(DHCPMessage);

        r = parse_options(message->options, len, &overload, &message_type, &error_message, cb, userdata);
        if (r < 0)
                return r;

        if (overload & DHCP_OVERLOAD_FILE) {
                r = parse_options(message->file, sizeof(message->file), NULL, &message_type, &error_message, cb, userdata);
                if (r < 0)
                        return r;
        }

        if (overload & DHCP_OVERLOAD_SNAME) {
                r = parse_options(message->sname, sizeof(message->sname), NULL, &message_type, &error_message, cb, userdata);
                if (r < 0)
                        return r;
        }

        if (message_type == 0)
                return -ENOMSG;

        if (_error_message && IN_SET(message_type, DHCP_NAK, DHCP_DECLINE))
                *_error_message = TAKE_PTR(error_message);

        return message_type;
}
