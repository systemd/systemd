/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "alloc-util.h"
#include "dhcp-internal.h"
#include "dhcp-server-internal.h"
#include "memory-util.h"
#include "strv.h"
#include "utf8.h"

/* Append type-length value structure to the options buffer */
static int dhcp_option_append_tlv(uint8_t options[], size_t size, size_t *offset, uint8_t code, size_t optlen, const void *optval) {
        assert(options);
        assert(size > 0);
        assert(offset);
        assert(optlen <= UINT8_MAX);
        assert(*offset < size);

        if (*offset + 2 + optlen > size)
                return -ENOBUFS;

        options[*offset] = code;
        options[*offset + 1] = optlen;

        memcpy_safe(&options[*offset + 2], optval, optlen);
        *offset += 2 + optlen;
        return 0;
}

static int option_append(uint8_t options[], size_t size, size_t *offset,
                         uint8_t code, size_t optlen, const void *optval) {
        assert(options);
        assert(size > 0);
        assert(offset);

        int r;

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

                if (strv_isempty((char **) optval))
                        return -EINVAL;

                STRV_FOREACH(s, (const char* const*) optval) {
                        size_t len = strlen(*s);

                        if (len > 255 || len == 0)
                                return -EINVAL;

                        total += 1 + len;
                }

                if (*offset + 2 + total > size)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] = total;
                *offset += 2;

                STRV_FOREACH(s, (const char* const*) optval) {
                        size_t len = strlen(*s);

                        options[*offset] = len;
                        memcpy(&options[*offset + 1], *s, len);
                        *offset += 1 + len;
                }

                break;
        }
        case SD_DHCP_OPTION_SIP_SERVER:
                if (*offset + 3 + optlen > size)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] = optlen + 1;
                options[*offset + 2] = 1;

                memcpy_safe(&options[*offset + 3], optval, optlen);
                *offset += 3 + optlen;

                break;
        case SD_DHCP_OPTION_VENDOR_SPECIFIC: {
                OrderedSet *s = (OrderedSet *) optval;
                struct sd_dhcp_option *p;
                size_t l = 0;

                ORDERED_SET_FOREACH(p, s)
                        l += p->length + 2;

                if (*offset + l + 2 > size)
                        return -ENOBUFS;

                options[*offset] = code;
                options[*offset + 1] = l;
                *offset += 2;

                ORDERED_SET_FOREACH(p, s) {
                        r = dhcp_option_append_tlv(options, size, offset, p->option, p->length, p->data);
                        if (r < 0)
                                return r;
                }
                break;
        }
        case SD_DHCP_OPTION_RELAY_AGENT_INFORMATION: {
                sd_dhcp_server *server = (sd_dhcp_server *) optval;
                size_t current_offset = *offset + 2;

                if (server->agent_circuit_id) {
                        r = dhcp_option_append_tlv(options, size, &current_offset, SD_DHCP_RELAY_AGENT_CIRCUIT_ID,
                                                   strlen(server->agent_circuit_id), server->agent_circuit_id);
                        if (r < 0)
                                return r;
                }
                if (server->agent_remote_id) {
                        r = dhcp_option_append_tlv(options, size, &current_offset, SD_DHCP_RELAY_AGENT_REMOTE_ID,
                                                   strlen(server->agent_remote_id), server->agent_remote_id);
                        if (r < 0)
                                return r;
                }

                options[*offset] = code;
                options[*offset + 1] = current_offset - *offset - 2;
                assert(current_offset - *offset - 2 <= UINT8_MAX);
                *offset = current_offset;
                break;
        }
        default:
                return dhcp_option_append_tlv(options, size, offset, code, optlen, optval);
        }
        return 0;
}

static int option_length(uint8_t *options, size_t length, size_t offset) {
        assert(options);
        assert(offset < length);

        if (IN_SET(options[offset], SD_DHCP_OPTION_PAD, SD_DHCP_OPTION_END))
                return 1;
        if (length < offset + 2)
                return -ENOBUFS;

        /* validating that buffer is long enough */
        if (length < offset + 2 + options[offset + 1])
                return -ENOBUFS;

        return options[offset + 1] + 2;
}

int dhcp_option_find_option(uint8_t *options, size_t length, uint8_t code, size_t *ret_offset) {
        int r;

        assert(options);
        assert(ret_offset);

        for (size_t offset = 0; offset < length; offset += r) {
                r = option_length(options, length, offset);
                if (r < 0)
                        return r;

                if (code == options[offset]) {
                        *ret_offset = offset;
                        return r;
                }
        }
        return -ENOENT;
}

int dhcp_option_remove_option(uint8_t *options, size_t length, uint8_t option_code) {
        int r;
        size_t offset;

        assert(options);

        r = dhcp_option_find_option(options, length, option_code, &offset);
        if (r < 0)
                return r;

        memmove(options + offset, options + offset + r, length - offset - r);
        return length - r;
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
                                r = option_append(message->file, sizeof(message->file), &file_offset, SD_DHCP_OPTION_END, 0, NULL);
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

static sd_dhcp_option* dhcp_option_free(sd_dhcp_option *i) {
        if (!i)
                return NULL;

        free(i->data);
        return mfree(i);
}

int sd_dhcp_option_new(uint8_t option, const void *data, size_t length, sd_dhcp_option **ret) {
        assert_return(ret, -EINVAL);
        assert_return(length == 0 || data, -EINVAL);

        _cleanup_free_ void *q = memdup(data, length);
        if (!q)
                return -ENOMEM;

        sd_dhcp_option *p = new(sd_dhcp_option, 1);
        if (!p)
                return -ENOMEM;

        *p = (sd_dhcp_option) {
                .n_ref = 1,
                .option = option,
                .length = length,
                .data = TAKE_PTR(q),
        };

        *ret = TAKE_PTR(p);
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_option, sd_dhcp_option, dhcp_option_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp_option_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                sd_dhcp_option,
                sd_dhcp_option_unref);
