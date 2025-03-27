/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "dhcp-option.h"
#include "dhcp-protocol.h"
#include "dhcp-server-internal.h"
#include "dns-domain.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "list.h"
#include "macro.h"
#include "memory-util.h"
#include "ordered-set.h"
#include "sd-dhcp-protocol.h"
#include "strv.h"
#include "unaligned.h"
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

static int parse_options(const uint8_t options[], size_t buflen, uint8_t *message_type,
                         char **error_message, dhcp_option_callback_t cb, void *userdata) {
        uint8_t code;
        uint16_t len;
        const uint8_t *option;
        size_t offset = 0;
        int r;

        while (offset < buflen) {
                code = options[offset++];

                if (buflen < offset + 2)
                        return -ENOBUFS;

                len = unaligned_read_be16(&options[offset]);
                offset += 2;

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

                                r = make_cstring((const char*) option, len, MAKE_CSTRING_ALLOW_TRAILING_NUL, &string);
                                if (r < 0)
                                        return r;

                                if (!ascii_is_valid(string))
                                        return -EINVAL;

                                free_and_replace(*error_message, string);
                        }

                        break;

                default:
                        if (cb)
                                cb(code, len, option, userdata);
                }

                offset += len;
        }

        if (offset < buflen)
                return -EINVAL;

        return 0;
}

typedef struct MergeOptionNode {
        const uint8_t *data;
        LIST_FIELDS(struct MergeOptionNode, options);
} MergeOptionNode;

static MergeOptionNode* merge_option_free(MergeOptionNode *head) {
        LIST_CLEAR(options, head, free);
        return NULL;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(merge_option_node_ops,
                                              void,
                                              trivial_hash_func,
                                              trivial_compare_func,
                                              MergeOptionNode,
                                              merge_option_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(MergeOptionNode*, merge_option_free);
#define _cleanup_merge_option_node_ _cleanup_(merge_option_freep)

static int dhcp_option_merge_append(const uint8_t *buf, size_t buflen, OrderedHashmap *opts,
                                    size_t *tot_len, uint8_t *overload) {
        int r;
        size_t offset = 0;
        _cleanup_merge_option_node_ MergeOptionNode *next;

        while (offset < buflen) {
                const uint8_t *data = &buf[offset];
                uint8_t code = buf[offset++];

                switch (code) {
                case SD_DHCP_OPTION_PAD:
                        continue;
                case SD_DHCP_OPTION_END:
                        return 0;
                }

                if (buflen < offset + 1)
                        return -ENOBUFS;

                uint8_t len = buf[offset++];

                if (buflen < offset + len)
                        return -EINVAL;

                switch (code) {
                case SD_DHCP_OPTION_OVERLOAD:
                        if (len != 1)
                                return -EINVAL;
                        if (overload)
                                *overload = buf[offset];
                        offset++;
                        continue;
                }

                next = new(MergeOptionNode, 1);
                if (!next)
                        return -ENOMEM;
                *next = (MergeOptionNode){.data = data};

                MergeOptionNode *head = ordered_hashmap_get(opts, UINT_TO_PTR(code));
                if (head)
                        LIST_APPEND(options, head, TAKE_PTR(next));
                else {
                        r = ordered_hashmap_put(opts, UINT_TO_PTR(code), next);
                        if (r < 0)
                                return r;
                        TAKE_PTR(next);
                }

                offset += len;
                *tot_len += len;
        }

        return 0;
}

/* RFC3396 specifies how DHCP options longer than 255 bytes should be handled.
 *
 * Option is to be repeated multiple times and treated as one, long, option. However, the cut can
 * happen at byte boundaries, and clients MUST assume no semantic meaning whatsoever from this cut.
 * In practice, this means the cut can happen anywhere in the middle of a semantic unit of the
 * option (e.g. DHCP option 121 (Classless Static Routes) can be split in the middle of a route).
 *
 * With the current architecture of stateless callbacks that take a whole chunk of memory, it
 * becomes hard to retain data between two consecutive callbacks without major changes to the
 * architecture.
 *
 * This function will merge DHCP options by concatenating options of the same type, producing a new
 * TLV buffer, but using u16 len fields instead of u8. This works due to a DHCP message size having
 * an inherent upper bound, lower than u16::MAX.
 *
 * Basically, this produces the aggregated option buffer the RFC talks about.
 */
static int dhcp_option_merge(const DHCPMessage *message, size_t buflen, uint8_t **ret_merged) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *opts;
        uint8_t *aggregate, overload = 0;
        size_t tot_len = 0;
        int r = 0;

        opts = ordered_hashmap_new(&merge_option_node_ops);
        if (!opts)
                return -ENOMEM;

        /* RFC3396 5. The Aggregate Option Buffer
         *
         *   [...], an option that doesn't fit into one field can't overlap the boundary into
         *   another field - the encoding agent must instead break the option into two parts and
         *   store one part in each buffer.
         *
         *   To simplify this discussion, we will talk about an aggregate option buffer, which will
         *   be the aggregate of the three buffers. [...] The aggregate option buffer is made up of
         *   the optional parameters field, the file field, and the sname field, in that order.
         *
         * Since options cannot overlap from one field to another, it is safe to read them in
         * isolation.
         */
        r = dhcp_option_merge_append(message->options, buflen, opts, &tot_len, &overload);
        if (r < 0)
                return r;
        if (overload & DHCP_OVERLOAD_FILE) {
                r = dhcp_option_merge_append(message->file, sizeof(message->file), opts, &tot_len, NULL);
                if (r < 0)
                        return r;
        }
        if (overload & DHCP_OVERLOAD_SNAME) {
                r = dhcp_option_merge_append(message->sname, sizeof(message->sname), opts, &tot_len, NULL);
                if (r < 0)
                        return r;
        }

        /* Consolidate in a new buffer */
        buflen = tot_len + ordered_hashmap_size(opts) * 3;
        aggregate = new(uint8_t, buflen);
        if (!aggregate)
                return r;

        size_t offset = 0;
        MergeOptionNode *head;
        ORDERED_HASHMAP_FOREACH(head, opts) {
                uint8_t code = head->data[0];
                uint8_t *opt_base = &aggregate[offset];
                offset += 3;

                size_t len = 0;
                LIST_FOREACH(options, opt, head) {
                        size_t optlen = opt->data[1];
                        memcpy_safe(&aggregate[offset], &opt->data[2], optlen);
                        offset += optlen;
                        len += optlen;
                }
                opt_base[0] = code;
                unaligned_write_be16(&opt_base[1], len);
        }

        *ret_merged = aggregate;
        return buflen;
}

int dhcp_option_parse(DHCPMessage *message, size_t len, dhcp_option_callback_t cb, void *userdata, char **ret_error_message) {
        _cleanup_free_ char *error_message = NULL;
        uint8_t message_type = 0;
        _cleanup_free_ uint8_t *options = NULL;
        int r;

        if (!message)
                return -EINVAL;

        if (len < sizeof(DHCPMessage))
                return -EINVAL;

        len -= sizeof(DHCPMessage);

        r = dhcp_option_merge(message, len, &options);
        if (r < 0)
                return r;
        len = r;

        r = parse_options(options, len, &message_type, &error_message, cb, userdata);
        if (r < 0)
                return r;

        if (message_type == 0)
                return -ENOMSG;

        if (ret_error_message && IN_SET(message_type, DHCP_NAK, DHCP_DECLINE))
                *ret_error_message = TAKE_PTR(error_message);

        return message_type;
}

int dhcp_option_parse_string(const uint8_t *option, size_t len, char **ret) {
        _cleanup_free_ char *string = NULL;
        int r;

        assert(option);
        assert(ret);

        if (len <= 0) {
                *ret = NULL;
                return 0;
        }

        /* One trailing NUL byte is OK, we don't mind. See:
         * https://github.com/systemd/systemd/issues/1337 */
        r = make_cstring((const char *) option, len, MAKE_CSTRING_ALLOW_TRAILING_NUL, &string);
        if (r < 0)
                return r;

        if (!string_is_safe(string) || !utf8_is_valid(string))
                return -EINVAL;

        *ret = TAKE_PTR(string);
        return 0;
}

int dhcp_option_parse_hostname(const uint8_t *option, size_t len, char **ret) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        assert(option);
        assert(ret);

        r = dhcp_option_parse_string(option, len, &hostname);
        if (r < 0)
                return r;

        if (!hostname) {
                *ret = NULL;
                return 0;
        }

        if (!hostname_is_valid(hostname, 0))
                return -EINVAL;

        r = dns_name_is_valid(hostname);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        *ret = TAKE_PTR(hostname);
        return 0;
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
