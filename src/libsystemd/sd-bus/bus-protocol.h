/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <endian.h>

#include "macro.h"

/* Packet header */

struct _packed_ bus_header {
        uint8_t endian;
        uint8_t type;
        uint8_t flags;
        uint8_t version;
        uint32_t body_size;
        /* Note that what the bus spec calls "serial" we'll call "cookie" instead, because we don't
         * want to imply that the cookie was in any way monotonically increasing. */
        uint32_t serial;
        uint32_t fields_size;
};

/* Endianness */

enum {
        _BUS_INVALID_ENDIAN = 0,
        BUS_LITTLE_ENDIAN   = 'l',
        BUS_BIG_ENDIAN      = 'B',
#if __BYTE_ORDER == __BIG_ENDIAN
        BUS_NATIVE_ENDIAN   = BUS_BIG_ENDIAN,
        BUS_REVERSE_ENDIAN  = BUS_LITTLE_ENDIAN
#else
        BUS_NATIVE_ENDIAN   = BUS_LITTLE_ENDIAN,
        BUS_REVERSE_ENDIAN  = BUS_BIG_ENDIAN
#endif
};

/* Flags */

enum {
        BUS_MESSAGE_NO_REPLY_EXPECTED               = 1 << 0,
        BUS_MESSAGE_NO_AUTO_START                   = 1 << 1,
        BUS_MESSAGE_ALLOW_INTERACTIVE_AUTHORIZATION = 1 << 2,
};

/* Header fields */

enum {
        _BUS_MESSAGE_HEADER_INVALID = 0,
        BUS_MESSAGE_HEADER_PATH,
        BUS_MESSAGE_HEADER_INTERFACE,
        BUS_MESSAGE_HEADER_MEMBER,
        BUS_MESSAGE_HEADER_ERROR_NAME,
        BUS_MESSAGE_HEADER_REPLY_SERIAL,
        BUS_MESSAGE_HEADER_DESTINATION,
        BUS_MESSAGE_HEADER_SENDER,
        BUS_MESSAGE_HEADER_SIGNATURE,
        BUS_MESSAGE_HEADER_UNIX_FDS,
        _BUS_MESSAGE_HEADER_MAX
};

/* RequestName parameters */

enum  {
        BUS_NAME_ALLOW_REPLACEMENT = 1 << 0,
        BUS_NAME_REPLACE_EXISTING  = 1 << 1,
        BUS_NAME_DO_NOT_QUEUE      = 1 << 2,
};

/* RequestName returns */
enum  {
        BUS_NAME_PRIMARY_OWNER = 1,
        BUS_NAME_IN_QUEUE = 2,
        BUS_NAME_EXISTS = 3,
        BUS_NAME_ALREADY_OWNER = 4
};

/* ReleaseName returns */
enum {
        BUS_NAME_RELEASED = 1,
        BUS_NAME_NON_EXISTENT = 2,
        BUS_NAME_NOT_OWNER = 3,
};

/* StartServiceByName returns */
enum {
        BUS_START_REPLY_SUCCESS = 1,
        BUS_START_REPLY_ALREADY_RUNNING = 2,
};
