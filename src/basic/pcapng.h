/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * For details about the file format see RFC:
 *   https://www.ietf.org/id/draft-tuexen-opsawg-pcapng-03.html
 *  and
 *    https://github.com/pcapng/pcapng/
 */
enum pcapng_block_types {
        PCAPNG_INTERFACE_BLOCK = 1,
        PCAPNG_PACKET_BLOCK,		/* Obsolete */
        PCAPNG_SIMPLE_PACKET_BLOCK,
        PCAPNG_NAME_RESOLUTION_BLOCK,
        PCAPNG_INTERFACE_STATS_BLOCK,
        PCAPNG_ENHANCED_PACKET_BLOCK,

        PCAPNG_SECTION_BLOCK   = 0x0A0D0D0A,
};

struct pcapng_option {
        uint16_t code;
        uint16_t length;
        uint8_t data[];
};

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D
#define PCAPNG_MAJOR_VERS 1
#define PCAPNG_MINOR_VERS 0

enum pcapng_opt {
        PCAPNG_OPT_END     = 0,
        PCAPNG_OPT_COMMENT = 1,
};

struct pcapng_section {
        uint32_t block_type;
        uint32_t block_length;
        uint32_t byte_order_magic;
        uint16_t major_version;
        uint16_t minor_version;
        uint64_t section_length;
};

enum pcapng_section_opt {
        PCAPNG_SHB_HARDWARE = 2,
        PCAPNG_SHB_OS       = 3,
        PCAPNG_SHB_USERAPPL = 4,
};

struct pcapng_interface_block {
        uint32_t block_type;	/* 1 */
        uint32_t block_length;
        uint16_t link_type;
        uint16_t reserved;
        uint32_t snap_len;
};

enum pcapng_interface_options {
        PCAPNG_IFB_NAME	 = 2,
        PCAPNG_IFB_DESCRIPTION,
        PCAPNG_IFB_IPV4ADDR,
        PCAPNG_IFB_IPV6ADDR,
        PCAPNG_IFB_MACADDR,
        PCAPNG_IFB_EUIADDR,
        PCAPNG_IFB_SPEED,
        PCAPNG_IFB_TSRESOL,
        PCAPNG_IFB_TZONE,
        PCAPNG_IFB_FILTER,
        PCAPNG_IFB_OS,
        PCAPNG_IFB_FCSLEN,
        PCAPNG_IFB_TSOFFSET,
        PCAPNG_IFB_HARDWARE,
};

struct pcapng_enhance_packet_block {
        uint32_t block_type;	/* 6 */
        uint32_t block_length;
        uint32_t interface_id;
        uint32_t timestamp_hi;
        uint32_t timestamp_lo;
        uint32_t capture_length;
        uint32_t original_length;
};

/* Flags values */
#define PCAPNG_IFB_INBOUND   0b01
#define PCAPNG_IFB_OUTBOUND  0b10

enum pcapng_epb_options {
        PCAPNG_EPB_FLAGS = 2,
        PCAPNG_EPB_HASH,
        PCAPNG_EPB_DROPCOUNT,
        PCAPNG_EPB_PACKETID,
        PCAPNG_EPB_QUEUE,
        PCAPNG_EPB_VERDICT,
};

struct pcapng_statistics_block {
        uint32_t block_type;	/* 5 */
        uint32_t block_length;
        uint32_t interface_id;
        uint32_t timestamp_hi;
        uint32_t timestamp_lo;
};

enum pcapng_isb_options {
        PCAPNG_ISB_STARTTIME = 2,
        PCAPNG_ISB_ENDTIME,
        PCAPNG_ISB_IFRECV,
        PCAPNG_ISB_IFDROP,
        PCAPNG_ISB_FILTERACCEPT,
        PCAPNG_ISB_OSDROP,
        PCAPNG_ISB_USRDELIV,
};
