#pragma once

#include <inttypes.h>

#include "macro.h"
#include "sparse-endian.h"

struct DosFileHeader {
        le16_t LastSize;
        le16_t nBlocks;
        le16_t nReloc;
        le16_t HdrSize;
        le16_t MinAlloc;
        le16_t MaxAlloc;
        le16_t ss;
        le16_t sp;
        le16_t Checksum;
        le16_t ip;
        le16_t cs;
        le16_t RelocPos;
        le16_t nOverlay;
        le16_t OEMId;
        le16_t OEMInfo;
        le32_t ExeHeader;
        uint8_t Magic[2];
        le16_t reserved[4];
        le16_t reserved2[10];
} _packed_;

#define PE_HEADER_MACHINE_I386 0x014cU
#define PE_HEADER_MACHINE_X64  0x8664U

struct PeFileHeader {
        le16_t Machine;
        le16_t NumberOfSections;
        le32_t TimeDateStamp;
        le32_t PointerToSymbolTable;
        le32_t NumberOfSymbols;
        le16_t SizeOfOptionalHeader;
        le16_t Characteristics;
} _packed_;

struct PeHeader {
        struct PeFileHeader FileHeader;
        uint8_t Magic[4];
} _packed_;

struct PeSectionHeader {
        le32_t VirtualSize;
        le32_t VirtualAddress;
        le32_t SizeOfRawData;
        le32_t PointerToRawData;
        le32_t PointerToRelocations;
        le32_t PointerToLinenumbers;
        le16_t NumberOfRelocations;
        le16_t NumberOfLinenumbers;
        le32_t Characteristics;
        uint8_t Name[8];
 } _packed_;
