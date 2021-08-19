/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define SETUP_MAGIC             0x53726448      /* "HdrS" */

struct setup_header {
        UINT8  setup_sects;
        UINT16 root_flags;
        UINT32 syssize;
        UINT16 ram_size;
        UINT16 vid_mode;
        UINT16 root_dev;
        UINT16 boot_flag;
        UINT16 jump;
        UINT32 header;
        UINT16 version;
        UINT32 realmode_swtch;
        UINT16 start_sys_seg;
        UINT16 kernel_version;
        UINT8  type_of_loader;
        UINT8  loadflags;
        UINT16 setup_move_size;
        UINT32 code32_start;
        UINT32 ramdisk_image;
        UINT32 ramdisk_size;
        UINT32 bootsect_kludge;
        UINT16 heap_end_ptr;
        UINT8  ext_loader_ver;
        UINT8  ext_loader_type;
        UINT32 cmd_line_ptr;
        UINT32 initrd_addr_max;
        UINT32 kernel_alignment;
        UINT8  relocatable_kernel;
        UINT8  min_alignment;
        UINT16 xloadflags;
        UINT32 cmdline_size;
        UINT32 hardware_subarch;
        UINT64 hardware_subarch_data;
        UINT32 payload_offset;
        UINT32 payload_length;
        UINT64 setup_data;
        UINT64 pref_address;
        UINT32 init_size;
        UINT32 handover_offset;
} __attribute__((packed));

/* adapted from linux' bootparam.h */
struct boot_params {
        UINT8  screen_info[64];         // was: struct screen_info
        UINT8  apm_bios_info[20];       // was: struct apm_bios_info
        UINT8  _pad2[4];
        UINT64 tboot_addr;
        UINT8  ist_info[16];            // was: struct ist_info
        UINT8  _pad3[16];
        UINT8  hd0_info[16];
        UINT8  hd1_info[16];
        UINT8  sys_desc_table[16];      // was: struct sys_desc_table
        UINT8  olpc_ofw_header[16];     // was: struct olpc_ofw_header
        UINT32 ext_ramdisk_image;
        UINT32 ext_ramdisk_size;
        UINT32 ext_cmd_line_ptr;
        UINT8  _pad4[116];
        UINT8  edid_info[128];          // was: struct edid_info
        UINT8  efi_info[32];            // was: struct efi_info
        UINT32 alt_mem_k;
        UINT32 scratch;
        UINT8  e820_entries;
        UINT8  eddbuf_entries;
        UINT8  edd_mbr_sig_buf_entries;
        UINT8  kbd_status;
        UINT8  secure_boot;
        UINT8  _pad5[2];
        UINT8  sentinel;
        UINT8  _pad6[1];
        struct setup_header hdr;
        UINT8  _pad7[0x290-0x1f1-sizeof(struct setup_header)];
        UINT32 edd_mbr_sig_buffer[16];  // was: edd_mbr_sig_buffer[EDD_MBR_SIG_MAX]
        UINT8  e820_table[20*128];      // was: struct boot_e820_entry e820_table[E820_MAX_ENTRIES_ZEROPAGE]
        UINT8  _pad8[48];
        UINT8  eddbuf[6*82];            // was: struct edd_info eddbuf[EDDMAXNR]
        UINT8  _pad9[276];
} __attribute__((packed));

EFI_STATUS linux_exec(EFI_HANDLE image,
                      CHAR8 *cmdline, UINTN cmdline_size,
                      UINTN linux_addr,
                      UINTN initrd_addr, UINTN initrd_size);
