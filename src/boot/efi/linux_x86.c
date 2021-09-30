/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * x86 specific code to for EFI handover boot protocol
 * Linux kernels version 5.8 and newer support providing the initrd by
 * LINUX_INITRD_MEDIA_GUID DevicePath. In order to support older kernels too,
 * this x86 specific linux_exec function passes the initrd by setting the
 * corresponding fields in the setup_header struct.
 *
 * see https://www.kernel.org/doc/html/latest/x86/boot.html
 */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "linux.h"
#include "macro-fundamental.h"
#include "util.h"

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
} _packed_;

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
} _packed_;

#ifdef __i386__
#define __regparm0__ __attribute__((regparm(0)))
#else
#define __regparm0__
#endif

typedef void(*handover_f)(void *image, EFI_SYSTEM_TABLE *table, struct boot_params *params) __regparm0__;

static void linux_efi_handover(EFI_HANDLE image, struct boot_params *params) {
        handover_f handover;
        UINTN start = (UINTN)params->hdr.code32_start;

        assert(params);

#ifdef __x86_64__
        asm volatile ("cli");
        start += 512;
#endif
        handover = (handover_f)(start + params->hdr.handover_offset);
        handover(image, ST, params);
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const CHAR8 *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        const struct boot_params *image_params;
        struct boot_params *boot_params;
        EFI_HANDLE initrd_handle = NULL;
        EFI_PHYSICAL_ADDRESS addr;
        UINT8 setup_sectors;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        image_params = (const struct boot_params *) linux_buffer;

        if (image_params->hdr.boot_flag != 0xAA55 ||
            image_params->hdr.header != SETUP_MAGIC ||
            image_params->hdr.version < 0x20b ||
            !image_params->hdr.relocatable_kernel)
                return EFI_LOAD_ERROR;

        addr = UINT32_MAX; /* Below the 32bit boundary */
        err = BS->AllocatePages(
                        AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(0x4000),
                        &addr);
        if (EFI_ERROR(err))
                return err;

        boot_params = (struct boot_params *) PHYSICAL_ADDRESS_TO_POINTER(addr);
        ZeroMem(boot_params, 0x4000);
        boot_params->hdr = image_params->hdr;
        boot_params->hdr.type_of_loader = 0xff;
        setup_sectors = image_params->hdr.setup_sects > 0 ? image_params->hdr.setup_sects : 4;
        boot_params->hdr.code32_start = (UINT32) POINTER_TO_PHYSICAL_ADDRESS(linux_buffer) + (setup_sectors + 1) * 512;

        if (cmdline) {
                addr = 0xA0000;

                err = BS->AllocatePages(
                                AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1),
                                &addr);
                if (EFI_ERROR(err))
                        return err;

                CopyMem(PHYSICAL_ADDRESS_TO_POINTER(addr), cmdline, cmdline_len);
                ((CHAR8 *) PHYSICAL_ADDRESS_TO_POINTER(addr))[cmdline_len] = 0;
                boot_params->hdr.cmd_line_ptr = (UINT32) addr;
        }

        /* Providing the initrd via LINUX_INITRD_MEDIA_GUID is only supported by Linux 5.8+ (5.7+ on ARM64).
           Until supported kernels become more established, we continue to set ramdisk in the handover struct.
           This value is overridden by kernels that support LINUX_INITRD_MEDIA_GUID.
           If you need to know which protocol was used by the kernel, pass "efi=debug" to the kernel,
           this will print a line when InitrdMediaGuid was successfully used to load the initrd.
         */
        boot_params->hdr.ramdisk_image = (UINT32) POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer);
        boot_params->hdr.ramdisk_size = (UINT32) initrd_length;

        /* register LINUX_INITRD_MEDIA_GUID */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (EFI_ERROR(err))
                return err;
        linux_efi_handover(image, boot_params);
        (void) initrd_unregister(initrd_handle);
        initrd_handle = NULL;
        return EFI_LOAD_ERROR;
}
