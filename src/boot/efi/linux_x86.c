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
        uint8_t  setup_sects;
        uint16_t root_flags;
        uint32_t syssize;
        uint16_t ram_size;
        uint16_t vid_mode;
        uint16_t root_dev;
        uint16_t boot_flag;
        uint16_t jump;
        uint32_t header;
        uint16_t version;
        uint32_t realmode_swtch;
        uint16_t start_sys_seg;
        uint16_t kernel_version;
        uint8_t  type_of_loader;
        uint8_t  loadflags;
        uint16_t setup_move_size;
        uint32_t code32_start;
        uint32_t ramdisk_image;
        uint32_t ramdisk_size;
        uint32_t bootsect_kludge;
        uint16_t heap_end_ptr;
        uint8_t  ext_loader_ver;
        uint8_t  ext_loader_type;
        uint32_t cmd_line_ptr;
        uint32_t initrd_addr_max;
        uint32_t kernel_alignment;
        uint8_t  relocatable_kernel;
        uint8_t  min_alignment;
        uint16_t xloadflags;
        uint32_t cmdline_size;
        uint32_t hardware_subarch;
        uint64_t hardware_subarch_data;
        uint32_t payload_offset;
        uint32_t payload_length;
        uint64_t setup_data;
        uint64_t pref_address;
        uint32_t init_size;
        uint32_t handover_offset;
} _packed_;

/* adapted from linux' bootparam.h */
struct boot_params {
        uint8_t  screen_info[64];         // was: struct screen_info
        uint8_t  apm_bios_info[20];       // was: struct apm_bios_info
        uint8_t  _pad2[4];
        uint64_t tboot_addr;
        uint8_t  ist_info[16];            // was: struct ist_info
        uint8_t  _pad3[16];
        uint8_t  hd0_info[16];
        uint8_t  hd1_info[16];
        uint8_t  sys_desc_table[16];      // was: struct sys_desc_table
        uint8_t  olpc_ofw_header[16];     // was: struct olpc_ofw_header
        uint32_t ext_ramdisk_image;
        uint32_t ext_ramdisk_size;
        uint32_t ext_cmd_line_ptr;
        uint8_t  _pad4[116];
        uint8_t  edid_info[128];          // was: struct edid_info
        uint8_t  efi_info[32];            // was: struct efi_info
        uint32_t alt_mem_k;
        uint32_t scratch;
        uint8_t  e820_entries;
        uint8_t  eddbuf_entries;
        uint8_t  edd_mbr_sig_buf_entries;
        uint8_t  kbd_status;
        uint8_t  secure_boot;
        uint8_t  _pad5[2];
        uint8_t  sentinel;
        uint8_t  _pad6[1];
        struct setup_header hdr;
        uint8_t  _pad7[0x290-0x1f1-sizeof(struct setup_header)];
        uint32_t edd_mbr_sig_buffer[16];  // was: edd_mbr_sig_buffer[EDD_MBR_SIG_MAX]
        uint8_t  e820_table[20*128];      // was: struct boot_e820_entry e820_table[E820_MAX_ENTRIES_ZEROPAGE]
        uint8_t  _pad8[48];
        uint8_t  eddbuf[6*82];            // was: struct edd_info eddbuf[EDDMAXNR]
        uint8_t  _pad9[276];
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
        uint8_t setup_sectors;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        if (linux_length < sizeof(struct boot_params))
                return EFI_LOAD_ERROR;

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
        if (err != EFI_SUCCESS)
                return err;

        boot_params = (struct boot_params *) PHYSICAL_ADDRESS_TO_POINTER(addr);
        memset(boot_params, 0, 0x4000);
        boot_params->hdr = image_params->hdr;
        boot_params->hdr.type_of_loader = 0xff;
        setup_sectors = image_params->hdr.setup_sects > 0 ? image_params->hdr.setup_sects : 4;
        boot_params->hdr.code32_start = (uint32_t) POINTER_TO_PHYSICAL_ADDRESS(linux_buffer) + (setup_sectors + 1) * 512;

        if (cmdline) {
                addr = 0xA0000;

                err = BS->AllocatePages(
                                AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1),
                                &addr);
                if (err != EFI_SUCCESS)
                        return err;

                memcpy(PHYSICAL_ADDRESS_TO_POINTER(addr), cmdline, cmdline_len);
                ((CHAR8 *) PHYSICAL_ADDRESS_TO_POINTER(addr))[cmdline_len] = 0;
                boot_params->hdr.cmd_line_ptr = (uint32_t) addr;
        }

        /* Providing the initrd via LINUX_INITRD_MEDIA_GUID is only supported by Linux 5.8+ (5.7+ on ARM64).
           Until supported kernels become more established, we continue to set ramdisk in the handover struct.
           This value is overridden by kernels that support LINUX_INITRD_MEDIA_GUID.
           If you need to know which protocol was used by the kernel, pass "efi=debug" to the kernel,
           this will print a line when InitrdMediaGuid was successfully used to load the initrd.
         */
        boot_params->hdr.ramdisk_image = (uint32_t) POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer);
        boot_params->hdr.ramdisk_size = (uint32_t) initrd_length;

        /* register LINUX_INITRD_MEDIA_GUID */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (err != EFI_SUCCESS)
                return err;
        linux_efi_handover(image, boot_params);
        (void) initrd_unregister(initrd_handle);
        initrd_handle = NULL;
        return EFI_LOAD_ERROR;
}
