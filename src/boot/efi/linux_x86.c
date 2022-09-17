/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * x86 specific code to for EFI handover boot protocol
 * Linux kernels version 5.8 and newer support providing the initrd by
 * LINUX_INITRD_MEDIA_GUID DevicePath. In order to support older kernels too,
 * this x86 specific linux_exec function passes the initrd by setting the
 * corresponding fields in the setup_header struct.
 *
 * see https://docs.kernel.org/x86/boot.html
 */

#include <efi.h>
#include <efilib.h>

#include "initrd.h"
#include "linux.h"
#include "macro-fundamental.h"
#include "util.h"

#define KERNEL_SECTOR_SIZE 512u
#define BOOT_FLAG_MAGIC    0xAA55u
#define SETUP_MAGIC        0x53726448u /* "HdrS" */
#define SETUP_VERSION_2_11 0x20bu
#define SETUP_VERSION_2_12 0x20cu
#define CMDLINE_PTR_MAX    0xA0000u

enum {
        XLF_KERNEL_64              = 1 << 0,
        XLF_CAN_BE_LOADED_ABOVE_4G = 1 << 1,
        XLF_EFI_HANDOVER_32        = 1 << 2,
        XLF_EFI_HANDOVER_64        = 1 << 3,
#ifdef __x86_64__
        XLF_EFI_HANDOVER           = XLF_EFI_HANDOVER_64,
#else
        XLF_EFI_HANDOVER           = XLF_EFI_HANDOVER_32,
#endif
};

typedef struct {
        uint8_t  setup_sects;
        uint16_t root_flags;
        uint32_t syssize;
        uint16_t ram_size;
        uint16_t vid_mode;
        uint16_t root_dev;
        uint16_t boot_flag;
        uint8_t  jump; /* We split the 2-byte jump field from the spec in two for convenience. */
        uint8_t  setup_size;
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
} _packed_ SetupHeader;

/* We really only care about a few fields, but we still have to provide a full page otherwise. */
typedef struct {
        uint8_t pad[192];
        uint32_t ext_ramdisk_image;
        uint32_t ext_ramdisk_size;
        uint32_t ext_cmd_line_ptr;
        uint8_t pad2[293];
        SetupHeader hdr;
        uint8_t pad3[3480];
} _packed_ BootParams;
assert_cc(offsetof(BootParams, ext_ramdisk_image) == 0x0C0);
assert_cc(sizeof(BootParams) == 4096);

#ifdef __i386__
#  define __regparm0__ __attribute__((regparm(0)))
#else
#  define __regparm0__
#endif

typedef void (*handover_f)(void *image, EFI_SYSTEM_TABLE *table, BootParams *params) __regparm0__;

static void linux_efi_handover(EFI_HANDLE image, uintptr_t kernel, BootParams *params) {
        assert(params);

        kernel += (params->hdr.setup_sects + 1) * KERNEL_SECTOR_SIZE; /* 32bit entry address. */

#ifdef __x86_64__
        asm volatile("cli");
        kernel += KERNEL_SECTOR_SIZE; /* 64bit entry address. */
#endif

        kernel += params->hdr.handover_offset; /* 32/64bit EFI handover address. */

        /* Note in EFI mixed mode this now points to the correct 32bit handover entry point, allowing a 64bit
         * kernel to be booted from a 32bit sd-stub. */

        handover_f handover = (handover_f) kernel;
        handover(image, ST, params);
}

EFI_STATUS linux_exec(
                EFI_HANDLE image,
                const char *cmdline, UINTN cmdline_len,
                const void *linux_buffer, UINTN linux_length,
                const void *initrd_buffer, UINTN initrd_length) {

        EFI_HANDLE initrd_handle = NULL;
        EFI_PHYSICAL_ADDRESS addr;
        EFI_STATUS err;

        assert(image);
        assert(cmdline || cmdline_len == 0);
        assert(linux_buffer);
        assert(initrd_buffer || initrd_length == 0);

        if (linux_length < sizeof(BootParams))
                return EFI_LOAD_ERROR;

        const BootParams *image_params = (const BootParams *) linux_buffer;
        if (image_params->hdr.header != SETUP_MAGIC || image_params->hdr.boot_flag != BOOT_FLAG_MAGIC)
                return log_error_status_stall(EFI_UNSUPPORTED, u"Unsupported kernel image.");
        if (image_params->hdr.version < SETUP_VERSION_2_11)
                return log_error_status_stall(EFI_UNSUPPORTED, u"Kernel too old.");
        if (!image_params->hdr.relocatable_kernel)
                return log_error_status_stall(EFI_UNSUPPORTED, u"Kernel is not relocatable.");

        /* The xloadflags were added in version 2.12+ of the boot protocol but the handover support predates
         * that, so we cannot safety-check this for 2.11. */
        if (image_params->hdr.version >= SETUP_VERSION_2_12 &&
            !FLAGS_SET(image_params->hdr.xloadflags, XLF_EFI_HANDOVER))
                return log_error_status_stall(EFI_UNSUPPORTED, u"Kernel does not support EFI handover protocol.");

        bool can_4g = image_params->hdr.version >= SETUP_VERSION_2_12 &&
                        FLAGS_SET(image_params->hdr.xloadflags, XLF_CAN_BE_LOADED_ABOVE_4G);

        if (!can_4g && POINTER_TO_PHYSICAL_ADDRESS(linux_buffer) + linux_length > UINT32_MAX)
                return log_error_status_stall(
                                EFI_UNSUPPORTED,
                                u"Unified kernel image was loaded above 4G, but kernel lacks support.");
        if (!can_4g && POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer) + initrd_length > UINT32_MAX)
                return log_error_status_stall(
                                EFI_UNSUPPORTED, u"Initrd is above 4G, but kernel lacks support.");

        addr = UINT32_MAX; /* Below the 32bit boundary */
        err = BS->AllocatePages(
                        can_4g ? AllocateAnyPages : AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(sizeof(BootParams)),
                        &addr);
        if (err != EFI_SUCCESS)
                return err;

        BootParams *boot_params = PHYSICAL_ADDRESS_TO_POINTER(addr);
        memset(boot_params, 0, sizeof(BootParams));

        /* Setup size is determined by offset 0x0202 + byte value at offset 0x0201, which is the same as
         * offset of the header field and the target from the jump field (which we split for this reason). */
        memcpy(&boot_params->hdr,
               &image_params->hdr,
               offsetof(SetupHeader, header) + image_params->hdr.setup_size);

        boot_params->hdr.type_of_loader = 0xff;

        /* Spec says: For backwards compatibility, if the setup_sects field contains 0, the real value is 4. */
        if (boot_params->hdr.setup_sects == 0)
                boot_params->hdr.setup_sects = 4;

        if (cmdline) {
                addr = CMDLINE_PTR_MAX;

                err = BS->AllocatePages(
                                can_4g ? AllocateAnyPages : AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1),
                                &addr);
                if (err != EFI_SUCCESS)
                        return err;

                memcpy(PHYSICAL_ADDRESS_TO_POINTER(addr), cmdline, cmdline_len);
                ((char *) PHYSICAL_ADDRESS_TO_POINTER(addr))[cmdline_len] = 0;
                boot_params->hdr.cmd_line_ptr = (uint32_t) addr;
                boot_params->ext_cmd_line_ptr = addr >> 32;
                assert(can_4g || addr <= CMDLINE_PTR_MAX);
        }

        /* Providing the initrd via LINUX_INITRD_MEDIA_GUID is only supported by Linux 5.8+ (5.7+ on ARM64).
           Until supported kernels become more established, we continue to set ramdisk in the handover struct.
           This value is overridden by kernels that support LINUX_INITRD_MEDIA_GUID.
           If you need to know which protocol was used by the kernel, pass "efi=debug" to the kernel,
           this will print a line when InitrdMediaGuid was successfully used to load the initrd.
         */
        boot_params->hdr.ramdisk_image = (uintptr_t) initrd_buffer;
        boot_params->ext_ramdisk_image = POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer) >> 32;
        boot_params->hdr.ramdisk_size = initrd_length;
        boot_params->ext_ramdisk_size = ((uint64_t) initrd_length) >> 32;

        /* register LINUX_INITRD_MEDIA_GUID */
        err = initrd_register(initrd_buffer, initrd_length, &initrd_handle);
        if (err != EFI_SUCCESS)
                return err;
        linux_efi_handover(image, (uintptr_t) linux_buffer, boot_params);
        (void) initrd_unregister(initrd_handle);
        initrd_handle = NULL;
        return EFI_LOAD_ERROR;
}
