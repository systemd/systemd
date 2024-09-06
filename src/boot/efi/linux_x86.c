/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * x86 specific code to for EFI handover boot protocol
 * Linux kernels version 5.8 and newer support providing the initrd by
 * LINUX_INITRD_MEDIA_GUID DevicePath. In order to support older kernels too,
 * this x86 specific linux_exec function passes the initrd by setting the
 * corresponding fields in the setup_header struct.
 *
 * see https://docs.kernel.org/arch/x86/boot.html
 */

#include "initrd.h"
#include "linux.h"
#include "macro-fundamental.h"
#include "memory-util-fundamental.h"
#include "util.h"

#define KERNEL_SECTOR_SIZE 512u
#define BOOT_FLAG_MAGIC    0xAA55u
#define SETUP_MAGIC        0x53726448u /* "HdrS" */
#define SETUP_VERSION_2_11 0x20bu
#define SETUP_VERSION_2_12 0x20cu
#define SETUP_VERSION_2_15 0x20fu
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

typedef void (*handover_f)(void *parent, EFI_SYSTEM_TABLE *table, BootParams *params) __regparm0__
                __attribute__((sysv_abi));

static void linux_efi_handover(EFI_HANDLE parent, uintptr_t kernel, BootParams *params) {
        assert(params);

        kernel += (params->hdr.setup_sects + 1) * KERNEL_SECTOR_SIZE; /* 32-bit entry address. */

        /* Old kernels needs this set, while newer ones seem to ignore this. */
        params->hdr.code32_start = kernel;

#ifdef __x86_64__
        kernel += KERNEL_SECTOR_SIZE; /* 64-bit entry address. */
#endif

        kernel += params->hdr.handover_offset; /* 32/64-bit EFI handover address. */

        /* Note in EFI mixed mode this now points to the correct 32-bit handover entry point, allowing a 64-bit
         * kernel to be booted from a 32-bit sd-stub. */

        handover_f handover = (handover_f) kernel;
        handover(parent, ST, params);
}

EFI_STATUS linux_exec_efi_handover(
                EFI_HANDLE parent,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd,
                size_t kernel_size_in_memory) {

        assert(parent);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        if (kernel->iov_len < sizeof(BootParams))
                return EFI_LOAD_ERROR;

        const BootParams *image_params = (const BootParams *) kernel->iov_base;
        if (image_params->hdr.header != SETUP_MAGIC || image_params->hdr.boot_flag != BOOT_FLAG_MAGIC)
                return log_error_status(EFI_UNSUPPORTED, "Unsupported kernel image.");
        if (image_params->hdr.version < SETUP_VERSION_2_11)
                return log_error_status(EFI_UNSUPPORTED, "Kernel too old.");
        if (!image_params->hdr.relocatable_kernel)
                return log_error_status(EFI_UNSUPPORTED, "Kernel is not relocatable.");

        /* The xloadflags were added in version 2.12+ of the boot protocol but the handover support predates
         * that, so we cannot safety-check this for 2.11. */
        if (image_params->hdr.version >= SETUP_VERSION_2_12 &&
            !FLAGS_SET(image_params->hdr.xloadflags, XLF_EFI_HANDOVER))
                return log_error_status(EFI_UNSUPPORTED, "Kernel does not support EFI handover protocol.");

        bool can_4g = image_params->hdr.version >= SETUP_VERSION_2_12 &&
                        FLAGS_SET(image_params->hdr.xloadflags, XLF_CAN_BE_LOADED_ABOVE_4G);

        /* There is no way to pass the high bits of code32_start. Newer kernels seems to handle this
         * just fine, but older kernels will fail even if they otherwise have above 4G boot support.
         * A PE image's memory footprint can be larger than its file size, due to unallocated virtual
         * memory sections. While normally all PE headers should be taken into account, this case only
         * involves x86 Linux bzImage kernel images, for which unallocated areas are only part of the last
         * header, so parsing SizeOfImage and zeroeing the buffer past the image size is enough. */
        _cleanup_pages_ Pages linux_relocated = {};
        const void *linux_buffer;
        if (POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base) + kernel->iov_len > UINT32_MAX || kernel_size_in_memory > kernel->iov_len) {
                linux_relocated = xmalloc_pages(
                                AllocateMaxAddress,
                                EfiLoaderCode,
                                EFI_SIZE_TO_PAGES(MAX(kernel_size_in_memory, kernel->iov_len)),
                                UINT32_MAX);
                linux_buffer = memcpy(
                                PHYSICAL_ADDRESS_TO_POINTER(linux_relocated.addr), kernel->iov_base, kernel->iov_len);
                if (kernel_size_in_memory > kernel->iov_len)
                        memzero((uint8_t *) linux_buffer + kernel->iov_len, kernel_size_in_memory - kernel->iov_len);
        } else
                linux_buffer = kernel->iov_base;

        _cleanup_pages_ Pages initrd_relocated = {};
        const void *initrd_buffer;
        if (!can_4g && POINTER_TO_PHYSICAL_ADDRESS(initrd->iov_base) + initrd->iov_len > UINT32_MAX) {
                initrd_relocated = xmalloc_pages(
                                AllocateMaxAddress, EfiLoaderData, EFI_SIZE_TO_PAGES(initrd->iov_len), UINT32_MAX);
                initrd_buffer = memcpy(
                                PHYSICAL_ADDRESS_TO_POINTER(initrd_relocated.addr),
                                initrd->iov_base,
                                initrd->iov_len);
        } else
                initrd_buffer = initrd->iov_base;

        _cleanup_pages_ Pages boot_params_page = xmalloc_pages(
                        can_4g ? AllocateAnyPages : AllocateMaxAddress,
                        EfiLoaderData,
                        EFI_SIZE_TO_PAGES(sizeof(BootParams)),
                        UINT32_MAX /* Below the 4G boundary */);
        BootParams *boot_params = PHYSICAL_ADDRESS_TO_POINTER(boot_params_page.addr);
        *boot_params = (BootParams){};

        /* Setup size is determined by offset 0x0202 + byte value at offset 0x0201, which is the same as
         * offset of the header field and the target from the jump field (which we split for this reason). */
        memcpy(&boot_params->hdr,
               &image_params->hdr,
               offsetof(SetupHeader, header) + image_params->hdr.setup_size);

        boot_params->hdr.type_of_loader = 0xff;

        /* Spec says: For backwards compatibility, if the setup_sects field contains 0, the real value is 4. */
        if (boot_params->hdr.setup_sects == 0)
                boot_params->hdr.setup_sects = 4;

        _cleanup_pages_ Pages cmdline_pages = {};
        if (cmdline) {
                size_t len = MIN(strlen16(cmdline), image_params->hdr.cmdline_size);

                cmdline_pages = xmalloc_pages(
                                can_4g ? AllocateAnyPages : AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(len + 1),
                                CMDLINE_PTR_MAX);

                /* Convert cmdline to ASCII. */
                char *cmdline8 = PHYSICAL_ADDRESS_TO_POINTER(cmdline_pages.addr);
                for (size_t i = 0; i < len; i++)
                        cmdline8[i] = cmdline[i] <= 0x7E ? cmdline[i] : ' ';
                cmdline8[len] = '\0';

                boot_params->hdr.cmd_line_ptr = (uint32_t) cmdline_pages.addr;
                boot_params->ext_cmd_line_ptr = cmdline_pages.addr >> 32;
                assert(can_4g || cmdline_pages.addr <= CMDLINE_PTR_MAX);
        }

        boot_params->hdr.ramdisk_image = (uintptr_t) initrd_buffer;
        boot_params->ext_ramdisk_image = POINTER_TO_PHYSICAL_ADDRESS(initrd_buffer) >> 32;
        boot_params->hdr.ramdisk_size = initrd->iov_len;
        boot_params->ext_ramdisk_size = ((uint64_t) initrd->iov_len) >> 32;

        log_wait();
        linux_efi_handover(parent, (uintptr_t) linux_buffer, boot_params);
        return EFI_LOAD_ERROR;
}
