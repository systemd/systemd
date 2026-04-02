/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "proto/file-io.h"              /* IWYU pragma: keep */

#define xnew(type, n) ASSERT_PTR(new(type, n))

/* Include the implementation directly so we can exercise the internal PE helpers. */
#include "pe.c"

EFI_STATUS chid_match(
                const void *hwid_buffer,
                size_t hwid_length,
                uint32_t match_type,
                const Device **ret_device) {

        return EFI_UNSUPPORTED;
}

bool firmware_devicetree_exists(void) {
        return false;
}

EFI_STATUS devicetree_match(const void *uki_dtb, size_t uki_dtb_length) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS devicetree_match_by_compatible(const void *uki_dtb, size_t uki_dtb_length, const char *compat) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS efi_firmware_match_by_fwid(const void *blob, size_t blob_len, const char *fwid) {
        return EFI_UNSUPPORTED;
}

EFI_STATUS log_internal(EFI_STATUS status, LogLevel log_level, const char *format, ...) {
        return status;
}

static void make_test_kernel(
                void *file_image,
                void *loaded_image,
                size_t size,
                uint64_t image_base,
                uint64_t fixup_value,
                uint32_t page_rva,
                uint16_t entry) {

        assert(file_image);
        assert(loaded_image);
        assert(size >= 0x200);

        memzero(file_image, size);
        memzero(loaded_image, size);

        DosFileHeader *dos = file_image;
        memcpy(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC));
        dos->ExeHeader = 0x40;

        PeFileHeader *pe = (PeFileHeader *) ((uint8_t *) file_image + dos->ExeHeader);
        memcpy(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC));
        pe->FileHeader.Machine = TARGET_MACHINE_TYPE;
        pe->FileHeader.NumberOfSections = 1;
        pe->FileHeader.SizeOfOptionalHeader = sizeof(PeOptionalHeader);
        pe->OptionalHeader.Magic = OPTHDR64_MAGIC;
        pe->OptionalHeader.MajorImageVersion = 1;
        pe->OptionalHeader.ImageBase64 = image_base;
        pe->OptionalHeader.SizeOfImage = size;
        pe->OptionalHeader.SizeOfHeaders = 0x80;
        pe->OptionalHeader.NumberOfRvaAndSizes64 = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        pe->OptionalHeader.DataDirectory64[BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY] = (PeImageDataDirectory) {
                .VirtualAddress = 0x80,
                .Size = 10,
        };

        memcpy(loaded_image, file_image, 0x80);

        unaligned_write_ne32((uint8_t *) loaded_image + 0x80, page_rva);
        unaligned_write_ne32((uint8_t *) loaded_image + 0x84, 10);
        unaligned_write_ne16((uint8_t *) loaded_image + 0x88, entry);

        uint32_t fixup_rva = page_rva + (entry & 0x0FFF);
        if (fixup_rva <= size && sizeof(uint64_t) <= size - fixup_rva)
                unaligned_write_ne64((uint8_t *) loaded_image + fixup_rva, fixup_value);
}

static void test_pe_kernel_apply_relocations_add(void) {
        void *file_image;
        void *loaded_image;
        const uint64_t image_base = UINT64_C(0x100000);
        const uint64_t actual_base = UINT64_C(0x105000);
        const uint64_t fixup_value = image_base + UINT64_C(0x2340);

        file_image = ASSERT_PTR(malloc0(0x400));
        loaded_image = ASSERT_PTR(malloc0(0x400));

        make_test_kernel(
                        file_image,
                        loaded_image,
                        0x400,
                        image_base,
                        fixup_value,
                        0x100,
                        (IMAGE_REL_BASED_DIR64 << 12) | 0x20);

        assert_se(pe_kernel_apply_relocations(file_image, loaded_image, 0x400, actual_base) == EFI_SUCCESS);
        assert_se(unaligned_read_ne64((uint8_t *) loaded_image + 0x120) == fixup_value + (actual_base - image_base));

        free(loaded_image);
        free(file_image);
}

static void test_pe_kernel_apply_relocations_subtract(void) {
        void *file_image;
        void *loaded_image;
        const uint64_t image_base = UINT64_C(0x200000);
        const uint64_t actual_base = UINT64_C(0x1ff000);
        const uint64_t fixup_value = image_base + UINT64_C(0x5000);

        file_image = ASSERT_PTR(malloc0(0x400));
        loaded_image = ASSERT_PTR(malloc0(0x400));

        make_test_kernel(
                        file_image,
                        loaded_image,
                        0x400,
                        image_base,
                        fixup_value,
                        0x100,
                        (IMAGE_REL_BASED_DIR64 << 12) | 0x20);

        assert_se(pe_kernel_apply_relocations(file_image, loaded_image, 0x400, actual_base) == EFI_SUCCESS);
        assert_se(unaligned_read_ne64((uint8_t *) loaded_image + 0x120) == fixup_value + (actual_base - image_base));

        free(loaded_image);
        free(file_image);
}

static void test_pe_kernel_apply_relocations_fixup_overflow(void) {
        void *file_image;
        void *loaded_image;

        file_image = ASSERT_PTR(malloc0(0x400));
        loaded_image = ASSERT_PTR(malloc0(0x400));

        make_test_kernel(
                        file_image,
                        loaded_image,
                        0x400,
                        UINT64_C(0x300000),
                        UINT64_C(0x300000),
                        UINT32_MAX,
                        (IMAGE_REL_BASED_DIR64 << 12) | 0x0FFF);

        assert_se(pe_kernel_apply_relocations(file_image, loaded_image, 0x400, UINT64_C(0x301000)) == EFI_LOAD_ERROR);

        free(loaded_image);
        free(file_image);
}

int main(int argc, char *argv[]) {
        test_pe_kernel_apply_relocations_add();
        test_pe_kernel_apply_relocations_subtract();
        test_pe_kernel_apply_relocations_fixup_overflow();
        return EXIT_SUCCESS;
}
