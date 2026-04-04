/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efi-log.h"
#include "part-discovery.h"
#include "proto/block-io.h"
#include "proto/device-path.h"
#include "proto/disk-io.h"
#include "string-util-fundamental.h"
#include "util.h"

typedef struct {
        EFI_GUID PartitionTypeGUID;
        EFI_GUID UniquePartitionGUID;
        EFI_LBA StartingLBA;
        EFI_LBA EndingLBA;
        uint64_t Attributes;
        char16_t PartitionName[36];
} EFI_PARTITION_ENTRY;

typedef struct {
        EFI_TABLE_HEADER Header;
        EFI_LBA MyLBA;
        EFI_LBA AlternateLBA;
        EFI_LBA FirstUsableLBA;
        EFI_LBA LastUsableLBA;
        EFI_GUID DiskGUID;
        EFI_LBA PartitionEntryLBA;
        uint32_t NumberOfPartitionEntries;
        uint32_t SizeOfPartitionEntry;
        uint32_t PartitionEntryArrayCRC32;
        uint8_t _pad[420];
} _packed_ GptHeader;
assert_cc(sizeof(GptHeader) == 512);

static bool verify_gpt(/* const */ GptHeader *h, EFI_LBA lba_expected) {
        uint32_t crc32, crc32_saved;
        EFI_STATUS err;

        assert(h);

        /* Some superficial validation of the GPT header */
        if (memcmp(&h->Header.Signature, "EFI PART", sizeof(h->Header.Signature)) != 0)
                return false;

        if (h->Header.HeaderSize < 92 || h->Header.HeaderSize > 512)
                return false;

        if (h->Header.Revision != 0x00010000U)
                return false;

        /* Calculate CRC check */
        crc32_saved = h->Header.CRC32;
        h->Header.CRC32 = 0;
        err = BS->CalculateCrc32(h, h->Header.HeaderSize, &crc32);
        h->Header.CRC32 = crc32_saved;
        if (err != EFI_SUCCESS || crc32 != crc32_saved)
                return false;

        if (h->MyLBA != lba_expected)
                return false;

        if ((h->SizeOfPartitionEntry % sizeof(EFI_PARTITION_ENTRY)) != 0)
                return false;

        if (h->NumberOfPartitionEntries <= 0 || h->NumberOfPartitionEntries > 1024)
                return false;

        /* overflow check */
        if (h->SizeOfPartitionEntry > SIZE_MAX / h->NumberOfPartitionEntries)
                return false;

        return true;
}

static EFI_STATUS read_gpt_entries(
                EFI_DISK_IO_PROTOCOL *disk_io,
                uint32_t media_id,
                uint32_t block_size,
                EFI_LBA lba,
                EFI_LBA *reterr_backup_lba, /* May be changed even on error! */
                GptHeader *ret_gpt,
                void **ret_entries) {

        GptHeader gpt;
        EFI_STATUS err;
        uint32_t crc32;
        size_t size;

        assert(disk_io);
        assert(ret_gpt);
        assert(ret_entries);

        uint64_t offset;
        if (!MUL_SAFE(&offset, lba, block_size))
                return log_debug_status(
                                EFI_INVALID_PARAMETER,
                                "LBA %" PRIu64 " * block size %" PRIu32 " overflow: %m",
                                lba,
                                block_size);

        err = disk_io->ReadDisk(disk_io, media_id, offset, sizeof(gpt), &gpt);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to read GPT header at LBA %" PRIu64 ": %m", lba);

        /* Expose backup LBA even if the rest of the header is corrupt, so the caller can
         * try the backup GPT. */
        if (reterr_backup_lba)
                *reterr_backup_lba = gpt.AlternateLBA;

        if (!verify_gpt(&gpt, lba))
                return log_debug_status(EFI_NOT_FOUND, "GPT header at LBA %" PRIu64 " is not valid: %m", lba);

        size = (size_t) gpt.SizeOfPartitionEntry * (size_t) gpt.NumberOfPartitionEntries;
        if (size == SIZE_MAX) /* overflow check */
                return log_debug_status(EFI_OUT_OF_RESOURCES, "GPT partition entries size overflow: %m");

        _cleanup_free_ void *entries = xmalloc(size);

        if (!MUL_SAFE(&offset, gpt.PartitionEntryLBA, block_size))
                return log_debug_status(
                                EFI_INVALID_PARAMETER,
                                "Partition entry LBA %" PRIu64 " * block size %" PRIu32 " overflow: %m",
                                gpt.PartitionEntryLBA,
                                block_size);

        err = disk_io->ReadDisk(disk_io, media_id, offset, size, entries);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to read GPT partition entries at LBA %" PRIu64 ": %m", gpt.PartitionEntryLBA);

        err = BS->CalculateCrc32(entries, size, &crc32);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to calculate CRC32 of GPT partition entries: %m");
        if (crc32 != gpt.PartitionEntryArrayCRC32)
                return log_debug_status(
                                EFI_CRC_ERROR,
                                "GPT partition entries CRC32 mismatch (got 0x%08" PRIx32 ", expected 0x%08" PRIx32 "): %m",
                                crc32,
                                gpt.PartitionEntryArrayCRC32);

        *ret_gpt = gpt;
        *ret_entries = TAKE_PTR(entries);
        return EFI_SUCCESS;
}

static EFI_STATUS try_gpt(
                const EFI_GUID *type,
                EFI_DISK_IO_PROTOCOL *disk_io,
                uint32_t media_id,
                uint32_t block_size,
                EFI_LBA lba,
                EFI_LBA *reterr_backup_lba, /* May be changed even on error! */
                HARDDRIVE_DEVICE_PATH *ret_hd) {

        GptHeader gpt;
        _cleanup_free_ void *entries = NULL;
        EFI_STATUS err;

        assert(ret_hd);

        err = read_gpt_entries(disk_io, media_id, block_size, lba, reterr_backup_lba, &gpt, &entries);
        if (err != EFI_SUCCESS)
                return err;

        for (size_t i = 0; i < gpt.NumberOfPartitionEntries; i++) {
                EFI_PARTITION_ENTRY *entry =
                                (EFI_PARTITION_ENTRY *) ((uint8_t *) entries + gpt.SizeOfPartitionEntry * i);

                if (!efi_guid_equal(&entry->PartitionTypeGUID, type))
                        continue;

                if (entry->EndingLBA < entry->StartingLBA) /* Bogus? */
                        continue;

                *ret_hd = (HARDDRIVE_DEVICE_PATH) {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_HARDDRIVE_DP,
                                .Length = sizeof(HARDDRIVE_DEVICE_PATH),
                        },
                        .PartitionNumber = i + 1,
                        .PartitionStart = entry->StartingLBA,
                        .PartitionSize = entry->EndingLBA - entry->StartingLBA + 1,
                        .MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
                        .SignatureType = SIGNATURE_TYPE_GUID,
                };
                memcpy(ret_hd->Signature, &entry->UniquePartitionGUID, sizeof(ret_hd->Signature));

                return EFI_SUCCESS;
        }

        /* This GPT was fully valid, but we didn't find what we are looking for. This
         * means there's no reason to check the second copy of the GPT header */
        return EFI_NOT_FOUND;
}

static EFI_STATUS find_device(const EFI_GUID *type, EFI_HANDLE *device, EFI_DEVICE_PATH **ret_device_path) {
        EFI_STATUS err;

        assert(device);
        assert(ret_device_path);

        EFI_DEVICE_PATH *partition_path;
        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &partition_path);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to get device path: %m");

        /* Find the (last) partition node itself. */
        EFI_DEVICE_PATH *part_node = NULL;
        for (EFI_DEVICE_PATH *node = partition_path; !device_path_is_end(node);
             node = device_path_next_node(node)) {
                if (node->Type != MEDIA_DEVICE_PATH || node->SubType != MEDIA_HARDDRIVE_DP)
                        continue;

                part_node = node;
        }

        if (!part_node) {
                log_debug("No hard drive device path node found.");
                return EFI_NOT_FOUND;
        }

        /* Chop off the partition part, leaving us with the full path to the disk itself. */
        _cleanup_free_ EFI_DEVICE_PATH *disk_path = NULL;
        EFI_DEVICE_PATH *p = disk_path = device_path_replace_node(partition_path, part_node, NULL);

        EFI_HANDLE disk_handle;
        EFI_BLOCK_IO_PROTOCOL *block_io;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &p, &disk_handle);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to locate disk device: %m");

        /* The drivers for other partitions on this drive may not be initialized on fastboot firmware, so we
         * have to ask the firmware to do just that. */
        (void) BS->ConnectController(disk_handle, NULL, NULL, true);

        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), (void **) &block_io);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to get block I/O protocol: %m");

        /* Filter out some block devices early. (We only care about block devices that aren't
         * partitions themselves — we look for GPT partition tables to parse after all —, and only
         * those which contain a medium and have at least 2 blocks.) */
        if (block_io->Media->LogicalPartition ||
            !block_io->Media->MediaPresent ||
            block_io->Media->LastBlock <= 1 ||
            block_io->Media->BlockSize < 512 || block_io->Media->BlockSize > 4096)
                return EFI_NOT_FOUND;

        EFI_DISK_IO_PROTOCOL *disk_io;
        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_DISK_IO_PROTOCOL), (void **) &disk_io);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to get disk I/O protocol: %m");

        /* Try several copies of the GPT header, in case one is corrupted */
        EFI_LBA backup_lba = 0;
        for (size_t nr = 0; nr < 3; nr++) {
                EFI_LBA lba;

                /* Read the first copy at LBA 1 and then try the backup GPT header pointed
                 * to by the first header if that one was corrupted. As a last resort,
                 * try the very last LBA of this block device. */
                if (nr == 0)
                        lba = 1;
                else if (nr == 1 && backup_lba != 0)
                        lba = backup_lba;
                else if (nr == 2 && backup_lba != block_io->Media->LastBlock)
                        lba = block_io->Media->LastBlock;
                else
                        continue;

                HARDDRIVE_DEVICE_PATH hd;
                err = try_gpt(type, disk_io, block_io->Media->MediaId, block_io->Media->BlockSize, lba,
                        nr == 0 ? &backup_lba : NULL, /* Only get backup LBA location from first GPT header. */
                        &hd);
                if (err != EFI_SUCCESS) {
                        /* GPT was valid but no XBOOT loader partition found. */
                        if (err == EFI_NOT_FOUND)
                                break;
                        /* Bad GPT, try next one. */
                        continue;
                }

                /* Patch in the data we found */
                *ret_device_path = device_path_replace_node(partition_path, part_node, &hd.Header);
                return EFI_SUCCESS;
        }

        /* No xbootloader partition found */
        return EFI_NOT_FOUND;
}

EFI_STATUS partition_open(const EFI_GUID *type, EFI_HANDLE *device, EFI_HANDLE *ret_device,
                          EFI_FILE **ret_root_dir) {
        _cleanup_free_ EFI_DEVICE_PATH *partition_path = NULL;
        EFI_HANDLE new_device;
        EFI_FILE *root_dir;
        EFI_STATUS err;

        assert(type);
        assert(device);
        assert(ret_root_dir);

        err = find_device(type, device, &partition_path);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *dp = partition_path;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &dp, &new_device);
        if (err != EFI_SUCCESS)
                return err;

        err = open_volume(new_device, &root_dir);
        if (err != EFI_SUCCESS)
                return err;

        if (ret_device)
                *ret_device = new_device;
        *ret_root_dir = root_dir;
        return EFI_SUCCESS;
}

static char16_t* disk_get_part_uuid_cdrom(const EFI_DEVICE_PATH *dp) {
        EFI_STATUS err;

        assert(dp);

        /* When booting from a CD-ROM via El Torito, the device path contains a CDROM node instead of
         * a HARDDRIVE node. The CDROM node doesn't carry a partition UUID, so we need to read the GPT
         * from the underlying disk to find it. */

        const CDROM_DEVICE_PATH *cdrom = NULL;
        for (const EFI_DEVICE_PATH *node = dp; !device_path_is_end(node); node = device_path_next_node(node))
                if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_CDROM_DP)
                        cdrom = (const CDROM_DEVICE_PATH *) node;
        if (!cdrom) {
                log_debug("No CDROM device path node found.");
                return NULL;
        }

        /* Chop off the CDROM node to get the whole-disk device path */
        _cleanup_free_ EFI_DEVICE_PATH *disk_path = device_path_replace_node(dp, &cdrom->Header, /* new_node= */ NULL);

        EFI_DEVICE_PATH *remaining = disk_path;
        EFI_HANDLE disk_handle;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &remaining, &disk_handle);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Failed to locate disk device for CDROM: %m");
                return NULL;
        }

        (void) BS->ConnectController(disk_handle, /* DriverImageHandle= */ NULL, /* RemainingDevicePath= */ NULL, /* Recursive= */ true);

        EFI_BLOCK_IO_PROTOCOL *block_io;
        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), (void **) &block_io);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Failed to get block I/O protocol for CDROM disk: %m");
                return NULL;
        }

        if (block_io->Media->LogicalPartition || !block_io->Media->MediaPresent ||
            block_io->Media->LastBlock <= 1) {
                log_debug("CDROM disk has unsuitable media (partition=%ls, present=%ls, lastblock=%" PRIu64 ").",
                          yes_no(block_io->Media->LogicalPartition),
                          yes_no(block_io->Media->MediaPresent),
                          (uint64_t) block_io->Media->LastBlock);
                return NULL;
        }

        uint32_t iso9660_block_size = block_io->Media->BlockSize;
        if (iso9660_block_size < 512 || iso9660_block_size > 4096 || !ISPOWEROF2(iso9660_block_size)) {
                log_debug("Unexpected CDROM block size %" PRIu32 ", skipping.", iso9660_block_size);
                return NULL;
        }

        EFI_DISK_IO_PROTOCOL *disk_io;
        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_DISK_IO_PROTOCOL), (void **) &disk_io);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Failed to get disk I/O protocol for CDROM disk: %m");
                return NULL;
        }

        uint32_t media_id = block_io->Media->MediaId;

        /* Probe for the GPT header at multiple possible sector sizes (512, 1024, 2048, 4096).
         * The GPT header is at LBA 1, i.e. byte offset == sector_size. On CD-ROMs, the GPT
         * may use a different sector size than the media's block size (e.g. 512-byte GPT sectors
         * on 2048-byte CD-ROM blocks), so we try all possibilities. If the primary GPT header is
         * corrupt but contains a valid backup LBA, fall back to the backup header. */
        uint32_t gpt_sector_size = 0;
        GptHeader gpt;
        _cleanup_free_ void *entries = NULL;
        for (uint32_t ss = 512; ss <= 4096; ss <<= 1) {
                EFI_LBA backup_lba = 0;

                err = read_gpt_entries(disk_io, media_id, ss, /* lba= */ 1, &backup_lba, &gpt, &entries);
                if (err == EFI_SUCCESS) {
                        gpt_sector_size = ss;
                        break;
                }
                if (err != EFI_NOT_FOUND)
                        log_debug_status(err, "Failed to read primary GPT header at sector size %"PRIu32", ignoring: %m", ss);

                if (backup_lba != 0) {
                        err = read_gpt_entries(disk_io, media_id, ss, backup_lba, /* reterr_backup_lba= */ NULL, &gpt, &entries);
                        if (err == EFI_SUCCESS) {
                                gpt_sector_size = ss;
                                break;
                        }
                        if (err != EFI_NOT_FOUND)
                                log_debug_status(err, "Failed to read backup GPT header at sector size %"PRIu32", ignoring: %m", ss);
                }
        }

        if (gpt_sector_size == 0) {
                log_debug("No valid GPT found on CDROM at any sector size.");
                return NULL;
        }

        log_debug("Found GPT on CDROM with sector size %" PRIu32 ", %" PRIu32 " partition entries.",
                  gpt_sector_size, gpt.NumberOfPartitionEntries);

        /* Find the partition whose byte offset matches the CDROM's PartitionStart.
         * CDROM PartitionStart is in media iso9660_block_size units, GPT StartingLBA is in gpt_sector_size units. */
        uint64_t cdrom_start;
        if (!MUL_SAFE(&cdrom_start, cdrom->PartitionStart, iso9660_block_size)) {
                log_debug("CDROM start offset overflow.");
                return NULL;
        }

        for (size_t i = 0; i < gpt.NumberOfPartitionEntries; i++) {
                const EFI_PARTITION_ENTRY *entry =
                                (const EFI_PARTITION_ENTRY *) ((const uint8_t *) entries + gpt.SizeOfPartitionEntry * i);

                if (!efi_guid_equal(&entry->PartitionTypeGUID, &(const EFI_GUID) ESP_GUID))
                        continue;

                uint64_t entry_start;
                if (MUL_SAFE(&entry_start, entry->StartingLBA, gpt_sector_size) &&
                    entry_start == cdrom_start)
                        return xasprintf(GUID_FORMAT_STR, GUID_FORMAT_VAL(entry->UniquePartitionGUID));
        }

        log_debug("No ESP partition matches CDROM start offset %" PRIu64 " (block size %" PRIu32 ").",
                  cdrom->PartitionStart, iso9660_block_size);
        return NULL;
}

char16_t *disk_get_part_uuid(EFI_HANDLE *handle) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        /* export the device path this image is started from */

        if (!handle)
                return NULL;

        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return NULL;

        for (EFI_DEVICE_PATH *node = dp; !device_path_is_end(node); node = device_path_next_node(node)) {
                if (node->Type != MEDIA_DEVICE_PATH || node->SubType != MEDIA_HARDDRIVE_DP)
                        continue;

                HARDDRIVE_DEVICE_PATH *hd = (HARDDRIVE_DEVICE_PATH *) node;
                if (hd->SignatureType != SIGNATURE_TYPE_GUID)
                        continue;

                return xasprintf(GUID_FORMAT_STR, GUID_FORMAT_VAL(hd->SignatureGuid));
        }

        /* No GPT partition node found — try CDROM device path as fallback */
        return disk_get_part_uuid_cdrom(dp);
}
