/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "part-discovery.h"
#include "proto/block-io.h"
#include "proto/device-path.h"
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

static bool verify_gpt(/*const*/ GptHeader *h, EFI_LBA lba_expected) {
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

static EFI_STATUS try_gpt(
                const EFI_GUID *type,
                EFI_BLOCK_IO_PROTOCOL *block_io,
                EFI_LBA lba,
                EFI_LBA *ret_backup_lba, /* May be changed even on error! */
                HARDDRIVE_DEVICE_PATH *ret_hd) {

        _cleanup_free_ EFI_PARTITION_ENTRY *entries = NULL;
        GptHeader gpt;
        EFI_STATUS err;
        uint32_t crc32;
        size_t size;

        assert(block_io);
        assert(ret_hd);

        /* Read the GPT header */
        err = block_io->ReadBlocks(
                        block_io,
                        block_io->Media->MediaId,
                        lba,
                        sizeof(gpt), &gpt);
        if (err != EFI_SUCCESS)
                return err;

        /* Indicate the location of backup LBA even if the rest of the header is corrupt. */
        if (ret_backup_lba)
                *ret_backup_lba = gpt.AlternateLBA;

        if (!verify_gpt(&gpt, lba))
                return EFI_NOT_FOUND;

        /* Now load the GPT entry table */
        size = ALIGN_TO((size_t) gpt.SizeOfPartitionEntry * (size_t) gpt.NumberOfPartitionEntries, 512);
        entries = xmalloc(size);

        err = block_io->ReadBlocks(
                        block_io,
                        block_io->Media->MediaId,
                        gpt.PartitionEntryLBA,
                        size, entries);
        if (err != EFI_SUCCESS)
                return err;

        /* Calculate CRC of entries array, too */
        err = BS->CalculateCrc32(entries, size, &crc32);
        if (err != EFI_SUCCESS || crc32 != gpt.PartitionEntryArrayCRC32)
                return EFI_CRC_ERROR;

        /* Now we can finally look for xbootloader partitions. */
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
        void *partition_path_raw;
        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &partition_path_raw);
        if (err != EFI_SUCCESS)
                return err;
        
        partition_path = partition_path_raw;

        /* Find the (last) partition node itself. */
        EFI_DEVICE_PATH *part_node = NULL;
        for (EFI_DEVICE_PATH *node = partition_path; !device_path_is_end(node);
             node = device_path_next_node(node)) {
                if (node->Type != MEDIA_DEVICE_PATH || node->SubType != MEDIA_HARDDRIVE_DP)
                        continue;

                part_node = node;
        }

        if (!part_node)
                return EFI_NOT_FOUND;

        /* Chop off the partition part, leaving us with the full path to the disk itself. */
        _cleanup_free_ EFI_DEVICE_PATH *disk_path = NULL;
        EFI_DEVICE_PATH *p = disk_path = device_path_replace_node(partition_path, part_node, NULL);

        EFI_HANDLE disk_handle;
        EFI_BLOCK_IO_PROTOCOL *block_io;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), &p, &disk_handle);
        if (err != EFI_SUCCESS)
                return err;

        /* The drivers for other partitions on this drive may not be initialized on fastboot firmware, so we
         * have to ask the firmware to do just that. */
        (void) BS->ConnectController(disk_handle, NULL, NULL, true);

        err = BS->HandleProtocol(disk_handle, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), (void **) &block_io);
        if (err != EFI_SUCCESS)
                return err;

        /* Filter out some block devices early. (We only care about block devices that aren't
         * partitions themselves — we look for GPT partition tables to parse after all —, and only
         * those which contain a medium and have at least 2 blocks.) */
        if (block_io->Media->LogicalPartition ||
            !block_io->Media->MediaPresent ||
            block_io->Media->LastBlock <= 1)
                return EFI_NOT_FOUND;

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
                err = try_gpt(type, block_io, lba,
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

char16_t *disk_get_part_uuid(EFI_HANDLE *handle) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        /* export the device path this image is started from */

        if (!handle)
                return NULL;

        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return NULL;

        for (; !device_path_is_end(dp); dp = device_path_next_node(dp)) {
                if (dp->Type != MEDIA_DEVICE_PATH || dp->SubType != MEDIA_HARDDRIVE_DP)
                        continue;

                HARDDRIVE_DEVICE_PATH *hd = (HARDDRIVE_DEVICE_PATH *) dp;
                if (hd->SignatureType != SIGNATURE_TYPE_GUID)
                        continue;

                return xasprintf(GUID_FORMAT_STR, GUID_FORMAT_VAL(hd->SignatureGuid));
        }

        return NULL;
}
