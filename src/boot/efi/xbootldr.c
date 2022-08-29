/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efigpt.h>
#include <efilib.h>

#include "util.h"
#include "xbootldr.h"

union GptHeaderBuffer {
        EFI_PARTITION_TABLE_HEADER gpt_header;
        uint8_t space[CONST_ALIGN_TO(sizeof(EFI_PARTITION_TABLE_HEADER), 512)];
};

static EFI_DEVICE_PATH *path_replace_hd(
                const EFI_DEVICE_PATH *path,
                const EFI_DEVICE_PATH *node,
                const HARDDRIVE_DEVICE_PATH *new_node) {

        /* Create a new device path as a copy of path, while chopping off the remainder starting at the given
         * node. If new_node is provided, it is appended at the end of the new path. */

        assert(path);
        assert(node);

        size_t len = (uint8_t *) node - (uint8_t *) path, new_node_len = 0;
        if (new_node)
                new_node_len = DevicePathNodeLength(&new_node->Header);

        EFI_DEVICE_PATH *ret = xmalloc(len + new_node_len + END_DEVICE_PATH_LENGTH);
        EFI_DEVICE_PATH *end = mempcpy(ret, path, len);

        if (new_node)
                end = mempcpy(end, new_node, new_node_len);

        SetDevicePathEndNode(end);
        return ret;
}

static bool verify_gpt(union GptHeaderBuffer *gpt_header_buffer, EFI_LBA lba_expected) {
        EFI_PARTITION_TABLE_HEADER *h;
        uint32_t crc32, crc32_saved;
        EFI_STATUS err;

        assert(gpt_header_buffer);

        h = &gpt_header_buffer->gpt_header;

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
        err = BS->CalculateCrc32(gpt_header_buffer, h->Header.HeaderSize, &crc32);
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
        if (h->SizeOfPartitionEntry > UINTN_MAX / h->NumberOfPartitionEntries)
                return false;

        return true;
}

static EFI_STATUS try_gpt(
                EFI_BLOCK_IO_PROTOCOL *block_io,
                EFI_LBA lba,
                EFI_LBA *ret_backup_lba, /* May be changed even on error! */
                HARDDRIVE_DEVICE_PATH *ret_hd) {

        _cleanup_free_ EFI_PARTITION_ENTRY *entries = NULL;
        union GptHeaderBuffer gpt;
        EFI_STATUS err;
        uint32_t crc32;
        UINTN size;

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
                *ret_backup_lba = gpt.gpt_header.AlternateLBA;

        if (!verify_gpt(&gpt, lba))
                return EFI_NOT_FOUND;

        /* Now load the GPT entry table */
        size = ALIGN_TO((UINTN) gpt.gpt_header.SizeOfPartitionEntry * (UINTN) gpt.gpt_header.NumberOfPartitionEntries, 512);
        entries = xmalloc(size);

        err = block_io->ReadBlocks(
                        block_io,
                        block_io->Media->MediaId,
                        gpt.gpt_header.PartitionEntryLBA,
                        size, entries);
        if (err != EFI_SUCCESS)
                return err;

        /* Calculate CRC of entries array, too */
        err = BS->CalculateCrc32(entries, size, &crc32);
        if (err != EFI_SUCCESS || crc32 != gpt.gpt_header.PartitionEntryArrayCRC32)
                return EFI_CRC_ERROR;

        /* Now we can finally look for xbootloader partitions. */
        for (UINTN i = 0; i < gpt.gpt_header.NumberOfPartitionEntries; i++) {
                EFI_PARTITION_ENTRY *entry =
                                (EFI_PARTITION_ENTRY *) ((uint8_t *) entries + gpt.gpt_header.SizeOfPartitionEntry * i);

                if (memcmp(&entry->PartitionTypeGUID, XBOOTLDR_GUID, sizeof(entry->PartitionTypeGUID)) != 0)
                        continue;

                if (entry->EndingLBA < entry->StartingLBA) /* Bogus? */
                        continue;

                *ret_hd = (HARDDRIVE_DEVICE_PATH) {
                        .Header = {
                                .Type = MEDIA_DEVICE_PATH,
                                .SubType = MEDIA_HARDDRIVE_DP,
                        },
                        .PartitionNumber = i + 1,
                        .PartitionStart = entry->StartingLBA,
                        .PartitionSize = entry->EndingLBA - entry->StartingLBA + 1,
                        .MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER,
                        .SignatureType = SIGNATURE_TYPE_GUID,
                };
                memcpy(ret_hd->Signature, &entry->UniquePartitionGUID, sizeof(ret_hd->Signature));

                /* HARDDRIVE_DEVICE_PATH has padding, which at least OVMF does not like. */
                SetDevicePathNodeLength(
                                &ret_hd->Header,
                                offsetof(HARDDRIVE_DEVICE_PATH, SignatureType) + sizeof(ret_hd->SignatureType));

                return EFI_SUCCESS;
        }

        /* This GPT was fully valid, but we didn't find what we are looking for. This
         * means there's no reason to check the second copy of the GPT header */
        return EFI_NOT_FOUND;
}

static EFI_STATUS find_device(EFI_HANDLE *device, EFI_DEVICE_PATH **ret_device_path) {
        EFI_STATUS err;

        assert(device);
        assert(ret_device_path);

        EFI_DEVICE_PATH *partition_path;
        err = BS->HandleProtocol(device, &DevicePathProtocol, (void **) &partition_path);
        if (err != EFI_SUCCESS)
                return err;

        /* Find the (last) partition node itself. */
        EFI_DEVICE_PATH *part_node = NULL;
        for (EFI_DEVICE_PATH *node = partition_path; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                if (DevicePathType(node) != MEDIA_DEVICE_PATH)
                        continue;

                if (DevicePathSubType(node) != MEDIA_HARDDRIVE_DP)
                        continue;

                part_node = node;
        }

        if (!part_node)
                return EFI_NOT_FOUND;

        /* Chop off the partition part, leaving us with the full path to the disk itself. */
        _cleanup_free_ EFI_DEVICE_PATH *disk_path = NULL;
        EFI_DEVICE_PATH *p = disk_path = path_replace_hd(partition_path, part_node, NULL);

        EFI_HANDLE disk_handle;
        EFI_BLOCK_IO_PROTOCOL *block_io;
        err = BS->LocateDevicePath(&BlockIoProtocol, &p, &disk_handle);
        if (err != EFI_SUCCESS)
                return err;

        err = BS->HandleProtocol(disk_handle, &BlockIoProtocol, (void **)&block_io);
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
        for (UINTN nr = 0; nr < 3; nr++) {
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
                err = try_gpt(
                        block_io, lba,
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
                *ret_device_path = path_replace_hd(partition_path, part_node, &hd);
                return EFI_SUCCESS;
        }

        /* No xbootloader partition found */
        return EFI_NOT_FOUND;
}

EFI_STATUS xbootldr_open(EFI_HANDLE *device, EFI_HANDLE *ret_device, EFI_FILE **ret_root_dir) {
        _cleanup_free_ EFI_DEVICE_PATH *partition_path = NULL;
        EFI_HANDLE new_device;
        EFI_FILE *root_dir;
        EFI_STATUS err;

        assert(device);
        assert(ret_device);
        assert(ret_root_dir);

        err = find_device(device, &partition_path);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *dp = partition_path;
        err = BS->LocateDevicePath(&BlockIoProtocol, &dp, &new_device);
        if (err != EFI_SUCCESS)
                return err;

        err = open_volume(new_device, &root_dir);
        if (err != EFI_SUCCESS)
                return err;

        *ret_device = new_device;
        *ret_root_dir = root_dir;
        return EFI_SUCCESS;
}
