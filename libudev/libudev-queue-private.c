/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2009 Alan Jenkins <alan-jenkins@tuffmail.co.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

/*
 * DISCLAIMER - The file format mentioned here is private to udev/libudev,
 *              and may be changed without notice.
 *
 * The udev event queue is exported as a binary log file.
 * Each log record consists of a sequence number followed by the device path.
 *
 * When a new event is queued, its details are appended to the log.
 * When the event finishes, a second record is appended to the log
 * with the same sequence number but a devpath len of 0.
 *
 * Example:
 *	{ 0x0000000000000001 }
 *	{ 0x0000000000000001, 0x0019, "/devices/virtual/mem/null" },
 *	{ 0x0000000000000002, 0x001b, "/devices/virtual/mem/random" },
 *	{ 0x0000000000000001, 0x0000 },
 *	{ 0x0000000000000003, 0x0019, "/devices/virtual/mem/zero" },
 *
 * Events 2 and 3 are still queued, but event 1 has finished.
 *
 * The queue does not grow indefinitely. It is periodically re-created
 * to remove finished events. Atomic rename() makes this transparent to readers.
 *
 * The queue file starts with a single sequence number which specifies the
 * minimum sequence number in the log that follows. Any events prior to this
 * sequence number have already finished.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libudev.h"
#include "libudev-private.h"

static int rebuild_queue_file(struct udev_queue_export *udev_queue_export);

struct udev_queue_export {
	struct udev *udev;
	int failed_count;	/* number of failed events exported */
	int queued_count;	/* number of unfinished events exported in queue file */
	FILE *queue_file;
	unsigned long long int seqnum_max;	/* earliest sequence number in queue file */
	unsigned long long int seqnum_min;	/* latest sequence number in queue file */
	int waste_bytes;			/* queue file bytes wasted on finished events */
};

struct udev_queue_export *udev_queue_export_new(struct udev *udev)
{
	struct udev_queue_export *udev_queue_export;
	unsigned long long int initial_seqnum;

	if (udev == NULL)
		return NULL;

	udev_queue_export = calloc(1, sizeof(struct udev_queue_export));
	if (udev_queue_export == NULL)
		return NULL;
	udev_queue_export->udev = udev;

	initial_seqnum = udev_get_kernel_seqnum(udev);
	udev_queue_export->seqnum_min = initial_seqnum;
	udev_queue_export->seqnum_max = initial_seqnum;

	udev_queue_export_cleanup(udev_queue_export);
	if (rebuild_queue_file(udev_queue_export) != 0) {
		free(udev_queue_export);
		return NULL;
	}

	return udev_queue_export;
}

void udev_queue_export_unref(struct udev_queue_export *udev_queue_export)
{
	if (udev_queue_export == NULL)
		return;
	if (udev_queue_export->queue_file != NULL)
		fclose(udev_queue_export->queue_file);
	free(udev_queue_export);
}

void udev_queue_export_cleanup(struct udev_queue_export *udev_queue_export)
{
	char filename[UTIL_PATH_SIZE];

	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev_queue_export->udev), "/.udev/queue.tmp", NULL);
	unlink(filename);

	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev_queue_export->udev), "/.udev/queue.bin", NULL);
	unlink(filename);
}

static int skip_to(FILE *file, long offset)
{
	long old_offset;

	/* fseek may drop buffered data, avoid it for small seeks */
	old_offset = ftell(file);
	if (offset > old_offset && offset - old_offset <= BUFSIZ) {
		size_t skip_bytes = offset - old_offset;
		char buf[skip_bytes];

		if (fread(buf, skip_bytes, 1, file) != skip_bytes)
			return -1;
	}

	return fseek(file, offset, SEEK_SET);
}

struct queue_devpaths {
	unsigned int devpaths_first;	/* index of first queued event */
	unsigned int devpaths_size;
	long devpaths[];		/* seqnum -> offset of devpath in queue file (or 0) */
};

/*
 * Returns a table mapping seqnum to devpath file offset for currently queued events.
 * devpaths[i] represents the event with seqnum = i + udev_queue_export->seqnum_min.
 */
static struct queue_devpaths *build_index(struct udev_queue_export *udev_queue_export)
{
	struct queue_devpaths *devpaths;
	unsigned long long int range;
	long devpath_offset;
	ssize_t devpath_len;
	unsigned long long int seqnum;
	unsigned long long int n;
	unsigned int i;

	/* seek to the first event in the file */
	rewind(udev_queue_export->queue_file);
	udev_queue_read_seqnum(udev_queue_export->queue_file, &seqnum);

	/* allocate the table */
	range = udev_queue_export->seqnum_min - udev_queue_export->seqnum_max;
	if (range - 1 > INT_MAX) {
		err(udev_queue_export->udev, "queue file overflow\n");
		return NULL;
	}
	devpaths = calloc(1, sizeof(struct queue_devpaths) + (range + 1) * sizeof(long));
	if (devpaths == NULL)
		return NULL;
	devpaths->devpaths_size = range + 1;

	/* read all records and populate the table */
	while(1) {
		if (udev_queue_read_seqnum(udev_queue_export->queue_file, &seqnum) < 0)
			break;
		n = seqnum - udev_queue_export->seqnum_max;
		if (n >= devpaths->devpaths_size)
			goto read_error;

		devpath_offset = ftell(udev_queue_export->queue_file);
		devpath_len = udev_queue_skip_devpath(udev_queue_export->queue_file);
		if (devpath_len < 0)
			goto read_error;

		if (devpath_len > 0)
			devpaths->devpaths[n] = devpath_offset;
		else
			devpaths->devpaths[n] = 0;
	}

	/* find first queued event */
	for (i = 0; i < devpaths->devpaths_size; i++) {
		if (devpaths->devpaths[i] != 0)
			break;
	}
	devpaths->devpaths_first = i;

	return devpaths;

read_error:
	err(udev_queue_export->udev, "queue file corrupted\n");
	free(devpaths);
	return NULL;
}

static int rebuild_queue_file(struct udev_queue_export *udev_queue_export)
{
	unsigned long long int seqnum;
	struct queue_devpaths *devpaths = NULL;
	char filename[UTIL_PATH_SIZE];
	char filename_tmp[UTIL_PATH_SIZE];
	FILE *new_queue_file = NULL;
	unsigned int i;

	/* read old queue file */
	if (udev_queue_export->queue_file != NULL) {
		dbg(udev_queue_export->udev, "compacting queue file, freeing %d bytes\n",
						udev_queue_export->waste_bytes);

		devpaths = build_index(udev_queue_export);
		if (devpaths != NULL)
			udev_queue_export->seqnum_max += devpaths->devpaths_first;
	}
	if (devpaths == NULL) {
		dbg(udev_queue_export->udev, "creating empty queue file\n");
		udev_queue_export->queued_count = 0;
		udev_queue_export->seqnum_max = udev_queue_export->seqnum_min;
	}

	/* create new queue file */
	util_strscpyl(filename_tmp, sizeof(filename_tmp), udev_get_dev_path(udev_queue_export->udev), "/.udev/queue.tmp", NULL);
	new_queue_file = fopen(filename_tmp, "w+");
	if (new_queue_file == NULL)
		goto error;
	seqnum = udev_queue_export->seqnum_max;
	fwrite(&seqnum, 1, sizeof(unsigned long long int), new_queue_file);

	/* copy unfinished events only to the new file */
	if (devpaths != NULL) {
		for (i = devpaths->devpaths_first; i < devpaths->devpaths_size; i++) {
			char devpath[UTIL_PATH_SIZE];
			int err;
			unsigned short devpath_len;

			if (devpaths->devpaths[i] != 0)
			{
				skip_to(udev_queue_export->queue_file, devpaths->devpaths[i]);
				err = udev_queue_read_devpath(udev_queue_export->queue_file, devpath, sizeof(devpath));
				devpath_len = err;

				fwrite(&seqnum, sizeof(unsigned long long int), 1, new_queue_file);
				fwrite(&devpath_len, sizeof(unsigned short), 1, new_queue_file);
				fwrite(devpath, 1, devpath_len, new_queue_file);
			}
			seqnum++;
		}
		free(devpaths);
		devpaths = NULL;
	}
	fflush(new_queue_file);
	if (ferror(new_queue_file))
		goto error;

	/* rename the new file on top of the old one */
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev_queue_export->udev), "/.udev/queue.bin", NULL);
	if (rename(filename_tmp, filename) != 0)
		goto error;

	if (udev_queue_export->queue_file != NULL)
		fclose(udev_queue_export->queue_file);
	udev_queue_export->queue_file = new_queue_file;
	udev_queue_export->waste_bytes = 0;

	return 0;

error:
	err(udev_queue_export->udev, "failed to create queue file: %m\n");
	udev_queue_export_cleanup(udev_queue_export);

	if (udev_queue_export->queue_file != NULL) {
		fclose(udev_queue_export->queue_file);
		udev_queue_export->queue_file = NULL;
	}
	if (new_queue_file != NULL)
		fclose(new_queue_file);

	if (devpaths != NULL)
		free(devpaths);
	udev_queue_export->queued_count = 0;
	udev_queue_export->waste_bytes = 0;
	udev_queue_export->seqnum_max = udev_queue_export->seqnum_min;

	return -1;
}

static int write_queue_record(struct udev_queue_export *udev_queue_export,
			      unsigned long long int seqnum, const char *devpath, size_t devpath_len)
{
	unsigned short len;

	if (udev_queue_export->queue_file == NULL) {
		dbg(udev_queue_export->udev, "can't record event: queue file not available\n");
		return -1;
	}

	if (fwrite(&seqnum, sizeof(unsigned long long int), 1, udev_queue_export->queue_file) != 1)
		goto write_error;

	len = (devpath_len < USHRT_MAX) ? devpath_len : USHRT_MAX;
	if (fwrite(&len, sizeof(unsigned short), 1, udev_queue_export->queue_file) != 1)
		goto write_error;
	if (fwrite(devpath, 1, len, udev_queue_export->queue_file) != len)
		goto write_error;

	/* *must* flush output; caller may fork */
	if (fflush(udev_queue_export->queue_file) != 0)
		goto write_error;

	return 0;

write_error:
	/* if we failed half way through writing a record to a file,
	   we should not try to write any further records to it. */
	err(udev_queue_export->udev, "error writing to queue file: %m\n");
	fclose(udev_queue_export->queue_file);
	udev_queue_export->queue_file = NULL;

	return -1;
}

enum device_state {
	DEVICE_QUEUED,
	DEVICE_FINISHED,
	DEVICE_FAILED,
};

static inline size_t queue_record_size(size_t devpath_len)
{
	return sizeof(unsigned long long int) + sizeof(unsigned short int) + devpath_len;
}

static int update_queue(struct udev_queue_export *udev_queue_export,
			 struct udev_device *udev_device, enum device_state state)
{
	unsigned long long int seqnum = udev_device_get_seqnum(udev_device);
	const char *devpath = NULL;
	size_t devpath_len = 0;
	int bytes;
	int err;

	if (state == DEVICE_QUEUED) {
		devpath = udev_device_get_devpath(udev_device);
		devpath_len = strlen(devpath);
	}

	/* recover from an earlier failed rebuild */
	if (udev_queue_export->queue_file == NULL) {
		if (rebuild_queue_file(udev_queue_export) != 0)
			return -1;
	}

	/* when the queue file grows too large, garbage-collect and rebuild it */
	bytes = ftell(udev_queue_export->queue_file) + queue_record_size(devpath_len);

	/* if we're removing the last event from the queue, that's the best time to rebuild it */
	if (state != DEVICE_QUEUED && udev_queue_export->queued_count == 1 && bytes > 2048) {
		/* because we don't need to read the old queue file */
		fclose(udev_queue_export->queue_file);
		udev_queue_export->queue_file = NULL;
		rebuild_queue_file(udev_queue_export);
		return 0;
	}

	/* try to rebuild the queue files before they grow larger than one page. */
	if ((udev_queue_export->waste_bytes > bytes / 2) && bytes > 4096)
		rebuild_queue_file(udev_queue_export);

	/* don't record a finished event, if we already dropped the event in a failed rebuild */
	if (seqnum < udev_queue_export->seqnum_max)
		return 0;

	/* now write to the queue */
	if (state == DEVICE_QUEUED) {
		udev_queue_export->queued_count++;
		udev_queue_export->seqnum_min = seqnum;
	} else {
		udev_queue_export->waste_bytes += queue_record_size(devpath_len) + queue_record_size(0);
		udev_queue_export->queued_count--;
	}
	err = write_queue_record(udev_queue_export, seqnum, devpath, devpath_len);

	/* try to handle ENOSPC */
	if (err != 0 && udev_queue_export->queued_count == 0) {
		udev_queue_export_cleanup(udev_queue_export);
		err = rebuild_queue_file(udev_queue_export);
	}

	return err;
}

static void update_failed(struct udev_queue_export *udev_queue_export,
			  struct udev_device *udev_device, enum device_state state)
{
	struct udev *udev = udev_device_get_udev(udev_device);
	char filename[UTIL_PATH_SIZE];

	if (state != DEVICE_FAILED && udev_queue_export->failed_count == 0)
		return;

	/* location of failed file */
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev), "/.udev/failed/",
		      udev_device_get_subsystem(udev_device), ":", udev_device_get_sysname(udev_device), NULL);

	switch (state) {
	case DEVICE_FAILED:
		/* record event in the failed directory */
		udev_queue_export->failed_count++;
		util_create_path(udev, filename);
		udev_selinux_setfscreatecon(udev, filename, S_IFLNK);
		symlink(udev_device_get_devpath(udev_device), filename);
		udev_selinux_resetfscreatecon(udev);
		break;

	case DEVICE_QUEUED:
		/* delete failed file */
		if (unlink(filename) == 0) {
			util_delete_path(udev, filename);
			udev_queue_export->failed_count--;
		}
		break;

	case DEVICE_FINISHED:
		break;
	}

	return;
}

static int update(struct udev_queue_export *udev_queue_export,
		  struct udev_device *udev_device, enum device_state state)
{
	update_failed(udev_queue_export, udev_device, state);

	if (update_queue(udev_queue_export, udev_device, state) != 0)
		return -1;

	return 0;
}

int udev_queue_export_device_queued(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device)
{
	return update(udev_queue_export, udev_device, DEVICE_QUEUED);
}

int udev_queue_export_device_finished(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device)
{
	return update(udev_queue_export, udev_device, DEVICE_FINISHED);
}

int udev_queue_export_device_failed(struct udev_queue_export *udev_queue_export, struct udev_device *udev_device)
{
	return update(udev_queue_export, udev_device, DEVICE_FAILED);
}
