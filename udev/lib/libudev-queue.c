/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_queue {
	struct udev *udev;
	int refcount;
	unsigned long long int last_seen_udev_seqnum;
	struct udev_list_node queue_list;
	struct udev_list_node failed_list;
};

struct udev_queue *udev_queue_new(struct udev *udev)
{
	struct udev_queue *udev_queue;

	if (udev == NULL)
		return NULL;

	udev_queue = calloc(1, sizeof(struct udev_queue));
	if (udev_queue == NULL)
		return NULL;
	udev_queue->refcount = 1;
	udev_queue->udev = udev;
	udev_list_init(&udev_queue->queue_list);
	udev_list_init(&udev_queue->failed_list);
	return udev_queue;
}

struct udev_queue *udev_queue_ref(struct udev_queue *udev_queue)
{
	if (udev_queue == NULL)
		return NULL;
	udev_queue->refcount++;
	return udev_queue;
}

void udev_queue_unref(struct udev_queue *udev_queue)
{
	if (udev_queue == NULL)
		return;
	udev_queue->refcount--;
	if (udev_queue->refcount > 0)
		return;
	udev_list_cleanup_entries(udev_queue->udev, &udev_queue->queue_list);
	udev_list_cleanup_entries(udev_queue->udev, &udev_queue->failed_list);
	free(udev_queue);
}

struct udev *udev_queue_get_udev(struct udev_queue *udev_queue)
{
	if (udev_queue == NULL)
		return NULL;
	return udev_queue->udev;
}

unsigned long long int udev_queue_get_kernel_seqnum(struct udev_queue *udev_queue)
{
	char filename[UTIL_PATH_SIZE];
	unsigned long long int seqnum;
	int fd;
	char buf[32];
	ssize_t len;

	if (udev_queue == NULL)
		return -EINVAL;
	util_strscpyl(filename, sizeof(filename), udev_get_sys_path(udev_queue->udev), "/kernel/uevent_seqnum", NULL);
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return 0;
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 2)
		return 0;
	buf[len-1] = '\0';
	seqnum = strtoull(buf, NULL, 10);
	dbg(udev_queue->udev, "seqnum=%llu\n", seqnum);
	return seqnum;
}

unsigned long long int udev_queue_get_udev_seqnum(struct udev_queue *udev_queue)
{
	char filename[UTIL_PATH_SIZE];
	unsigned long long int seqnum;
	int fd;
	char buf[32];
	ssize_t len;

	if (udev_queue == NULL)
		return -EINVAL;
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev_queue->udev), "/.udev/uevent_seqnum", NULL);
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return 0;
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 2)
		return 0;
	buf[len-1] = '\0';
	seqnum = strtoull(buf, NULL, 10);
	dbg(udev_queue->udev, "seqnum=%llu\n", seqnum);
	udev_queue->last_seen_udev_seqnum = seqnum;
	return seqnum;
}

int udev_queue_get_udev_is_active(struct udev_queue *udev_queue)
{
	char filename[UTIL_PATH_SIZE];
	struct stat statbuf;

	if (udev_queue == NULL)
		return 0;
	util_strscpyl(filename, sizeof(filename), udev_get_dev_path(udev_queue->udev), "/.udev/uevent_seqnum", NULL);
	if (stat(filename, &statbuf) == 0)
		return 1;
	return 0;
}

int udev_queue_get_queue_is_empty(struct udev_queue *udev_queue)
{
	char queuename[UTIL_PATH_SIZE];
	struct stat statbuf;
	unsigned long long int seqnum_kernel;

	if (udev_queue == NULL)
		return -EINVAL;
	util_strscpyl(queuename, sizeof(queuename), udev_get_dev_path(udev_queue->udev), "/.udev/queue", NULL);
	if (stat(queuename, &statbuf) == 0) {
		dbg(udev_queue->udev, "queue is not empty\n");
		return 0;
	}
	seqnum_kernel = udev_queue_get_kernel_seqnum(udev_queue);
	if (seqnum_kernel <= udev_queue->last_seen_udev_seqnum) {
		dbg(udev_queue->udev, "queue is empty\n");
		return 1;
	}
	/* update udev seqnum, and check if udev is still running */
	if (udev_queue_get_udev_seqnum(udev_queue) == 0)
		if (!udev_queue_get_udev_is_active(udev_queue))
			return 1;
	if (seqnum_kernel <= udev_queue->last_seen_udev_seqnum) {
		dbg(udev_queue->udev, "queue is empty\n");
		return 1;
	}
	dbg(udev_queue->udev, "queue is empty, but kernel events still pending [%llu]<->[%llu]\n",
	     seqnum_kernel, udev_queue->last_seen_udev_seqnum);
	return 0;
}

int udev_queue_get_seqnum_is_finished(struct udev_queue *udev_queue, unsigned long long int seqnum)
{
	char filename[UTIL_PATH_SIZE];
	struct stat statbuf;

	if (udev_queue == NULL)
		return -EINVAL;
	/* did it reach the queue? */
	if (seqnum > udev_queue->last_seen_udev_seqnum)
		if (seqnum > udev_queue_get_udev_seqnum(udev_queue))
			return 0;
	/* is it still in the queue? */
	snprintf(filename, sizeof(filename), "%s/.udev/queue/%llu",
		 udev_get_dev_path(udev_queue->udev), seqnum);
	if (lstat(filename, &statbuf) == 0)
		return 0;
	dbg(udev_queue->udev, "seqnum: %llu finished\n", seqnum);
	return 1;
}

struct udev_list_entry *udev_queue_get_queued_list_entry(struct udev_queue *udev_queue)
{
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	if (udev_queue == NULL)
		return NULL;
	udev_list_cleanup_entries(udev_queue->udev, &udev_queue->queue_list);
	util_strscpyl(path, sizeof(path), udev_get_dev_path(udev_queue->udev), "/.udev/queue", NULL);
	dir = opendir(path);
	if (dir == NULL)
		return NULL;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char syspath[UTIL_PATH_SIZE];
		char *s;
		size_t l;
		ssize_t len;

		if (dent->d_name[0] == '.')
			continue;
		s = syspath;
		l = util_strpcpyl(&s, sizeof(syspath), udev_get_sys_path(udev_queue->udev), NULL);
		len = readlinkat(dirfd(dir), dent->d_name, s, l);
		if (len < 0 || (size_t)len >= l)
			continue;
		s[len] = '\0';
		dbg(udev_queue->udev, "found '%s' [%s]\n", syspath, dent->d_name);
		udev_list_entry_add(udev_queue->udev, &udev_queue->queue_list, syspath, dent->d_name, 0, 0);
	}
	closedir(dir);
	return udev_list_get_entry(&udev_queue->queue_list);
}

struct udev_list_entry *udev_queue_get_failed_list_entry(struct udev_queue *udev_queue)
{
	char path[UTIL_PATH_SIZE];
	DIR *dir;
	struct dirent *dent;

	if (udev_queue == NULL)
		return NULL;
	udev_list_cleanup_entries(udev_queue->udev, &udev_queue->failed_list);
	util_strscpyl(path, sizeof(path), udev_get_dev_path(udev_queue->udev), "/.udev/failed", NULL);
	dir = opendir(path);
	if (dir == NULL)
		return NULL;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char filename[UTIL_PATH_SIZE];
		char syspath[UTIL_PATH_SIZE];
		char *s;
		size_t l;
		ssize_t len;
		struct stat statbuf;

		if (dent->d_name[0] == '.')
			continue;
		s = syspath;
		l = util_strpcpyl(&s, sizeof(syspath), udev_get_sys_path(udev_queue->udev), NULL);
		len = readlinkat(dirfd(dir), dent->d_name, s, l);
		if (len < 0 || (size_t)len >= l)
			continue;
		s[len] = '\0';
		dbg(udev_queue->udev, "found '%s' [%s]\n", syspath, dent->d_name);
		util_strscpyl(filename, sizeof(filename), syspath, "/uevent", NULL);
		if (stat(filename, &statbuf) != 0)
			continue;
		udev_list_entry_add(udev_queue->udev, &udev_queue->failed_list, syspath, NULL, 0, 0);
	}
	closedir(dir);
	return udev_list_get_entry(&udev_queue->failed_list);
}

int udev_queue_export_udev_seqnum(struct udev_queue *udev_queue, unsigned long long int seqnum)
{
	return -1;
}

int udev_queue_export_device_queued(struct udev_queue *udev_queue, struct udev_device *udev_device)
{
	return -1;
}

int udev_queue_export_device_finished(struct udev_queue *udev_queue, struct udev_device *udev_device)
{
	return -1;
}

int udev_queue_export_device_failed(struct udev_queue *udev_queue, struct udev_device *udev_device)
{
	return -1;
}
