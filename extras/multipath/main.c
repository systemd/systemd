/*
 * Soft:        multipath device mapper target autoconfig
 *
 * Version:     $Id: main.h,v 0.0.1 2003/09/18 15:13:38 cvaroqui Exp $
 *
 * Author:      Copyright (C) 2003 Christophe Varoqui
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/kdev_t.h>
#include <string.h>
#include <sys/ioctl.h>
#include <libsysfs.h>
#include "libdevmapper/libdevmapper.h"
#include "main.h"

static int
do_inq(int sg_fd, int cmddt, int evpd, unsigned int pg_op,
       void *resp, int mx_resp_len, int noisy)
{
	unsigned char inqCmdBlk[INQUIRY_CMDLEN] =
	    { INQUIRY_CMD, 0, 0, 0, 0, 0 };
	unsigned char sense_b[SENSE_BUFF_LEN];
	struct sg_io_hdr io_hdr;

	if (cmddt)
		inqCmdBlk[1] |= 2;
	if (evpd)
		inqCmdBlk[1] |= 1;
	inqCmdBlk[2] = (unsigned char) pg_op;
	inqCmdBlk[4] = (unsigned char) mx_resp_len;
	memset(&io_hdr, 0, sizeof (struct sg_io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof (inqCmdBlk);
	io_hdr.mx_sb_len = sizeof (sense_b);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len = mx_resp_len;
	io_hdr.dxferp = resp;
	io_hdr.cmdp = inqCmdBlk;
	io_hdr.sbp = sense_b;
	io_hdr.timeout = DEF_TIMEOUT;

	if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
		perror("SG_IO (inquiry) error");
		return -1;
	}

	/* treat SG_ERR here to get rid of sg_err.[ch] */
	io_hdr.status &= 0x7e;
	if ((0 == io_hdr.status) && (0 == io_hdr.host_status) &&
	    (0 == io_hdr.driver_status))
		return 0;
	if ((SCSI_CHECK_CONDITION == io_hdr.status) ||
	    (SCSI_COMMAND_TERMINATED == io_hdr.status) ||
	    (SG_ERR_DRIVER_SENSE == (0xf & io_hdr.driver_status))) {
		if (io_hdr.sbp && (io_hdr.sb_len_wr > 2)) {
			int sense_key;
			unsigned char * sense_buffer = io_hdr.sbp;
			if (sense_buffer[0] & 0x2)
				sense_key = sense_buffer[1] & 0xf;
			else
				sense_key = sense_buffer[2] & 0xf;
			if(RECOVERED_ERROR == sense_key)
				return 0;
		}
	}
	return -1;
}

static void
sprint_wwid(char * buff, const char * str)
{
	int i;
	const char *p;
	char *cursor;
	unsigned char c;

	p = str;
	cursor = buff;
	for (i = 0; i <= WWID_SIZE / 2 - 1; i++) {
		c = *p++;
		sprintf(cursor, "%.2x", (int) (unsigned char) c);
		cursor += 2;
	}
	buff[WWID_SIZE - 1] = '\0';
}

static void
basename(char * str1, char * str2)
{
	char *p = str1 + (strlen(str1) - 1);

	while (*--p != '/')
		continue;
	strcpy(str2, ++p);
}

static int
get_lun_strings(struct env * conf, struct path * mypath)
{
	int fd;
	char buff[36];
	char attr_path[FILE_NAME_SIZE];
	char basedev[FILE_NAME_SIZE];

	if(conf->with_sysfs) {
		/* sysfs style */
		basename(mypath->sg_dev, basedev);

		sprintf(attr_path, "%s/block/%s/device/vendor",
                        conf->sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
		    mypath->vendor_id, 8)) return 0;

		sprintf(attr_path, "%s/block/%s/device/model",
                        conf->sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
		    mypath->product_id, 16)) return 0;

		sprintf(attr_path, "%s/block/%s/device/rev",
                        conf->sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
		    mypath->rev, 4)) return 0;
	} else {
		/* ioctl style */
		if ((fd = open(mypath->sg_dev, O_RDONLY)) < 0)
			return 0;
		if (0 != do_inq(fd, 0, 0, 0, buff, 36, 1))
			return 0;
		memcpy(mypath->vendor_id, &buff[8], 8);
		memcpy(mypath->product_id, &buff[16], 16);
		memcpy(mypath->rev, &buff[32], 4);
		close(fd);
		return 1;
	}
	return 0;
}

/* hardware vendor specifics : add support for new models below */

/* this one get EVPD page 0x83 off 8 */
/* tested ok with StorageWorks */
static int
get_evpd_wwid(struct path * mypath)
{
	int fd;
	char buff[64];

	if ((fd = open(mypath->sg_dev, O_RDONLY)) < 0)
                        return 0;

	if (0 == do_inq(fd, 0, 1, 0x83, buff, sizeof (buff), 1)) {
		sprint_wwid(mypath->wwid, &buff[8]);
		close(fd);
		return 1; /* success */
	}
	close(fd);
	return 0; /* not good */
}

/* White list switch */
static int
get_unique_id(struct path * mypath)
{
	int i;
	static struct {
		char * vendor;
		char * product;
		int iopolicy;
		int (*getuid) (struct path *);
	} wlist[] = {
		{"COMPAQ  ", "HSV110 (C)COMPAQ", MULTIBUS, &get_evpd_wwid},
		{"COMPAQ  ", "MSA1000         ", MULTIBUS, &get_evpd_wwid},
		{"COMPAQ  ", "MSA1000 VOLUME  ", MULTIBUS, &get_evpd_wwid},
		{"DEC     ", "HSG80           ", MULTIBUS, &get_evpd_wwid},
		{"HP      ", "HSV100          ", MULTIBUS, &get_evpd_wwid},
		{"HP      ", "A6189A          ", MULTIBUS, &get_evpd_wwid},
		{"HP      ", "OPEN-           ", MULTIBUS, &get_evpd_wwid},
		{"DDN     ", "SAN DataDirector", MULTIBUS, &get_evpd_wwid},
		{"FSC     ", "CentricStor     ", MULTIBUS, &get_evpd_wwid},
		{"HITACHI ", "DF400           ", MULTIBUS, &get_evpd_wwid},
		{"HITACHI ", "DF500           ", MULTIBUS, &get_evpd_wwid},
		{"HITACHI ", "DF600           ", MULTIBUS, &get_evpd_wwid},
		{"IBM     ", "ProFibre 4000R  ", MULTIBUS, &get_evpd_wwid},
		{"SGI     ", "TP9100          ", MULTIBUS, &get_evpd_wwid},
		{"SGI     ", "TP9300          ", MULTIBUS, &get_evpd_wwid},
		{"SGI     ", "TP9400          ", MULTIBUS, &get_evpd_wwid},
		{"SGI     ", "TP9500          ", MULTIBUS, &get_evpd_wwid},
		{NULL, NULL, 0, NULL},
	};

	for (i = 0; wlist[i].vendor; i++) {
		if (strncmp(mypath->vendor_id, wlist[i].vendor, 8) == 0 &&
		    strncmp(mypath->product_id, wlist[i].product, 16) == 0) {
			mypath->iopolicy = wlist[i].iopolicy;
			if (!wlist[i].getuid(mypath))
				return 0;
		}
	}
	return 1;
}

static int
blacklist (char * dev) {
	int i;
	static struct {
		char * headstr;
		int lengh;
	} blist[] = {
		{"cciss", 5},
		{"hd", 2},
		{"md", 2},
		{"dm", 2},
		{"sr", 2},
		{"scd", 3},
		{"ram", 3},
		{"raw", 3},
		{NULL, 0},
	};

	for (i = 0; blist[i].lengh; i++) {
		if (strncmp(dev, blist[i].headstr, blist[i].lengh) == 0)
			return 1;
	}
	return 0;
}

static int
get_all_paths_sysfs(struct env * conf, struct path * all_paths)
{
	int k=0;
	struct sysfs_directory * sdir;
	struct sysfs_directory * devp;
	struct sysfs_link * linkp;
	char refwwid[WWID_SIZE];
	char empty_buff[WWID_SIZE];
	char buff[FILE_NAME_SIZE];
	char path[FILE_NAME_SIZE];
	struct path curpath;

	/* if called from hotplug, only consider the paths that relate to */
	/* to the device pointed by conf.hotplugdev */
	memset(empty_buff, 0, WWID_SIZE);
	memset(refwwid, 0, WWID_SIZE);
	if (strncmp("/devices", conf->hotplugdev, 8) == 0) {
		sprintf(buff, "%s%s/block",
			conf->sysfs_path, conf->hotplugdev);
		memset(conf->hotplugdev, 0, FILE_NAME_SIZE);

		/* if called from hotplug but with no block, leave */
		if (0 > readlink(buff, conf->hotplugdev, FILE_NAME_SIZE))
			return 0;

		basename(conf->hotplugdev, buff);
		sprintf(curpath.sg_dev, "/dev/%s", buff);

		get_lun_strings(conf, &curpath);
		if (!get_unique_id(&curpath))
			return 0;
		strcpy(refwwid, curpath.wwid);
		memset(&curpath, 0, sizeof(path));
	}

	sprintf(path, "%s/block", conf->sysfs_path);
	sdir = sysfs_open_directory(path);
	sysfs_read_directory(sdir);

	dlist_for_each_data(sdir->subdirs, devp, struct sysfs_directory) {
		if (blacklist(devp->name))
			continue;

		sysfs_read_directory(devp);

		if(devp->links == NULL)
			continue;

		dlist_for_each_data(devp->links, linkp, struct sysfs_link) {
			if (!strncmp(linkp->name, "device", 6))
				break;
		}

		if (linkp == NULL) {
			continue;
		}

		basename(devp->path, buff);
		sprintf(curpath.sg_dev, "/dev/%s", buff);

		get_lun_strings(conf, &curpath);
		if(!get_unique_id(&curpath)) {
			memset(&curpath, 0, sizeof(path));
			continue;
		}

		if (memcmp(empty_buff, refwwid, WWID_SIZE) != 0 && 
		    strncmp(curpath.wwid, refwwid, WWID_SIZE) != 0) {
			memset(&curpath, 0, sizeof(path));
			continue;
		}

		strcpy(all_paths[k].sg_dev, curpath.sg_dev);
		strcpy(all_paths[k].dev, curpath.sg_dev);
		strcpy(all_paths[k].wwid, curpath.wwid);
		strcpy(all_paths[k].vendor_id, curpath.vendor_id);
		strcpy(all_paths[k].product_id, curpath.product_id);
		all_paths[k].iopolicy = curpath.iopolicy;

		/* done with curpath, zero for reuse */
		memset(&curpath, 0, sizeof(path));

		basename(linkp->target, buff);
		sscanf(buff, "%i:%i:%i:%i",
			&all_paths[k].sg_id.host_no,
			&all_paths[k].sg_id.channel,
			&all_paths[k].sg_id.scsi_id,
			&all_paths[k].sg_id.lun);
		k++;
	}
	sysfs_close_directory(sdir);
	return 0;
}

static int
get_all_paths_nosysfs(struct env * conf, struct path * all_paths,
		      struct scsi_dev * all_scsi_ids)
{
	int k, i, fd;
	char buff[FILE_NAME_SIZE];
	char file_name[FILE_NAME_SIZE];

	for (k = 0; k < conf->max_devs; k++) {
		strcpy(file_name, "/dev/sg");
		sprintf(buff, "%d", k);
		strncat(file_name, buff, FILE_NAME_SIZE);
		strcpy(all_paths[k].sg_dev, file_name);

		get_lun_strings(conf, &all_paths[k]);
		if (!get_unique_id(&all_paths[k]))
			continue;

		if ((fd = open(all_paths[k].sg_dev, O_RDONLY)) < 0)
			return 0;

		if (0 > ioctl(fd, SG_GET_SCSI_ID, &(all_paths[k].sg_id)))
			printf("device %s failed on sg ioctl, skip\n",
			       file_name);

		close(fd);

		for (i = 0; i < conf->max_devs; i++) {
			if ((all_paths[k].sg_id.host_no ==
			     all_scsi_ids[i].host_no)
			    && (all_paths[k].sg_id.scsi_id ==
				(all_scsi_ids[i].scsi_id.dev_id & 0xff))
			    && (all_paths[k].sg_id.lun ==
				((all_scsi_ids[i].scsi_id.dev_id >> 8) & 0xff))
			    && (all_paths[k].sg_id.channel ==
				((all_scsi_ids[i].scsi_id.
				  dev_id >> 16) & 0xff))) {
				strcpy(all_paths[k].dev, all_scsi_ids[i].dev);
				break;
			}
		}
	}
	return 0;
}

static int
get_all_scsi_ids(struct env * conf, struct scsi_dev * all_scsi_ids)
{
	int k, big, little, res, host_no, fd;
	char buff[64];
	char fname[FILE_NAME_SIZE];
	struct scsi_idlun my_scsi_id;

	for (k = 0; k < conf->max_devs; k++) {
		strcpy(fname, "/dev/sd");
		if (k < 26) {
			buff[0] = 'a' + (char) k;
			buff[1] = '\0';
			strcat(fname, buff);
		} else if (k <= 255) {
			/* assumes sequence goes x,y,z,aa,ab,ac etc */
			big = k / 26;
			little = k - (26 * big);
			big = big - 1;

			buff[0] = 'a' + (char) big;
			buff[1] = 'a' + (char) little;
			buff[2] = '\0';
			strcat(fname, buff);
		} else
			strcat(fname, "xxxx");

		if ((fd = open(fname, O_RDONLY)) < 0) {
			if (conf->verbose)
				fprintf(stderr, "can't open %s. mknod ?",
					fname); 
			continue;
		}

		res = ioctl(fd, SCSI_IOCTL_GET_IDLUN, &my_scsi_id);
		if (res < 0) {
			close(fd);
			printf("Could not get scsi idlun\n");
			continue;
		}

		res = ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &host_no);
		if (res < 0) {
			close(fd);
			printf("Could not get host_no\n");
			continue;
		}

		close(fd);

		strcpy(all_scsi_ids[k].dev, fname);
		all_scsi_ids[k].scsi_id = my_scsi_id;
		all_scsi_ids[k].host_no = host_no;
	}
	return 0;
}

/* print_path style */
#define ALL	0
#define NOWWID	1

static void
print_path(struct path * all_paths, int k, int style)
{
	if (style != NOWWID)
		printf("%s ", all_paths[k].wwid);
	else
		printf(" \\_");
	printf("(%i %i %i %i) ",
	       all_paths[k].sg_id.host_no,
	       all_paths[k].sg_id.channel,
	       all_paths[k].sg_id.scsi_id, all_paths[k].sg_id.lun);
	if(0 != strcmp(all_paths[k].sg_dev, all_paths[k].dev))
		printf("%s ", all_paths[k].sg_dev);
	printf("%s ", all_paths[k].dev);
	printf("[%.16s]\n", all_paths[k].product_id);
}

static void
print_all_path(struct env * conf, struct path * all_paths)
{
	int k;
	char empty_buff[WWID_SIZE];

	memset(empty_buff, 0, WWID_SIZE);
	for (k = 0; k < conf->max_devs; k++) {
		if (memcmp(empty_buff, all_paths[k].wwid, WWID_SIZE) == 0)
			continue;
		print_path(all_paths, k, ALL);
	}
}

static void
print_all_mp(struct path * all_paths, struct multipath * mp, int nmp)
{
	int k, i;

	for (k = 0; k <= nmp; k++) {
		printf("%s\n", mp[k].wwid);
		for (i = 0; i <= mp[k].npaths; i++)
			print_path(all_paths, PINDEX(k,i), NOWWID);
	}
}

static long
get_disk_size (struct env * conf, char * dev) {
	long size;
	int fd;
	char attr_path[FILE_NAME_SIZE];
	char buff[FILE_NAME_SIZE];
	char basedev[FILE_NAME_SIZE];

	if(conf->with_sysfs) {
		basename(dev, basedev);
		sprintf(attr_path, "%s/block/%s/size",
			conf->sysfs_path, basedev);
		if (0 > sysfs_read_attribute_value(attr_path, buff,
					 FILE_NAME_SIZE * sizeof(char)))
			return -1;
		size = atoi(buff);
		return size;
	} else {
		if ((fd = open(dev, O_RDONLY)) < 0)
			return -1;
		if(!ioctl(fd, BLKGETSIZE, &size))
			return size;
	}
	return -1;
}

static int
coalesce_paths(struct env * conf, struct multipath * mp,
	       struct path * all_paths)
{
	int k, i, nmp, np, already_done;
	char empty_buff[WWID_SIZE];

	nmp = -1;
	already_done = 0;
	memset(empty_buff, 0, WWID_SIZE);

	for (k = 0; k < conf->max_devs - 1; k++) {
		/* skip this path for some reason */

		/* 1. if path has no unique id */
		if (memcmp(empty_buff, all_paths[k].wwid, WWID_SIZE) == 0)
			continue;

		/* 2. mp with this uid already instanciated */
		for (i = 0; i <= nmp; i++) {
			if (0 == strcmp(mp[i].wwid, all_paths[k].wwid))
				already_done = 1;
		}
		if (already_done) {
			already_done = 0;
			continue;
		}

		/* at this point, we know we really got a new mp */
		np = 0;
		nmp++;
		strcpy(mp[nmp].wwid, all_paths[k].wwid);
		PINDEX(nmp,np) = k;

		if (mp[nmp].size == 0)
			mp[nmp].size = get_disk_size(conf, all_paths[k].dev);

		for (i = k + 1; i < conf->max_devs; i++) {
			if (0 == strcmp(all_paths[k].wwid, all_paths[i].wwid)) {
				np++;
				PINDEX(nmp,np) = i;
				mp[nmp].npaths = np;
			}
		}
	}
	return nmp;
}

static int
dm_simplecmd(int task, const char *name) {
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(task)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

	r = dm_task_run(dmt);

	out:
		dm_task_destroy(dmt);
		return r;
}

static int
dm_addmap(int task, const char *name, const char *params, long size) {
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(task)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto addout;

	if (!dm_task_add_target(dmt, 0, size, DM_TARGET, params))
		goto addout;

	if (!dm_task_run(dmt))
		goto addout;

	addout:
	dm_task_destroy(dmt);
	return 1;
}

static int
setup_map(struct env * conf, struct path * all_paths,
	struct multipath * mp, int index, int op)
{
	char params[255];
	char * params_p;
	int i, np;

	/* defaults for multipath target */
	int dm_pg_prio              = 1;
	char * dm_ps_name           = "round-robin";
	int dm_ps_nr_args           = 0;

	params_p = &params[0];

	np = 0;
	for (i=0; i<=mp[index].npaths; i++) {
		if (0 == all_paths[PINDEX(index,i)].sg_id.scsi_type)
			np++;
	}

	if (np < 1)
		return 0;

	params_p += sprintf(params_p, "%i", conf->dm_path_test_int);

	if (all_paths[PINDEX(index,0)].iopolicy == MULTIBUS &&
	    !conf->forcedfailover ) {
		params_p += sprintf(params_p, " 1 %i %s %i %i",
				    dm_pg_prio, dm_ps_name, np, dm_ps_nr_args);
		
		for (i=0; i<=mp[index].npaths; i++) {
			if (0 != all_paths[PINDEX(index,i)].sg_id.scsi_type)
				continue;
			params_p += sprintf(params_p, " %s",
					    all_paths[PINDEX(index,i)].dev);
		}
	}

	if (all_paths[PINDEX(index,0)].iopolicy == FAILOVER ||
	    conf->forcedfailover) {
		params_p += sprintf(params_p, " %i", mp[index].npaths + 1);
		for (i=0; i<=mp[index].npaths; i++) {
			if (0 != all_paths[PINDEX(index,i)].sg_id.scsi_type)
				continue;
			params_p += sprintf(params_p, " %i %s ",
					    dm_pg_prio, dm_ps_name);
			params_p += sprintf(params_p, "1 %i",
					    dm_ps_nr_args);
			params_p += sprintf(params_p, " %s",
					    all_paths[PINDEX(index,i)].dev);
		}
	}

	if (mp[index].size < 0)
		return 0;

	if (!conf->quiet) {
		if (op == DM_DEVICE_RELOAD)
			printf("U:");
		if (op == DM_DEVICE_CREATE)
			printf("N:");
		printf("%s:0 %li %s %s\n",
			mp[index].wwid, mp[index].size, DM_TARGET, params);
	}

	if (op == DM_DEVICE_RELOAD)
		dm_simplecmd(DM_DEVICE_SUSPEND, mp[index].wwid);

	dm_addmap(op, mp[index].wwid, params, mp[index].size);

	if (op == DM_DEVICE_RELOAD)
		dm_simplecmd(DM_DEVICE_RESUME, mp[index].wwid);

	return 1;
}

static int
map_present(char * str)
{
        int r = 0;
	struct dm_task *dmt;
        struct dm_names *names;
        unsigned next = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_LIST)))
		return 0;

	if (!dm_task_run(dmt))
		goto out;

	if (!(names = dm_task_get_names(dmt)))
		goto out;

	if (!names->dev) {
		goto out;
	}

	do {
		if (0 == strcmp(names->name, str))
			r = 1;
		next = names->next;
		names = (void *) names + next;
	} while (next);

	out:
	dm_task_destroy(dmt);
	return r;
}

static void
usage(char * progname)
{
	fprintf(stderr, VERSION_STRING);
	fprintf(stderr, "Usage: %s [-v|-q] [-d] [-i int] [-m max_devs]\n",
		progname);
	fprintf(stderr, "\t-d\t\tdry run, do not create or update devmaps\n");
	fprintf(stderr, "\t-f\t\tforce maps to failover mode (1 path/pg)\n");
	fprintf(stderr, "\t-i\t\tmultipath target param : polling interval\n");
	fprintf(stderr, "\t-m max_devs\tscan {max_devs} devices at most\n");
	fprintf(stderr, "\t-q\t\tquiet, no output at all\n");
	fprintf(stderr, "\t-v\t\tverbose, print all paths and multipaths\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct multipath * mp;
	struct path * all_paths;
	struct scsi_dev * all_scsi_ids;
	struct env conf;
	int i, k, nmp;

	/* Default behaviour */
	conf.max_devs = MAX_DEVS;
	conf.dry_run = 0;	/* 1 == Do not Create/Update devmaps */
	conf.verbose = 0;	/* 1 == Print all_paths and mp */
	conf.quiet = 0;		/* 1 == Do not even print devmaps */
	conf.with_sysfs = 0;	/* Default to compat / suboptimal behaviour */
	conf.dm_path_test_int = 10;

	/* kindly provided by libsysfs */
	if (0 == sysfs_get_mnt_path(conf.sysfs_path, FILE_NAME_SIZE))
		conf.with_sysfs = 1;

	for (i = 1; i < argc; ++i) {
		if (0 == strcmp("-v", argv[i])) {
			if (conf.quiet == 1)
				usage(argv[0]);
			conf.verbose = 1;
		} else if (0 == strcmp("-m", argv[i])) {
			conf.max_devs = atoi(argv[++i]);
			if (conf.max_devs < 2)
				usage(argv[0]);
		} else if (0 == strcmp("-q", argv[i])) {
			if (conf.verbose == 1)
				usage(argv[0]);
			conf.quiet = 1;
		} else if (0 == strcmp("-d", argv[i]))
			conf.dry_run = 1;
		else if (0 == strcmp("-f", argv[i]))
			conf.forcedfailover = 1;
		else if (0 == strcmp("-i", argv[i]))
			conf.dm_path_test_int = atoi(argv[++i]);
		else if (0 == strcmp("scsi", argv[i]))
			strcpy(conf.hotplugdev, argv[++i]);
		else if (*argv[i] == '-') {
			fprintf(stderr, "Unknown switch: %s\n", argv[i]);
			usage(argv[0]);
		} else if (*argv[i] != '-') {
			fprintf(stderr, "Unknown argument\n");
			usage(argv[0]);
		}

	}

	/* dynamic allocations */
	mp = malloc(conf.max_devs * sizeof(struct multipath));
	all_paths = malloc(conf.max_devs * sizeof(struct path));
	all_scsi_ids = malloc(conf.max_devs * sizeof(struct scsi_dev));
	if (mp == NULL || all_paths == NULL || all_scsi_ids == NULL)
		exit(1);

	if (!conf.with_sysfs) {
		get_all_scsi_ids(&conf, all_scsi_ids);
		get_all_paths_nosysfs(&conf, all_paths, all_scsi_ids);
	} else {
		get_all_paths_sysfs(&conf, all_paths);
	}
	nmp = coalesce_paths(&conf, mp, all_paths);

	if (conf.verbose) {
		print_all_path(&conf, all_paths);
		fprintf(stdout, "\n");
		print_all_mp(all_paths, mp, nmp);
		fprintf(stdout, "\n");
	}

	if (conf.dry_run)
		exit(0);

	for (k=0; k<=nmp; k++) {
		if (map_present(mp[k].wwid)) {
			setup_map(&conf, all_paths, mp, k, DM_DEVICE_RELOAD);
		} else {
			setup_map(&conf, all_paths, mp, k, DM_DEVICE_CREATE);
		}
	}

	/* free allocs */
	free(mp);
	free(all_paths);
	free(all_scsi_ids);

	exit(0);
}
