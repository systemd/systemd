/*
 * scsi_id.c
 *
 * Main section of the scsi_id program
 *
 * Copyright (C) IBM Corp. 2003
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sysfs/libsysfs.h>

#include "scsi_id_version.h"
#include "scsi_id.h"

#ifndef SCSI_ID_VERSION
#warning No version
#define SCSI_ID_VERSION	"unknown"
#endif

/*
 * temporary names for mknod.
 */
#define TMP_DIR	"/tmp"
#define TMP_PREFIX "scsi"

static const char short_options[] = "bc:d:ef:gip:s:vV";
/*
 * Just duplicate per dev options.
 */
static const char dev_short_options[] = "bc:gp:";

char sysfs_mnt_path[SYSFS_PATH_MAX];

static int all_good;
static char *default_callout;
static int dev_specified;
static int sys_specified;
static char config_file[MAX_NAME_LEN] = SCSI_ID_CONFIG_FILE;
static int display_bus_id;
static int default_page_code;
static int use_stderr;
static int debug;
static int hotplug_mode;

void log_message (int level, const char *format, ...)
{
	va_list	args;

	if (!debug && level == LOG_DEBUG)
		return;

	va_start (args, format);
	if (!hotplug_mode || use_stderr) {
		vfprintf(stderr, format, args);
	} else {
		static int logging_init = 0;
		static unsigned char logname[32];
		if (!logging_init) {
			/*
			 * klibc does not have LOG_PID.
			 */
			snprintf(logname, 32, "scsi_id[%d]", getpid());
			openlog (logname, 0, LOG_DAEMON);
			logging_init = 1;
		}

		vsyslog(level, format, args);
	}
	va_end (args);
	return;
}

int sysfs_get_attr(const char *devpath, const char *attr, char *value,
		   size_t bufsize)
{
	char attr_path[SYSFS_PATH_MAX];

	strncpy(attr_path, devpath, SYSFS_PATH_MAX);
	strncat(attr_path, "/", SYSFS_PATH_MAX);
	strncat(attr_path, attr,  SYSFS_PATH_MAX);
	dprintf("%s\n", attr_path);
	return sysfs_read_attribute_value(attr_path, value, SYSFS_NAME_LEN);
}

static int sysfs_get_actual_dev(const char *sysfs_path, char *dev, int len)
{
	dprintf("%s\n", sysfs_path);
	strncpy(dev, sysfs_path, len);
	strncat(dev, "/device", len);
	if (sysfs_get_link(dev, dev, len)) {
		if (!hotplug_mode)
			log_message(LOG_WARNING, "%s: %s\n", dev,
				    strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * sysfs_is_bus: Given the sysfs_path to a device, return 1 if sysfs_path
 * is on bus, 0 if not on bus, and < 0 on error
 */
static int sysfs_is_bus(const char *sysfs_path, const char *bus)
{
	char bus_dev_name[SYSFS_PATH_MAX];
	char bus_id[SYSFS_NAME_LEN];
	struct stat stat_buf;
	ino_t dev_inode;

	dprintf("%s\n", sysfs_path);

	if (sysfs_get_name_from_path(sysfs_path, bus_id, SYSFS_NAME_LEN))
		return -1;

	snprintf(bus_dev_name, MAX_NAME_LEN, "%s/%s/%s/%s/%s", sysfs_mnt_path,
		 SYSFS_BUS_NAME, bus, SYSFS_DEVICES_NAME, bus_id);

	if (stat(sysfs_path, &stat_buf))
		return -1;
	dev_inode = stat_buf.st_ino;

	if (stat(bus_dev_name, &stat_buf)) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}
	if (dev_inode == stat_buf.st_ino)
		return 1;
	else
		return 0;
}

static int get_major_minor(const char *devpath, int *major, int *minor)
{
	char dev_value[MAX_ATTR_LEN];

	if (sysfs_get_attr(devpath, "dev", dev_value, MAX_ATTR_LEN)) {
		/*
		 * XXX This happens a lot, since sg has no dev attr.
		 * And now sysfsutils does not set a meaningful errno
		 * value. Someday change this back to a LOG_WARNING.
		 * And if sysfsutils changes, check for ENOENT and handle
		 * it separately.
		 */
		log_message(LOG_DEBUG, "%s could not get dev attribute: %s\n",
			devpath, strerror(errno));
		return -1;
	}

	dprintf("dev value %s", dev_value); /* dev_value has a trailing \n */
	if (sscanf(dev_value, "%u:%u", major, minor) != 2) {
		log_message(LOG_WARNING, "%s: invalid dev major/minor\n",
			    devpath);
		return -1;
	}

	return 0;
}

static int create_tmp_dev(const char *devpath, char *tmpdev, int dev_type)
{
	int major, minor;

	dprintf("(%s)\n", devpath);

	if (get_major_minor(devpath, &major, &minor))
		return -1;
	snprintf(tmpdev, MAX_NAME_LEN, "%s/%s-maj%d-min%d-%u",
		 TMP_DIR, TMP_PREFIX, major, minor, getpid());

	dprintf("tmpdev '%s'\n", tmpdev);

	if (mknod(tmpdev, 0600 | dev_type, makedev(major, minor))) {
		log_message(LOG_WARNING, "mknod failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int has_sysfs_prefix(const char *path, const char *prefix)
{
	char match[MAX_NAME_LEN];

	strncpy(match, sysfs_mnt_path, MAX_NAME_LEN);
	strncat(match, prefix, MAX_NAME_LEN);
	if (strncmp(path, match, strlen(match)) == 0)
		return 1;
	else
		return 0;
}

/*
 * get_value:
 *
 * buf points to an '=' followed by a quoted string ("foo") or a string ending
 * with a space or ','.
 *
 * Return a pointer to the NUL terminated string, returns NULL if no
 * matches.
 */
static char *get_value(char **buffer)
{
	static char *quote_string = "\"\n";
	static char *comma_string = ",\n";
	char *val;
	char *end;

	if (**buffer == '"') {
		/*
		 * skip leading quote, terminate when quote seen
		 */
		(*buffer)++;
		end = quote_string;
	} else {
		end = comma_string;
	}
	val = strsep(buffer, end);
	if (val && end == quote_string)
		/*
		 * skip trailing quote
		 */
		(*buffer)++;

	while (isspace(**buffer))
		(*buffer)++;

	return val;
}

static int argc_count(char *opts)
{
	int i = 0;
	while (*opts != '\0')
		if (*opts++ == ' ')
			i++;
	return i;
}

/*
 * get_file_options:
 *
 * If vendor == NULL, find a line in the config file with only "OPTIONS=";
 * if vendor and model are set find the first OPTIONS line in the config
 * file that matches. Set argc and argv to match the OPTIONS string.
 *
 * vendor and model can end in '\n'.
 */
static int get_file_options(char *vendor, char *model, int *argc,
			    char ***newargv)
{
	char *buffer;
	FILE *fd;
	char *buf;
	char *str1;
	char *vendor_in, *model_in, *options_in; /* read in from file */
	int lineno;
	int c;
	int retval = 0;

	dprintf("vendor='%s'; model='%s'\n", vendor, model);
	fd = fopen(config_file, "r");
	if (fd == NULL) {
		dprintf("can't open %s\n", config_file);
		if (errno == ENOENT) {
			return 1;
		} else {
			log_message(LOG_WARNING, "can't open %s: %s\n",
				config_file, strerror(errno));
			return -1;
		}
	}

	/*
	 * Allocate a buffer rather than put it on the stack so we can
	 * keep it around to parse any options (any allocated newargv
	 * points into this buffer for its strings).
	 */
	buffer = malloc(MAX_BUFFER_LEN);
	if (!buffer) {
		log_message(LOG_WARNING, "Can't allocate memory.\n");
		return -1;
	}

	*newargv = NULL;
	lineno = 0;
	while (1) {
		vendor_in = model_in = options_in = NULL;

		buf = fgets(buffer, MAX_BUFFER_LEN, fd);
		if (buf == NULL)
			break;
		lineno++;
		if (buf[strlen(buffer) - 1] != '\n') {
			log_message(LOG_WARNING,
				    "Config file line %d too long.\n", lineno);
			break;
		}

		while (isspace(*buf))
			buf++;

		if (*buf == '\0')
			/*
			 * blank or all whitespace line
			 */
			continue;

		if (*buf == '#')
			/*
			 * comment line
			 */
			continue;

#ifdef LOTS
		dprintf("lineno %d: '%s'\n", lineno, buf);
#endif
		str1 = strsep(&buf, "=");
		if (str1 && strcasecmp(str1, "VENDOR") == 0) {
			str1 = get_value(&buf);
			if (!str1) {
				retval = -1;
				break;
			}
			vendor_in = str1;

			str1 = strsep(&buf, "=");
			if (str1 && strcasecmp(str1, "MODEL") == 0) {
				str1 = get_value(&buf);
				if (!str1) {
					retval = -1;
					break;
				}
				model_in = str1;
				str1 = strsep(&buf, "=");
			}
		}

		if (str1 && strcasecmp(str1, "OPTIONS") == 0) {
			str1 = get_value(&buf);
			if (!str1) {
				retval = -1;
				break;
			}
			options_in = str1;
		}
		dprintf("config file line %d:"
			" vendor '%s'; model '%s'; options '%s'\n",
			lineno, vendor_in, model_in, options_in);
		/*
		 * Only allow: [vendor=foo[,model=bar]]options=stuff
		 */
		if (!options_in || (!vendor_in && model_in)) {
			log_message(LOG_WARNING,
				    "Error parsing config file line %d '%s'\n",
				    lineno, buffer);
			retval = -1;
			break;
		}
		if (vendor == NULL) {
			if (vendor_in == NULL) {
				dprintf("matched global option\n");
				break;
			}
		} else if ((vendor_in && strncmp(vendor, vendor_in,
						 strlen(vendor_in)) == 0) &&
			   (!model_in || (strncmp(model, model_in,
						  strlen(model_in)) == 0))) {
				/*
				 * Matched vendor and optionally model.
				 *
				 * Note: a short vendor_in or model_in can
				 * give a partial match (that is FOO
				 * matches FOOBAR).
				 */
				dprintf("matched vendor/model\n");
				break;
		} else {
			dprintf("no match\n");
		}
	}

	if (retval == 0) {
		if (vendor_in != NULL || model_in != NULL ||
		    options_in != NULL) {
			/*
			 * Something matched. Allocate newargv, and store
			 * values found in options_in.
			 */
			strcpy(buffer, options_in);
			c = argc_count(buffer) + 2;
			*newargv = calloc(c, sizeof(**newargv));
			if (!*newargv) {
				log_message(LOG_WARNING,
					    "Can't allocate memory.\n");
				retval = -1;
			} else {
				*argc = c;
				c = 0;
				/*
				 * argv[0] at 0 is skipped by getopt, but
				 * store the buffer address there for
				 * alter freeing.
				 */
				(*newargv)[c] = buffer;
				for (c = 1; c < *argc; c++)
					(*newargv)[c] = strsep(&buffer, " ");
			}
		} else {
			/*
			 * No matches.
			 */
			retval = 1;
		}
	}
	if (retval != 0)
		free(buffer);
	fclose(fd);
	return retval;
}

static int set_options(int argc, char **argv, const char *short_opts,
		       char *target, char *maj_min_dev)
{
	int option;

	/*
	 * optind is a global extern used by getopt. Since we can call
	 * set_options twice (once for command line, and once for config
	 * file) we have to reset this back to 1. [Note glibc handles
	 * setting this to 0, but klibc does not.]
	 */
	optind = 1;
	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		if (optarg)
			dprintf("option '%c' arg '%s'\n", option, optarg);
		else
			dprintf("option '%c'\n", option);

		switch (option) {
		case 'b':
			all_good = 0;
			break;

		case 'c':
			default_callout = optarg;
			break;

		case 'd':
			dev_specified = 1;
			strncpy(maj_min_dev, optarg, MAX_NAME_LEN);
			break;

		case 'e':
			use_stderr = 1;
			break;

		case 'f':
			strncpy(config_file, optarg, MAX_NAME_LEN);
			break;

		case 'g':
			all_good = 1;
			break;

		case 'i':
			display_bus_id = 1;
			break;

		case 'p':
			if (strcmp(optarg, "0x80") == 0) {
				default_page_code = 0x80;
			} else if (strcmp(optarg, "0x83") == 0) {
				default_page_code = 0x83;
			} else {
				log_message(LOG_WARNING,
					    "Unknown page code '%s'\n", optarg);
				return -1;
			}
			break;

		case 's':
			sys_specified = 1;
			strncpy(target, sysfs_mnt_path, MAX_NAME_LEN);
			strncat(target, optarg, MAX_NAME_LEN);
			break;

		case 'v':
			debug++;
			break;

		case 'V':
			log_message(LOG_WARNING, "scsi_id version: %s\n",
				    SCSI_ID_VERSION);
			exit(0);
			break;

		default:
			log_message(LOG_WARNING,
				    "Unknown or bad option '%c' (0x%x)\n",
				    option, option);
			return -1;
		}
	}
	return 0;
}

static int per_dev_options(struct sysfs_class_device *scsi_dev, int *good_bad,
			   int *page_code, char *callout)
{
	int retval;
	int newargc;
	char **newargv = NULL;
	char vendor[MAX_ATTR_LEN];
	char model[MAX_ATTR_LEN];
	int option;

	*good_bad = all_good;
	*page_code = default_page_code;
	if (default_callout && (callout != default_callout))
		strncpy(callout, default_callout, MAX_NAME_LEN);
	else
		callout[0] = '\0';

	if (sysfs_get_attr(scsi_dev->path, "vendor", vendor, MAX_ATTR_LEN)) {
		log_message(LOG_WARNING, "%s: cannot get vendor attribute\n",
			    scsi_dev->name);
		return -1;
	}

	if (sysfs_get_attr(scsi_dev->path, "model", model, MAX_ATTR_LEN)) {
		log_message(LOG_WARNING, "%s: cannot get model attribute\n",
			    scsi_dev->name);
		return -1;
	}

	retval = get_file_options(vendor, model, &newargc, &newargv);

	optind = 1; /* reset this global extern */
	while (retval == 0) {
		option = getopt(newargc, newargv, dev_short_options);
		if (option == -1)
			break;

		if (optarg)
			dprintf("option '%c' arg '%s'\n", option, optarg);
		else
			dprintf("option '%c'\n", option);

		switch (option) {
		case 'b':
			*good_bad = 0;
			break;

		case 'c':
			strncpy(callout, default_callout, MAX_NAME_LEN);
			break;

		case 'g':
			*good_bad = 1;
			break;

		case 'p':
			if (strcmp(optarg, "0x80") == 0) {
				*page_code = 0x80;
			} else if (strcmp(optarg, "0x83") == 0) {
				*page_code = 0x83;
			} else {
				log_message(LOG_WARNING,
					    "Unknown page code '%s'\n", optarg);
				retval = -1;
			}
			break;

		default:
			log_message(LOG_WARNING,
				    "Unknown or bad option '%c' (0x%x)\n",
				    option, option);
			retval = -1;
			break;
		}
	}

	if (newargv) {
		free(newargv[0]);
		free(newargv);
	}
	return retval;
}

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 * returns a value passed to exit() - 0 if printed an id, else 1. This
 * could be expanded, for example, if we want to report a failure like no
 * memory etc. return 2, and return 1 for expected cases (like broken
 * device found) that do not print an id.
 */
static int scsi_id(const char *target_path, char *maj_min_dev)
{
	int retval;
	int dev_type = 0;
	char full_dev_path[MAX_NAME_LEN];
	char serial[MAX_SERIAL_LEN];
	struct sysfs_class_device *scsi_dev; /* of scsi_device full_dev_path */
	int good_dev;
	int page_code;
	char callout[MAX_NAME_LEN];

	dprintf("target_path %s\n", target_path);

	/*
	 * Ugly: depend on the sysfs path to tell us whether this is a
	 * block or char device. This should probably be encoded in the
	 * "dev" along with the major/minor.
	 */
	if (has_sysfs_prefix(target_path, "/block")) {
		dev_type = S_IFBLK;
	} else if (has_sysfs_prefix(target_path, "/class")) {
		dev_type = S_IFCHR;
	} else {
		if (!hotplug_mode) {
			log_message(LOG_WARNING,
				    "Non block or class device '%s'\n",
				    target_path);
			return 1;
		} else {
			/*
			 * Expected in some cases.
			 */
			dprintf("Non block or class device\n");
			return 0;
		}
	}

	if (sysfs_get_actual_dev(target_path, full_dev_path, MAX_NAME_LEN))
		return 1;

	dprintf("full_dev_path %s\n", full_dev_path);

	/*
	 * Allow only scsi devices (those that have a matching device
	 * under /bus/scsi/devices).
	 *
	 * Other block devices can support SG IO, but only ide-cd does, so
	 * for now, don't bother with anything else.
	 */
	retval = sysfs_is_bus(full_dev_path, "scsi");
	if (retval == 0) {
		if (hotplug_mode)
			/*
			 * Expected in some cases.
			 */
			dprintf("%s is not a scsi device\n", target_path);
		else
			log_message(LOG_WARNING, "%s is not a scsi device\n",
				    target_path);
		return 1;
	} else if (retval < 0) {
		log_message(LOG_WARNING, "sysfs_is_bus failed: %s\n",
			strerror(errno));
		return 1;
	}

	/*
	 * mknod a temp dev to communicate with the device.
	 */
	if (!dev_specified && create_tmp_dev(target_path, maj_min_dev,
					     dev_type)) {
		dprintf("create_tmp_dev failed\n");
		return 1;
	}

	scsi_dev = sysfs_open_class_device_path(full_dev_path);
	if (!scsi_dev) {
		log_message(LOG_WARNING, "open class %s failed: %s\n",
			    full_dev_path, strerror(errno));
		return 1;
	}

	/*
	 * Get any per device (vendor + model) options from the config
	 * file.
	 */
	retval = per_dev_options(scsi_dev, &good_dev, &page_code, callout);
	dprintf("per dev options: good %d; page code 0x%x; callout '%s'\n",
		good_dev, page_code, callout);

	if (!good_dev) {
		retval = 1;
	} else if (callout[0] != '\0') {
		/*
		 * exec vendor callout, pass it only the "name" to be used
		 * for error messages, and the dev to open.
		 *
		 * This won't work if we need to pass on the original
		 * command line (when not hotplug mode) since the option
		 * parsing and per dev parsing modify the argv's.
		 *
		 * XXX Not implemented yet. And not fully tested ;-)
		 */
		retval = 1;
	} else if (scsi_get_serial(scsi_dev, maj_min_dev, page_code,
				   serial, MAX_SERIAL_LEN)) {
		retval = 1;
	} else {
		retval = 0;
	}
	if (!retval) {
		if (display_bus_id)
			printf("%s ", scsi_dev->name);
		printf("%s", serial);
		if (!hotplug_mode)
			printf("\n");
		dprintf("%s\n", serial);
		retval = 0;
	}
	sysfs_close_class_device(scsi_dev);

	if (!dev_specified)
		unlink(maj_min_dev);

	return retval;
}

int main(int argc, char **argv)
{
	int retval;
	char *devpath;
	char target_path[MAX_NAME_LEN];
	char maj_min_dev[MAX_NAME_LEN];
	int newargc;
	char **newargv;

	if (getenv("DEBUG"))
		debug++;

	if ((argc == 2) && (argv[1][0] != '-')) {
		hotplug_mode = 1;
		dprintf("hotplug assumed\n");
	}

	dprintf("argc is %d\n", argc);
	if (sysfs_get_mnt_path(sysfs_mnt_path, MAX_NAME_LEN)) {
		log_message(LOG_WARNING, "sysfs_get_mnt_path failed: %s\n",
			strerror(errno));
		exit(1);
	}

	if (hotplug_mode) {
		/*
		 * There is a kernel race creating attributes, if called
		 * directly, uncomment the sleep.
		 */
		/* sleep(1); */

		devpath = getenv("DEVPATH");
		if (!devpath) {
			log_message(LOG_WARNING, "DEVPATH is not set\n");
			exit(1);
		}
		sys_specified = 1;

		strncpy(target_path, sysfs_mnt_path, MAX_NAME_LEN);
		strncat(target_path, devpath, MAX_NAME_LEN);
	} else {
		if (set_options(argc, argv, short_options, target_path,
				maj_min_dev) < 0)
			exit(1);
	}

	/*
	 * Override any command line options set via the config file. This
	 * is the only way to set options when in hotplug mode.
	 */
	newargv = NULL;
	retval = get_file_options(NULL, NULL, &newargc, &newargv);
	if (retval < 0) {
		exit(1);
	} else if (newargv && (retval == 0)) {
		if (set_options(newargc, newargv, short_options, target_path,
				maj_min_dev) < 0)
			exit(1);
		free(newargv);
	}

	if (!sys_specified) {
		log_message(LOG_WARNING, "-s must be specified\n");
		exit(1);
	}

	retval = scsi_id(target_path, maj_min_dev);
	exit(retval);
}
