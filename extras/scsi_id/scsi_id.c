/*
 * scsi_id.c
 *
 * Main section of the scsi_id program
 *
 * Copyright (C) IBM Corp. 2003
 * Copyright (C) SUSE Linux Products GmbH, 2006
 *
 * Author:
 *	Patrick Mansfield<patmans@us.ibm.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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

#include "../../udev.h"
#include "scsi_id.h"
#include "scsi_id_version.h"

/* temporary names for mknod  */
#define TMP_DIR		"/dev"
#define TMP_PREFIX	"tmp-scsi"

static const char short_options[] = "abd:f:gip:s:uvVx";
static const char dev_short_options[] = "bgp:";

static int all_good;
static int always_info;
static int dev_specified;
static int sys_specified;
static char config_file[MAX_PATH_LEN] = SCSI_ID_CONFIG_FILE;
static int display_bus_id;
static enum page_code default_page_code;
static int use_stderr;
static int debug;
static int hotplug_mode;
static int reformat_serial;
static int export;
static char vendor_str[64];
static char model_str[64];
static char revision_str[16];
static char type_str[16];

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static void set_str(char *to, const char *from, size_t count)
{
	size_t i, j, len;

	/* strip trailing whitespace */
	len = strnlen(from, count);
	while (len && isspace(from[len-1]))
		len--;

	/* strip leading whitespace */
	i = 0;
	while (isspace(from[i]) && (i < len))
		i++;

	j = 0;
	while (i < len) {
		/* substitute multiple whitespace */
		if (isspace(from[i])) {
			while (isspace(from[i]))
				i++;
			to[j++] = '_';
		}
		/* skip chars */
		if (from[i] == '/') {
			i++;
			continue;
		}
		to[j++] = from[i++];
	}
	to[j] = '\0';
}

static void set_type(char *to, const char *from, size_t len)
{
	int type_num;
	char *eptr;
	char *type = "generic";

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 0:
			type = "disk";
			break;
		case 1:
			type = "tape";
			break;
		case 4:
			type = "optical";
			break;
		case 5:
			type = "cd";
			break;
		case 7:
			type = "optical";
			break;
		case 0xe:
			type = "disk";
			break;
		case 0xf:
			type = "optical";
			break;
		default:
			break;
		}
	}
	strncpy(to, type, len);
	to[len-1] = '\0';
}

static int create_tmp_dev(const char *devpath, char *tmpdev, int dev_type)
{
	unsigned int maj, min;
	const char *attr;

	dbg("%s", devpath);
	attr = sysfs_attr_get_value(devpath, "dev");
	if (attr == NULL) {
		dbg("%s: could not get dev attribute: %s", devpath, strerror(errno));
		return -1;
	}

	dbg("dev value %s", attr);
	if (sscanf(attr, "%u:%u", &maj, &min) != 2) {
		err("%s: invalid dev major/minor", devpath);
		return -1;
	}

	snprintf(tmpdev, MAX_PATH_LEN, "%s/%s-maj%d-min%d-%u",
		 TMP_DIR, TMP_PREFIX, maj, min, getpid());

	dbg("tmpdev '%s'", tmpdev);
	if (mknod(tmpdev, 0600 | dev_type, makedev(maj, min))) {
		err("mknod failed: %s", strerror(errno));
		return -1;
	}
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
static int get_file_options(const char *vendor, const char *model,
			    int *argc, char ***newargv)
{
	char *buffer;
	FILE *fd;
	char *buf;
	char *str1;
	char *vendor_in, *model_in, *options_in; /* read in from file */
	int lineno;
	int c;
	int retval = 0;

	dbg("vendor='%s'; model='%s'\n", vendor, model);
	fd = fopen(config_file, "r");
	if (fd == NULL) {
		dbg("can't open %s\n", config_file);
		if (errno == ENOENT) {
			return 1;
		} else {
			err("can't open %s: %s", config_file, strerror(errno));
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
		err("Can't allocate memory.");
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
			info("Config file line %d too long.\n", lineno);
			break;
		}

		while (isspace(*buf))
			buf++;

		/* blank or all whitespace line */
		if (*buf == '\0')
			continue;

		/* comment line */
		if (*buf == '#')
			continue;

		dbg("lineno %d: '%s'\n", lineno, buf);
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
		dbg("config file line %d:"
			" vendor '%s'; model '%s'; options '%s'\n",
			lineno, vendor_in, model_in, options_in);
		/*
		 * Only allow: [vendor=foo[,model=bar]]options=stuff
		 */
		if (!options_in || (!vendor_in && model_in)) {
			info("Error parsing config file line %d '%s'", lineno, buffer);
			retval = -1;
			break;
		}
		if (vendor == NULL) {
			if (vendor_in == NULL) {
				dbg("matched global option\n");
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
				dbg("matched vendor/model\n");
				break;
		} else {
			dbg("no match\n");
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
				err("Can't allocate memory.");
				retval = -1;
			} else {
				*argc = c;
				c = 0;
				/*
				 * argv[0] at 0 is skipped by getopt, but
				 * store the buffer address there for
				 * later freeing
				 */
				(*newargv)[c] = buffer;
				for (c = 1; c < *argc; c++)
					(*newargv)[c] = strsep(&buffer, " \t");
			}
		} else {
			/* No matches  */
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
	 * file) we have to reset this back to 1.
	 */
	optind = 1;
	while (1) {
		option = getopt(argc, argv, short_opts);
		if (option == -1)
			break;

		if (optarg)
			dbg("option '%c' arg '%s'\n", option, optarg);
		else
			dbg("option '%c'\n", option);

		switch (option) {
		case 'a':
			always_info = 1;
			break;
		case 'b':
			all_good = 0;
			break;

		case 'd':
			dev_specified = 1;
			strncpy(maj_min_dev, optarg, MAX_PATH_LEN);
			maj_min_dev[MAX_PATH_LEN-1] = '\0';
			break;

		case 'e':
			use_stderr = 1;
			break;

		case 'f':
			strncpy(config_file, optarg, MAX_PATH_LEN);
			config_file[MAX_PATH_LEN-1] = '\0';
			break;

		case 'g':
			all_good = 1;
			break;

		case 'i':
			display_bus_id = 1;
			break;

		case 'p':
			if (strcmp(optarg, "0x80") == 0) {
				default_page_code = PAGE_80;
			} else if (strcmp(optarg, "0x83") == 0) {
				default_page_code = PAGE_83;
			} else if (strcmp(optarg, "pre-spc3-83") == 0) {
				default_page_code = PAGE_83_PRE_SPC3; 
			} else {
				info("Unknown page code '%s'", optarg);
				return -1;
			}
			break;

		case 's':
			sys_specified = 1;
			strncpy(target, optarg, MAX_PATH_LEN);
			target[MAX_PATH_LEN-1] = '\0';
			break;

		case 'u':
			reformat_serial = 1;
			break;

		case 'x':
			export = 1;
			break;

		case 'v':
			debug++;
			break;

		case 'V':
			info("scsi_id version: %s\n", SCSI_ID_VERSION);
			exit(0);
			break;

		default:
			info("Unknown or bad option '%c' (0x%x)", option, option);
			return -1;
		}
	}
	return 0;
}

static int per_dev_options(struct sysfs_device *dev_scsi, int *good_bad, int *page_code)
{
	int retval;
	int newargc;
	char **newargv = NULL;
	const char *vendor, *model, *type;
	int option;

	*good_bad = all_good;
	*page_code = default_page_code;

	vendor = sysfs_attr_get_value(dev_scsi->devpath, "vendor");
	if (!vendor) {
		info("%s: cannot get vendor attribute", dev_scsi->devpath);
		return -1;
	}
	set_str(vendor_str, vendor, sizeof(vendor_str)-1);

	model = sysfs_attr_get_value(dev_scsi->devpath, "model");
	if (!model) {
		info("%s: cannot get model attribute\n", dev_scsi->devpath);
		return -1;
	}
	set_str(model_str, model, sizeof(model_str)-1);

	type = sysfs_attr_get_value(dev_scsi->devpath, "type");
	if (!type) {
		info("%s: cannot get type attribute", dev_scsi->devpath);
		return -1;
	}
	set_type(type_str, type, sizeof(type_str));

	type = sysfs_attr_get_value(dev_scsi->devpath, "rev");
	if (!type) {
		info("%s: cannot get type attribute\n", dev_scsi->devpath);
		return -1;
	}
	set_str(revision_str, type, sizeof(revision_str)-1);

	retval = get_file_options(vendor, model, &newargc, &newargv);

	optind = 1; /* reset this global extern */
	while (retval == 0) {
		option = getopt(newargc, newargv, dev_short_options);
		if (option == -1)
			break;

		if (optarg)
			dbg("option '%c' arg '%s'\n", option, optarg);
		else
			dbg("option '%c'\n", option);

		switch (option) {
		case 'b':
			*good_bad = 0;
			break;

		case 'g':
			*good_bad = 1;
			break;

		case 'p':
			if (strcmp(optarg, "0x80") == 0) {
				*page_code = PAGE_80;
			} else if (strcmp(optarg, "0x83") == 0) {
				*page_code = PAGE_83;
			} else if (strcmp(optarg, "pre-spc3-83") == 0) {
				*page_code = PAGE_83_PRE_SPC3; 
			} else {
				info("Unknown page code '%s'", optarg);
				retval = -1;
			}
			break;

		default:
			info("Unknown or bad option '%c' (0x%x)", option, option);
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
 * format_serial: replace to whitespaces by underscores for calling
 * programs that use the serial for device naming (multipath, Suse
 * naming, etc...)
 */
static void format_serial(char *serial)
{
	char *p = serial, *q;

	q = p;
	while (*p != '\0') {
		if (isspace(*p)) {
			if (q > serial && q[-1] != '_') {
				*q = '_';
				q++;
			}
		} else {
			*q = *p;
			q++;
		}
		p++;
	}
	*q = '\0';
}

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 * returns a value passed to exit() - 0 if printed an id, else 1. This
 * could be expanded, for example, if we want to report a failure like no
 * memory etc. return 2, and return 1 for expected cases (like broken
 * device found) that do not print an id.
 */
static int scsi_id(const char *devpath, char *maj_min_dev)
{
	int retval;
	int dev_type = 0;
	struct sysfs_device *dev;
	struct sysfs_device *dev_scsi;
	int good_dev;
	int page_code;
	char serial[MAX_SERIAL_LEN];
	char serial_short[MAX_SERIAL_LEN];

	dbg("devpath %s\n", devpath);

	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		err("unable to access '%s'", devpath);
		return 1;
	}

	if (strcmp(dev->subsystem, "block") == 0)
		dev_type = S_IFBLK;
	else
		dev_type = S_IFCHR;

	/* get scsi parent device */
	dev_scsi = sysfs_device_get_parent_with_subsystem(dev, "scsi");
	if (dev_scsi == NULL) {
		err("unable to access parent device of '%s'", devpath);
		return 1;
	}

	/* mknod a temp dev to communicate with the device */
	if (!dev_specified && create_tmp_dev(dev->devpath, maj_min_dev, dev_type)) {
		dbg("create_tmp_dev failed\n");
		return 1;
	}

	/* get per device (vendor + model) options from the config file */
	retval = per_dev_options(dev_scsi, &good_dev, &page_code);
	dbg("per dev options: good %d; page code 0x%x", good_dev, page_code);

	if (!good_dev) {
		retval = 1;
	} else if (scsi_get_serial(dev_scsi, maj_min_dev, page_code,
				   serial, serial_short, MAX_SERIAL_LEN)) {
		retval = always_info?0:1;
	} else {
		retval = 0;
	}
	if (!retval) {
		if (export) {
			char serial_str[MAX_SERIAL_LEN];

			printf("ID_VENDOR=%s\n", vendor_str);
			printf("ID_MODEL=%s\n", model_str);
			printf("ID_REVISION=%s\n", revision_str);
			set_str(serial_str, serial, sizeof(serial_str));
			printf("ID_SERIAL=%s\n", serial_str);
			set_str(serial_str, serial_short, sizeof(serial_str));
			printf("ID_SERIAL_SHORT=%s\n", serial_str);
			printf("ID_TYPE=%s\n", type_str);
			printf("ID_BUS=scsi\n");
		} else {
			if (reformat_serial)
				format_serial(serial);
			if (display_bus_id)
				printf("%s: ", dev_scsi->kernel);
			printf("%s\n", serial);
		}
		dbg("%s\n", serial);
		retval = 0;
	}

	if (!dev_specified)
		unlink(maj_min_dev);

	return retval;
}

int main(int argc, char **argv)
{
	int retval = 0;
	char devpath[MAX_PATH_LEN];
	char maj_min_dev[MAX_PATH_LEN];
	int newargc;
	const char *env;
	char **newargv;

	logging_init("scsi_id");
	sysfs_init();
	dbg("argc is %d\n", argc);

	/* sysfs path can be overridden for testing */
	env = getenv("SYSFS_PATH");
	if (env) {
		strncpy(sysfs_path, env, sizeof(sysfs_path));
		sysfs_path[sizeof(sysfs_path)-1] = '\0';
	} else
		strcpy(sysfs_path, "/sys");

	env = getenv("DEVPATH");
	if (env) {
		hotplug_mode = 1;
		sys_specified = 1;
		strncpy(devpath, env, MAX_PATH_LEN);
		devpath[sizeof(devpath)-1] = '\0';
	}

	/*
	 * Get config file options.
	 */
	newargv = NULL;
	retval = get_file_options(NULL, NULL, &newargc, &newargv);
	if (retval < 0) {
		retval = 1;
		goto exit;
	}
	if (newargv && (retval == 0)) {
		if (set_options(newargc, newargv, short_options, devpath,
				maj_min_dev) < 0) {
			retval = 2;
			goto exit;
		}
		free(newargv);
	}

	/*
	 * Get command line options (overriding any config file or DEVPATH
	 * settings).
	 */
	if (set_options(argc, argv, short_options, devpath, maj_min_dev) < 0)
		exit(1);

	if (!sys_specified) {
		info("-s must be specified\n");
		retval = 1;
		goto exit;
	}

	retval = scsi_id(devpath, maj_min_dev);

exit:
	sysfs_cleanup();
	logging_close();
	return retval;
}
