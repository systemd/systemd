/*
 * Copyright (C) IBM Corp. 2003
 * Copyright (C) SUSE Linux Products GmbH, 2006
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <getopt.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"
#include "scsi_id.h"

static const struct option options[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "config", required_argument, NULL, 'f' },
	{ "page", required_argument, NULL, 'p' },
	{ "blacklisted", no_argument, NULL, 'b' },
	{ "whitelisted", no_argument, NULL, 'g' },
	{ "replace-whitespace", no_argument, NULL, 'u' },
	{ "sg-version", required_argument, NULL, 's' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "version", no_argument, NULL, 'V' },
	{ "export", no_argument, NULL, 'x' },
	{ "help", no_argument, NULL, 'h' },
	{}
};

static const char short_options[] = "d:f:ghip:uvVx";
static const char dev_short_options[] = "bgp:";

static int all_good;
static int dev_specified;
static char config_file[MAX_PATH_LEN] = SYSCONFDIR "/scsi_id.config";
static enum page_code default_page_code;
static int sg_version = 4;
static int use_stderr;
static int debug;
static int reformat_serial;
static int export;
static char vendor_str[64];
static char model_str[64];
static char vendor_enc_str[256];
static char model_enc_str[256];
static char revision_str[16];
static char type_str[16];

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	vsyslog(priority, format, args);
}

static void set_type(const char *from, char *to, size_t len)
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
	util_strscpy(to, len, type);
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
static int get_file_options(struct udev *udev,
			    const char *vendor, const char *model,
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

	dbg(udev, "vendor='%s'; model='%s'\n", vendor, model);
	fd = fopen(config_file, "r");
	if (fd == NULL) {
		dbg(udev, "can't open %s\n", config_file);
		if (errno == ENOENT) {
			return 1;
		} else {
			err(udev, "can't open %s: %s\n", config_file, strerror(errno));
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
		err(udev, "can't allocate memory\n");
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
			err(udev, "Config file line %d too long\n", lineno);
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

		dbg(udev, "lineno %d: '%s'\n", lineno, buf);
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
		dbg(udev, "config file line %d:\n"
			" vendor '%s'; model '%s'; options '%s'\n",
			lineno, vendor_in, model_in, options_in);
		/*
		 * Only allow: [vendor=foo[,model=bar]]options=stuff
		 */
		if (!options_in || (!vendor_in && model_in)) {
			err(udev, "Error parsing config file line %d '%s'\n", lineno, buffer);
			retval = -1;
			break;
		}
		if (vendor == NULL) {
			if (vendor_in == NULL) {
				dbg(udev, "matched global option\n");
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
				dbg(udev, "matched vendor/model\n");
				break;
		} else {
			dbg(udev, "no match\n");
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
				err(udev, "can't allocate memory\n");
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

static int set_options(struct udev *udev,
		       int argc, char **argv, const char *short_opts,
		       char *maj_min_dev)
{
	int option;

	/*
	 * optind is a global extern used by getopt. Since we can call
	 * set_options twice (once for command line, and once for config
	 * file) we have to reset this back to 1.
	 */
	optind = 1;
	while (1) {
		option = getopt_long(argc, argv, short_opts, options, NULL);
		if (option == -1)
			break;

		if (optarg)
			dbg(udev, "option '%c' arg '%s'\n", option, optarg);
		else
			dbg(udev, "option '%c'\n", option);

		switch (option) {
		case 'b':
			all_good = 0;
			break;

		case 'd':
			dev_specified = 1;
			util_strscpy(maj_min_dev, MAX_PATH_LEN, optarg);
			break;

		case 'e':
			use_stderr = 1;
			break;

		case 'f':
			util_strscpy(config_file, MAX_PATH_LEN, optarg);
			break;

		case 'g':
			all_good = 1;
			break;

		case 'h':
			printf("Usage: scsi_id OPTIONS <device>\n"
			       "  --device=                     device node for SG_IO commands\n"
			       "  --config=                     location of config file\n"
			       "  --page=0x80|0x83|pre-spc3-83  SCSI page (0x80, 0x83, pre-spc3-83)\n"
			       "  --sg-version=3|4              use SGv3 or SGv4\n"
			       "  --blacklisted                 threat device as blacklisted\n"
			       "  --whitelisted                 threat device as whitelisted\n"
			       "  --replace-whitespace          replace all whitespaces by underscores\n"
			       "  --verbose                     verbose logging\n"
			       "  --version                     print version\n"
			       "  --export                      print values as environment keys\n"
			       "  --help                        print this help text\n\n");
			exit(0);

		case 'p':
			if (strcmp(optarg, "0x80") == 0) {
				default_page_code = PAGE_80;
			} else if (strcmp(optarg, "0x83") == 0) {
				default_page_code = PAGE_83;
			} else if (strcmp(optarg, "pre-spc3-83") == 0) {
				default_page_code = PAGE_83_PRE_SPC3; 
			} else {
				err(udev, "Unknown page code '%s'\n", optarg);
				return -1;
			}
			break;

		case 's':
			sg_version = atoi(optarg);
			if (sg_version < 3 || sg_version > 4) {
				err(udev, "Unknown SG version '%s'\n", optarg);
				return -1;
			}
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
			printf("%s\n", VERSION);
			exit(0);
			break;

		default:
			exit(1);
		}
	}
	if (optind < argc && !dev_specified) {
		dev_specified = 1;
		util_strscpy(maj_min_dev, MAX_PATH_LEN, argv[optind]);
	}
	return 0;
}

static int per_dev_options(struct udev *udev,
			   struct scsi_id_device *dev_scsi, int *good_bad, int *page_code)
{
	int retval;
	int newargc;
	char **newargv = NULL;
	int option;

	*good_bad = all_good;
	*page_code = default_page_code;

	retval = get_file_options(udev, vendor_str, model_str, &newargc, &newargv);

	optind = 1; /* reset this global extern */
	while (retval == 0) {
		option = getopt_long(newargc, newargv, dev_short_options, options, NULL);
		if (option == -1)
			break;

		if (optarg)
			dbg(udev, "option '%c' arg '%s'\n", option, optarg);
		else
			dbg(udev, "option '%c'\n", option);

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
				err(udev, "Unknown page code '%s'\n", optarg);
				retval = -1;
			}
			break;

		default:
			err(udev, "Unknown or bad option '%c' (0x%x)\n", option, option);
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

static int set_inq_values(struct udev *udev, struct scsi_id_device *dev_scsi, const char *path)
{
	int retval;

	dev_scsi->use_sg = sg_version;

	retval = scsi_std_inquiry(udev, dev_scsi, path);
	if (retval)
		return retval;

	udev_util_encode_string(dev_scsi->vendor, vendor_enc_str, sizeof(vendor_enc_str));
	udev_util_encode_string(dev_scsi->model, model_enc_str, sizeof(model_enc_str));

	udev_util_replace_whitespace(dev_scsi->vendor, vendor_str, sizeof(vendor_str));
	udev_util_replace_chars(vendor_str, NULL);
	udev_util_replace_whitespace(dev_scsi->model, model_str, sizeof(model_str));
	udev_util_replace_chars(model_str, NULL);
	set_type(dev_scsi->type, type_str, sizeof(type_str));
	udev_util_replace_whitespace(dev_scsi->revision, revision_str, sizeof(revision_str));
	udev_util_replace_chars(revision_str, NULL);
	return 0;
}

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 * returns a value passed to exit() - 0 if printed an id, else 1.
 */
static int scsi_id(struct udev *udev, char *maj_min_dev)
{
	struct scsi_id_device dev_scsi;
	int good_dev;
	int page_code;
	int retval = 0;

	memset(&dev_scsi, 0x00, sizeof(struct scsi_id_device));

	if (set_inq_values(udev, &dev_scsi, maj_min_dev) < 0) {
		retval = 1;
		goto out;
	}

	/* get per device (vendor + model) options from the config file */
	per_dev_options(udev, &dev_scsi, &good_dev, &page_code);
	dbg(udev, "per dev options: good %d; page code 0x%x\n", good_dev, page_code);
	if (!good_dev) {
		retval = 1;
		goto out;
	}

	/* read serial number from mode pages (no values for optical drives) */
	scsi_get_serial(udev, &dev_scsi, maj_min_dev, page_code, MAX_SERIAL_LEN);

	if (export) {
		char serial_str[MAX_SERIAL_LEN];

		printf("ID_SCSI=1\n");
		printf("ID_VENDOR=%s\n", vendor_str);
		printf("ID_VENDOR_ENC=%s\n", vendor_enc_str);
		printf("ID_MODEL=%s\n", model_str);
		printf("ID_MODEL_ENC=%s\n", model_enc_str);
		printf("ID_REVISION=%s\n", revision_str);
		printf("ID_TYPE=%s\n", type_str);
		if (dev_scsi.serial[0] != '\0') {
			udev_util_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str));
			udev_util_replace_chars(serial_str, NULL);
			printf("ID_SERIAL=%s\n", serial_str);
			udev_util_replace_whitespace(dev_scsi.serial_short, serial_str, sizeof(serial_str));
			udev_util_replace_chars(serial_str, NULL);
			printf("ID_SERIAL_SHORT=%s\n", serial_str);
		}
		if (dev_scsi.wwn[0] != '\0') {
			printf("ID_WWN=0x%s\n", dev_scsi.wwn);
			if (dev_scsi.wwn_vendor_extension[0] != '\0') {
				printf("ID_WWN_VENDOR_EXTENSION=0x%s\n", dev_scsi.wwn_vendor_extension);
				printf("ID_WWN_WITH_EXTENSION=0x%s%s\n", dev_scsi.wwn, dev_scsi.wwn_vendor_extension);
			} else {
				printf("ID_WWN_WITH_EXTENSION=0x%s\n", dev_scsi.wwn);
			}
		}
		if (dev_scsi.tgpt_group[0] != '\0') {
			printf("ID_TARGET_PORT=%s\n", dev_scsi.tgpt_group);
		}
		if (dev_scsi.unit_serial_number[0] != '\0') {
			printf("ID_SCSI_SERIAL=%s\n", dev_scsi.unit_serial_number);
		}
		goto out;
	}

	if (dev_scsi.serial[0] == '\0') {
		retval = 1;
		goto out;
	}

	if (reformat_serial) {
		char serial_str[MAX_SERIAL_LEN];

		udev_util_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str));
		udev_util_replace_chars(serial_str, NULL);
		printf("%s\n", serial_str);
		goto out;
	}

	printf("%s\n", dev_scsi.serial);
out:
	return retval;
}

int main(int argc, char **argv)
{
	struct udev *udev;
	int retval = 0;
	char maj_min_dev[MAX_PATH_LEN];
	int newargc;
	char **newargv;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("scsi_id");
	udev_set_log_fn(udev, log_fn);

	/*
	 * Get config file options.
	 */
	newargv = NULL;
	retval = get_file_options(udev, NULL, NULL, &newargc, &newargv);
	if (retval < 0) {
		retval = 1;
		goto exit;
	}
	if (newargv && (retval == 0)) {
		if (set_options(udev, newargc, newargv, short_options, maj_min_dev) < 0) {
			retval = 2;
			goto exit;
		}
		free(newargv);
	}

	/*
	 * Get command line options (overriding any config file settings).
	 */
	if (set_options(udev, argc, argv, short_options, maj_min_dev) < 0)
		exit(1);

	if (!dev_specified) {
		err(udev, "no device specified\n");
		retval = 1;
		goto exit;
	}

	retval = scsi_id(udev, maj_min_dev);

exit:
	udev_unref(udev);
	udev_log_close();
	return retval;
}
