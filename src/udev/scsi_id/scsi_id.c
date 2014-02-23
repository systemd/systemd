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
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/stat.h>

#include "libudev.h"
#include "libudev-private.h"
#include "scsi_id.h"
#include "udev-util.h"

static const struct option options[] = {
        { "device",             required_argument, NULL, 'd' },
        { "config",             required_argument, NULL, 'f' },
        { "page",               required_argument, NULL, 'p' },
        { "blacklisted",        no_argument,       NULL, 'b' },
        { "whitelisted",        no_argument,       NULL, 'g' },
        { "replace-whitespace", no_argument,       NULL, 'u' },
        { "sg-version",         required_argument, NULL, 's' },
        { "verbose",            no_argument,       NULL, 'v' },
        { "version",            no_argument,       NULL, 'V' }, /* don't advertise -V */
        { "export",             no_argument,       NULL, 'x' },
        { "help",               no_argument,       NULL, 'h' },
        {}
};

static bool all_good = false;
static bool dev_specified = false;
static char config_file[MAX_PATH_LEN] = "/etc/scsi_id.config";
static enum page_code default_page_code = PAGE_UNSPECIFIED;
static int sg_version = 4;
static int debug = 0;
static bool reformat_serial = false;
static bool export = false;
static char vendor_str[64];
static char model_str[64];
static char vendor_enc_str[256];
static char model_enc_str[256];
static char revision_str[16];
static char type_str[16];

_printf_(6,0)
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
        const char *type = "generic";

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
        strscpy(to, len, type);
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
        static const char *quote_string = "\"\n";
        static const char *comma_string = ",\n";
        char *val;
        const char *end;

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
        _cleanup_fclose_ FILE *f;
        char *buf;
        char *str1;
        char *vendor_in, *model_in, *options_in; /* read in from file */
        int lineno;
        int c;
        int retval = 0;

        f = fopen(config_file, "re");
        if (f == NULL) {
                if (errno == ENOENT)
                        return 1;
                else {
                        log_error("can't open %s: %m", config_file);
                        return -1;
                }
        }

        /*
         * Allocate a buffer rather than put it on the stack so we can
         * keep it around to parse any options (any allocated newargv
         * points into this buffer for its strings).
         */
        buffer = malloc(MAX_BUFFER_LEN);
        if (!buffer)
                return log_oom();

        *newargv = NULL;
        lineno = 0;
        while (1) {
                vendor_in = model_in = options_in = NULL;

                buf = fgets(buffer, MAX_BUFFER_LEN, f);
                if (buf == NULL)
                        break;
                lineno++;
                if (buf[strlen(buffer) - 1] != '\n') {
                        log_error("Config file line %d too long", lineno);
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

                str1 = strsep(&buf, "=");
                if (str1 && strcaseeq(str1, "VENDOR")) {
                        str1 = get_value(&buf);
                        if (!str1) {
                                retval = log_oom();
                                break;
                        }
                        vendor_in = str1;

                        str1 = strsep(&buf, "=");
                        if (str1 && strcaseeq(str1, "MODEL")) {
                                str1 = get_value(&buf);
                                if (!str1) {
                                        retval = log_oom();
                                        break;
                                }
                                model_in = str1;
                                str1 = strsep(&buf, "=");
                        }
                }

                if (str1 && strcaseeq(str1, "OPTIONS")) {
                        str1 = get_value(&buf);
                        if (!str1) {
                                retval = log_oom();
                                break;
                        }
                        options_in = str1;
                }

                /*
                 * Only allow: [vendor=foo[,model=bar]]options=stuff
                 */
                if (!options_in || (!vendor_in && model_in)) {
                        log_error("Error parsing config file line %d '%s'", lineno, buffer);
                        retval = -1;
                        break;
                }
                if (vendor == NULL) {
                        if (vendor_in == NULL)
                                break;
                } else if (vendor_in &&
                           strneq(vendor, vendor_in, strlen(vendor_in)) &&
                           (!model_in ||
                            (strneq(model, model_in, strlen(model_in))))) {
                                /*
                                 * Matched vendor and optionally model.
                                 *
                                 * Note: a short vendor_in or model_in can
                                 * give a partial match (that is FOO
                                 * matches FOOBAR).
                                 */
                                break;
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
                                retval = log_oom();
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
        return retval;
}

static void help(void) {
        printf("Usage: scsi_id [OPTION...] DEVICE\n"
               "  -d,--device=                     device node for SG_IO commands\n"
               "  -f,--config=                     location of config file\n"
               "  -p,--page=0x80|0x83|pre-spc3-83  SCSI page (0x80, 0x83, pre-spc3-83)\n"
               "  -s,--sg-version=3|4              use SGv3 or SGv4\n"
               "  -b,--blacklisted                 threat device as blacklisted\n"
               "  -g,--whitelisted                 threat device as whitelisted\n"
               "  -u,--replace-whitespace          replace all whitespace by underscores\n"
               "  -v,--verbose                     verbose logging\n"
               "     --version                     print version\n"
               "  -x,--export                      print values as environment keys\n"
               "  -h,--help                        print this help text\n\n");

}

static int set_options(struct udev *udev,
                       int argc, char **argv,
                       char *maj_min_dev)
{
        int option;

        /*
         * optind is a global extern used by getopt. Since we can call
         * set_options twice (once for command line, and once for config
         * file) we have to reset this back to 1.
         */
        optind = 1;
        while ((option = getopt_long(argc, argv, "d:f:gp:uvVxh", options, NULL)) >= 0)
                switch (option) {
                case 'b':
                        all_good = false;
                        break;

                case 'd':
                        dev_specified = true;
                        strscpy(maj_min_dev, MAX_PATH_LEN, optarg);
                        break;

                case 'f':
                        strscpy(config_file, MAX_PATH_LEN, optarg);
                        break;

                case 'g':
                        all_good = true;
                        break;

                case 'h':
                        help();
                        exit(0);

                case 'p':
                        if (streq(optarg, "0x80"))
                                default_page_code = PAGE_80;
                        else if (streq(optarg, "0x83"))
                                default_page_code = PAGE_83;
                        else if (streq(optarg, "pre-spc3-83"))
                                default_page_code = PAGE_83_PRE_SPC3;
                        else {
                                log_error("Unknown page code '%s'", optarg);
                                return -1;
                        }
                        break;

                case 's':
                        sg_version = atoi(optarg);
                        if (sg_version < 3 || sg_version > 4) {
                                log_error("Unknown SG version '%s'", optarg);
                                return -1;
                        }
                        break;

                case 'u':
                        reformat_serial = true;
                        break;

                case 'v':
                        debug++;
                        break;

                case 'V':
                        printf("%s\n", VERSION);
                        exit(0);

                case 'x':
                        export = true;
                        break;

                case '?':
                        return -1;

                default:
                        assert_not_reached("Unknown option");
                }

        if (optind < argc && !dev_specified) {
                dev_specified = true;
                strscpy(maj_min_dev, MAX_PATH_LEN, argv[optind]);
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
                option = getopt_long(newargc, newargv, "bgp:", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'b':
                        *good_bad = 0;
                        break;

                case 'g':
                        *good_bad = 1;
                        break;

                case 'p':
                        if (streq(optarg, "0x80")) {
                                *page_code = PAGE_80;
                        } else if (streq(optarg, "0x83")) {
                                *page_code = PAGE_83;
                        } else if (streq(optarg, "pre-spc3-83")) {
                                *page_code = PAGE_83_PRE_SPC3;
                        } else {
                                log_error("Unknown page code '%s'", optarg);
                                retval = -1;
                        }
                        break;

                default:
                        log_error("Unknown or bad option '%c' (0x%x)", option, option);
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

        util_replace_whitespace(dev_scsi->vendor, vendor_str, sizeof(vendor_str));
        util_replace_chars(vendor_str, NULL);
        util_replace_whitespace(dev_scsi->model, model_str, sizeof(model_str));
        util_replace_chars(model_str, NULL);
        set_type(dev_scsi->type, type_str, sizeof(type_str));
        util_replace_whitespace(dev_scsi->revision, revision_str, sizeof(revision_str));
        util_replace_chars(revision_str, NULL);
        return 0;
}

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 * returns a value passed to exit() - 0 if printed an id, else 1.
 */
static int scsi_id(struct udev *udev, char *maj_min_dev)
{
        struct scsi_id_device dev_scsi = {};
        int good_dev;
        int page_code;
        int retval = 0;

        if (set_inq_values(udev, &dev_scsi, maj_min_dev) < 0) {
                retval = 1;
                goto out;
        }

        /* get per device (vendor + model) options from the config file */
        per_dev_options(udev, &dev_scsi, &good_dev, &page_code);
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
                        util_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str));
                        util_replace_chars(serial_str, NULL);
                        printf("ID_SERIAL=%s\n", serial_str);
                        util_replace_whitespace(dev_scsi.serial_short, serial_str, sizeof(serial_str));
                        util_replace_chars(serial_str, NULL);
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

                util_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str));
                util_replace_chars(serial_str, NULL);
                printf("%s\n", serial_str);
                goto out;
        }

        printf("%s\n", dev_scsi.serial);
out:
        return retval;
}

int main(int argc, char **argv)
{
        _cleanup_udev_unref_ struct udev *udev;
        int retval = 0;
        char maj_min_dev[MAX_PATH_LEN];
        int newargc;
        char **newargv = NULL;

        udev = udev_new();
        if (udev == NULL)
                goto exit;

        log_open();
        udev_set_log_fn(udev, log_fn);

        /*
         * Get config file options.
         */
        retval = get_file_options(udev, NULL, NULL, &newargc, &newargv);
        if (retval < 0) {
                retval = 1;
                goto exit;
        }
        if (retval == 0) {
                assert(newargv);

                if (set_options(udev, newargc, newargv, maj_min_dev) < 0) {
                        retval = 2;
                        goto exit;
                }
        }

        /*
         * Get command line options (overriding any config file settings).
         */
        if (set_options(udev, argc, argv, maj_min_dev) < 0)
                exit(1);

        if (!dev_specified) {
                log_error("no device specified");
                retval = 1;
                goto exit;
        }

        retval = scsi_id(udev, maj_min_dev);

exit:
        if (newargv) {
                free(newargv[0]);
                free(newargv);
        }
        log_close();
        return retval;
}
