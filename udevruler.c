/*
 * udevruler.c - simple udev-rule composer
 *
 * Reads the udev-db to get all currently known devices and
 * scans the sysfs device chain for the choosen device to select attributes
 * to compose a rule for the udev.rules file to uniquely name this device.
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <newt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include "udev.h"
#include "udev_lib.h"
#include "udev_version.h"
#include "udevdb.h"
#include "logging.h"
#include "libsysfs/sysfs.h"
#include "list.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	if (!udev_log)
		return;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

static char *dev_blacklist[] = {
	"tty",
	"pty",
	"zero",
	"null",
	"kmsg",
	"rtc",
	"timer",
	"full",
	"kmem",
	"mem",
	"random",
	"urandom",
	"console",
	"port",
	""
};

struct device {
	struct list_head list;
	char name[NAME_SIZE];
	char devpath[DEVPATH_SIZE];
	int config_line;
	char config_file[NAME_SIZE];
	long config_uptime;
	int added;
};

static LIST_HEAD(device_list);
static int device_count;

/* callback for database dump */
static int add_record(char *path, struct udevice *udev)
{
	struct device *dev;
	struct device *loop_dev;
	int i = 0;

	while (dev_blacklist[i][0] != '\0') {
		if (strncmp(udev->name, dev_blacklist[i], strlen(dev_blacklist[i])) == 0)
			goto exit;
		i++;
	}

	dev = malloc(sizeof(struct device));
	if (dev == NULL) {
		printf("error malloc\n");
		exit(2);
	}
	strfieldcpy(dev->name, udev->name);
	strfieldcpy(dev->devpath, path);
	dev->config_line = udev->config_line;
	strfieldcpy(dev->config_file, udev->config_file);
	dev->config_uptime = udev->config_uptime;
	dev->added = 0;

	/* sort in lexical order */
	list_for_each_entry(loop_dev, &device_list, list) {
		if (strcmp(loop_dev->name, dev->name) > 0) {
			break;
		}
	}

	list_add_tail(&dev->list, &loop_dev->list);
	device_count++;

exit:
	return 0;
}

/* get all devices from udev database */
static int get_all_devices(void)
{
	int retval;

	device_count = 0;
	INIT_LIST_HEAD(&device_list);

	retval = udevdb_open_ro();
	if (retval != 0) {
		printf("unable to open udev database\n");
		exit(1);
	}

	udevdb_call_foreach(add_record);
	udevdb_exit();

	return 0;
}

struct attribute {
	struct list_head list;
	int level;
	char key[NAME_SIZE];
};

static LIST_HEAD(attribute_list);
static int attribute_count;

static int add_attribute(const char *key, int level)
{
	struct attribute *attr;

	dbg("add attribute '%s'", key);
	attr = malloc(sizeof(struct attribute));
	if (attr == NULL) {
		printf("error malloc\n");
		exit(2);
	}

	strfieldcpy(attr->key, key);
	attr->level = level;
	list_add_tail(&attr->list, &attribute_list);
	attribute_count++;
	return 0;
}

static int add_all_attributes(const char *path, int level)
{
	struct dlist *attributes;
	struct sysfs_attribute *attr;
	struct sysfs_directory *sysfs_dir;
	char value[NAME_SIZE];
	char key[NAME_SIZE];
	int len;
	int retval = 0;

	dbg("look at '%s', level %i", path, level);

	sysfs_dir = sysfs_open_directory(path);
	if (sysfs_dir == NULL)
		return -1;

	attributes = sysfs_get_dir_attributes(sysfs_dir);
	if (attributes == NULL) {
		retval = -1;
		return 0;
	}

	dlist_for_each_data(attributes, attr, struct sysfs_attribute)
		if (attr->value != NULL) {
			dbg("found attribute '%s'", attr->name);
			strfieldcpy(value, attr->value);
			len = strlen(value);
			if (len == 0)
				continue;

			/* skip very long attributes */
			if (len > 40)
				continue;

			/* remove trailing newline */
			if (value[len-1] == '\n') {
				value[len-1] = '\0';
				len--;
			}

			/* skip nonprintable values */
			while (len) {
				if (!isprint(value[len-1]))
					break;
				len--;
			}
			if (len == 0) {
				sprintf(key, "SYSFS{%s}=\"%s\"", attr->name, value);
				add_attribute(key, level);
			}
		}

	sysfs_close_directory(sysfs_dir);
	return 0;
}

static int get_all_attributes(char *path)
{
	struct sysfs_class_device *class_dev;
	struct sysfs_class_device *class_dev_parent;
	struct sysfs_device *sysfs_dev;
	struct sysfs_device *sysfs_dev_parent;
	char key[NAME_SIZE];
	int retval = 0;
	int level = 0;

	attribute_count = 0;
	INIT_LIST_HEAD(&attribute_list);

	/*  get the class dev */
	class_dev = sysfs_open_class_device_path(path);
	if (class_dev == NULL) {
		dbg("couldn't get the class device");
		return -1;
	}

	/* open sysfs class device directory and get all attributes */
	if (add_all_attributes(class_dev->path, level) != 0) {
		dbg("couldn't open class device directory");
		retval = -1;
		goto exit;
	}
	level++;

	/* get the device link (if parent exists look here) */
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent != NULL)
		sysfs_dev = sysfs_get_classdev_device(class_dev_parent);
	else
		sysfs_dev = sysfs_get_classdev_device(class_dev);

	/* look the device chain upwards */
	while (sysfs_dev != NULL) {
		if (sysfs_dev->bus[0] != '\0') {
			add_attribute("", level);
			sprintf(key, "BUS=\"%s\"", sysfs_dev->bus);
			add_attribute(key, level);
			sprintf(key, "ID=\"%s\"", sysfs_dev->bus_id);
			add_attribute(key, level);

			/* open sysfs device directory and print all attributes */
			add_all_attributes(sysfs_dev->path, level);
		}
		level++;

		sysfs_dev_parent = sysfs_get_device_parent(sysfs_dev);
		if (sysfs_dev_parent == NULL)
			break;

		sysfs_dev = sysfs_dev_parent;
	}

exit:
	sysfs_close_class_device(class_dev);
	return retval;
}


int main(int argc, char *argv[]) {
	newtComponent lbox, run, lattr;
	newtComponent quit, form, answer;
	newtGrid grid, grid2;
	char roottext[81];
	char path[NAME_SIZE];
	struct device *dev;
	long time_last;
	int count_last;

	newtInit();
	newtCls();

	newtWinMessage("udevruler", "Ok",
		       "This program lets you select a device currently present "
		       "on the system and you may choose the attributes to uniquely "
		       "name the device with a udev rule.\n"
		       "No configuration will be changed, it just prints the rule "
		       "to place in a udev.rules configuration file. The \"%k\" in the "
		       "NAME key of the printed rule may be replaced by the name the "
		       "node should have.");

	init_logging("udevruler");
	udev_init_config();
	get_all_devices();

	lbox = newtListbox(2, 1, 10, NEWT_FLAG_SCROLL | NEWT_FLAG_RETURNEXIT);

	/* look for last discovered device */
	time_last = 0;
	list_for_each_entry(dev, &device_list, list)
		if (dev->config_uptime > time_last)
			time_last = dev->config_uptime;

	/* skip if more than 16 recent devices */
	count_last = 0;
	list_for_each_entry(dev, &device_list, list) {
		if (dev->config_uptime < time_last - 10)
			continue;
		count_last++;
	}

	/* add devices up to 10 seconds older than the last one */
	if (count_last < 16) {
		newtListboxAppendEntry(lbox, "--- last dicovered ---", NULL);
		list_for_each_entry(dev, &device_list, list) {
			if (dev->config_uptime < time_last - 10)
				continue;

			dbg("%s %i", dev->name, dev->config_line);
			newtListboxAppendEntry(lbox, dev->name, (void*) dev);
			dev->added = 1;
		}
		newtListboxAppendEntry(lbox, "", NULL);
	}

	/* add devices not catched by a rule */
	newtListboxAppendEntry(lbox, "--- not configured by a rule ---", NULL);
	list_for_each_entry(dev, &device_list, list) {
		if (dev->added)
			continue;

		if (dev->config_line != 0)
			continue;

		dbg("%s %i", dev->name, dev->config_line);
		newtListboxAppendEntry(lbox, dev->name, (void*) dev);
		dev->added = 1;
	}
	newtListboxAppendEntry(lbox, "", NULL);

	/* add remaining devices */
	newtListboxAppendEntry(lbox, "--- configured by a rule ---", NULL);
	list_for_each_entry(dev, &device_list, list) {
		if (dev->added)
			continue;

		dbg("%s %i", dev->name, dev->config_line);
		newtListboxAppendEntry(lbox, dev->name, (void*) dev);
	}

	newtPushHelpLine("    <Tab>/<Alt-Tab> between elements  |    Use <Enter> to select a device");
	snprintf(roottext, sizeof(roottext), "simple udev rule composer, version %s, (c) 2004 can't sleep team", UDEV_VERSION);
	roottext[sizeof(roottext)-1] = '\0';
	newtDrawRootText(0, 0, roottext);

	form = newtForm(NULL, NULL, 0);
	grid = newtCreateGrid(1, 2);
	grid2 = newtButtonBar("Select device", &run, "Quit", &quit, NULL);
	newtGridSetField(grid, 0, 0, NEWT_GRID_COMPONENT, lbox, 1, 0, 1, 0, NEWT_ANCHOR_TOP, 0);
	newtGridSetField(grid, 0, 1, NEWT_GRID_SUBGRID, grid2, 0, 1, 0, 0, NEWT_ANCHOR_TOP, 0);
	newtFormAddComponents(form, lbox, run, quit, NULL);
	newtGridWrappedWindow(grid,"Choose the device for which to compose a rule");
	newtGridFree(grid, 1);

	while (1) {
		struct attribute *attr;
		newtComponent ok, back, form2, answer2, text;
		newtGrid grid3, grid4;
		int i;
		int numitems;
		struct attribute **selattr;
		char text_rule[255];

		answer = newtRunForm(form);
		if (answer == quit)
			break;

		dev = (struct device *) newtListboxGetCurrent(lbox);
		if (dev == NULL)
			continue;

		if (dev->config_line > 0)
			snprintf(text_rule, sizeof(text_rule),
				 "The device is handled by a rule in the file '%s', line %i.",
				 dev->config_file, dev->config_line);
		else
			strcpy(text_rule, "The device was not handled by a rule.");

		strfieldcpy(path, sysfs_path);
		strfieldcat(path, dev->devpath);
		dbg("look at sysfs device '%s'", path);
		get_all_attributes(path);

		grid3 = newtCreateGrid(1, 3);
		form2 = newtForm(NULL, NULL, 0);
		grid4 = newtButtonBar("Ok", &ok, "Back", &back, NULL);

		lattr = newtListbox(-1, -1, 10, NEWT_FLAG_MULTIPLE | NEWT_FLAG_BORDER | NEWT_FLAG_RETURNEXIT);
		list_for_each_entry(attr, &attribute_list, list)
			newtListboxAddEntry(lattr, attr->key, (void *) attr);

		text = newtTextbox(-1, -1, 50, 2, NEWT_FLAG_WRAP);
		newtTextboxSetText(text, text_rule);

		newtGridSetField(grid3, 0, 0, NEWT_GRID_COMPONENT, lattr, 0, 0, 0, 1, 0, 0);
		newtGridSetField(grid3, 0, 1, NEWT_GRID_COMPONENT, text, 0, 0, 0, 1, 0, 0);
		newtGridSetField(grid3, 0, 2, NEWT_GRID_SUBGRID, grid4, 0, 1, 0, 0, NEWT_ANCHOR_TOP, 0);

		newtFormAddComponents(form2, text, lattr, ok, back, NULL);
		newtGridWrappedWindow(grid3, "Select one ore more attributes within one section with the space bar");
		newtGridFree(grid3, 1);

		while (1) {
			char rule[255];
			int onelevel;
			int skipped;

			answer2 = newtRunForm(form2);
			if (answer2 == back)
				break;

			selattr = (struct attribute **) newtListboxGetSelection(lattr, &numitems);
			if (selattr == NULL)
				continue;

			rule[0] = '\0';
			onelevel = -1;
			skipped = 0;
			for (i = 0; i < numitems; i++) {
				if (selattr[i]->key[0] == '\0')
					continue;

				if (onelevel != -1) {
					if (onelevel != selattr[i]->level) {
						skipped = 1;
						continue;
					}
				} else {
					onelevel = selattr[i]->level;
				}

				dbg("'%s'\n", selattr[i]->key);
				strfieldcat(rule, selattr[i]->key);
				strfieldcat(rule, ", ");
			}
			if (skipped) {
				newtWinMessage("error", "Ok", "Please select only attributes within one section");
				continue;
			}

			if (strlen(rule) > 200) {
				newtWinMessage("error", "Ok", "The line is too long, please select fewer attributes.");
			} else {
				if (rule[0] == '\0')
					continue;

				strfieldcat(rule, "NAME=\"%k\"");
				newtWinMessage("the rule to place in config file", "Ok", rule);
			}
		}

		newtPopWindow();
	}

	newtPopWindow();
	newtFormDestroy(form);
	newtFinished();
	return 0;
}
