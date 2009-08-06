/*
 * Copyright (C) 2003-2009 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "udev.h"

struct udev_event *udev_event_new(struct udev_device *dev)
{
	struct udev_event *event;

	event = calloc(1, sizeof(struct udev_event));
	if (event == NULL)
		return NULL;
	event->dev = dev;
	event->udev = udev_device_get_udev(dev);
	udev_list_init(&event->run_list);
	event->mode = 0660;
	dbg(event->udev, "allocated event %p\n", event);
	return event;
}

void udev_event_unref(struct udev_event *event)
{
	if (event == NULL)
		return;
	udev_list_cleanup_entries(event->udev, &event->run_list);
	free(event->tmp_node);
	free(event->program_result);
	free(event->name);
	dbg(event->udev, "free event %p\n", event);
	free(event);
}

size_t udev_event_apply_format(struct udev_event *event, const char *src, char *dest, size_t size)
{
	struct udev_device *dev = event->dev;
	enum subst_type {
		SUBST_UNKNOWN,
		SUBST_TEMP_NODE,
		SUBST_ATTR,
		SUBST_ENV,
		SUBST_KERNEL,
		SUBST_KERNEL_NUMBER,
		SUBST_DRIVER,
		SUBST_DEVPATH,
		SUBST_ID,
		SUBST_MAJOR,
		SUBST_MINOR,
		SUBST_RESULT,
		SUBST_PARENT,
		SUBST_NAME,
		SUBST_LINKS,
		SUBST_ROOT,
		SUBST_SYS,
	};
	static const struct subst_map {
		char *name;
		char fmt;
		enum subst_type type;
	} map[] = {
		{ .name = "tempnode",	.fmt = 'N',	.type = SUBST_TEMP_NODE },
		{ .name = "attr",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "sysfs",	.fmt = 's',	.type = SUBST_ATTR },
		{ .name = "env",	.fmt = 'E',	.type = SUBST_ENV },
		{ .name = "kernel",	.fmt = 'k',	.type = SUBST_KERNEL },
		{ .name = "number",	.fmt = 'n',	.type = SUBST_KERNEL_NUMBER },
		{ .name = "driver",	.fmt = 'd',	.type = SUBST_DRIVER },
		{ .name = "devpath",	.fmt = 'p',	.type = SUBST_DEVPATH },
		{ .name = "id",		.fmt = 'b',	.type = SUBST_ID },
		{ .name = "major",	.fmt = 'M',	.type = SUBST_MAJOR },
		{ .name = "minor",	.fmt = 'm',	.type = SUBST_MINOR },
		{ .name = "result",	.fmt = 'c',	.type = SUBST_RESULT },
		{ .name = "parent",	.fmt = 'P',	.type = SUBST_PARENT },
		{ .name = "name",	.fmt = 'D',	.type = SUBST_NAME },
		{ .name = "links",	.fmt = 'L',	.type = SUBST_LINKS },
		{ .name = "root",	.fmt = 'r',	.type = SUBST_ROOT },
		{ .name = "sys",	.fmt = 'S',	.type = SUBST_SYS },
	};
	const char *from;
	char *s;
	size_t l;

	from = src;
	s = dest;
	l = size;

	while (1) {
		enum subst_type type = SUBST_UNKNOWN;
		char attrbuf[UTIL_PATH_SIZE];
		char *attr = NULL;

		while (from[0] != '\0') {
			if (from[0] == '$') {
				/* substitute named variable */
				unsigned int i;

				if (from[1] == '$') {
					from++;
					goto copy;
				}

				for (i = 0; i < ARRAY_SIZE(map); i++) {
					if (strncmp(&from[1], map[i].name, strlen(map[i].name)) == 0) {
						type = map[i].type;
						from += strlen(map[i].name)+1;
						dbg(event->udev, "will substitute format name '%s'\n", map[i].name);
						goto subst;
					}
				}
			} else if (from[0] == '%') {
				/* substitute format char */
				unsigned int i;

				if (from[1] == '%') {
					from++;
					goto copy;
				}

				for (i = 0; i < ARRAY_SIZE(map); i++) {
					if (from[1] == map[i].fmt) {
						type = map[i].type;
						from += 2;
						dbg(event->udev, "will substitute format char '%c'\n", map[i].fmt);
						goto subst;
					}
				}
			}
copy:
			/* copy char */
			if (l == 0)
				goto out;
			s[0] = from[0];
			from++;
			s++;
			l--;
		}

		goto out;
subst:
		/* extract possible $format{attr} */
		if (from[0] == '{') {
			unsigned int i;

			from++;
			for (i = 0; from[i] != '}'; i++) {
				if (from[i] == '\0') {
					err(event->udev, "missing closing brace for format '%s'\n", src);
					goto out;
				}
			}
			if (i >= sizeof(attrbuf))
				goto out;
			memcpy(attrbuf, from, i);
			attrbuf[i] = '\0';
			from += i+1;
			attr = attrbuf;
		} else {
			attr = NULL;
		}

		switch (type) {
		case SUBST_DEVPATH:
			l = util_strpcpy(&s, l, udev_device_get_devpath(dev));
			dbg(event->udev, "substitute devpath '%s'\n", udev_device_get_devpath(dev));
			break;
		case SUBST_KERNEL:
			l = util_strpcpy(&s, l, udev_device_get_sysname(dev));
			dbg(event->udev, "substitute kernel name '%s'\n", udev_device_get_sysname(dev));
			break;
		case SUBST_KERNEL_NUMBER:
			if (udev_device_get_sysnum(dev) == NULL)
				break;
			l = util_strpcpy(&s, l, udev_device_get_sysnum(dev));
			dbg(event->udev, "substitute kernel number '%s'\n", udev_device_get_sysnum(dev));
			break;
		case SUBST_ID:
			if (event->dev_parent == NULL)
				break;
			l = util_strpcpy(&s, l, udev_device_get_sysname(event->dev_parent));
			dbg(event->udev, "substitute id '%s'\n", udev_device_get_sysname(event->dev_parent));
			break;
		case SUBST_DRIVER: {
			const char *driver;

			if (event->dev_parent == NULL)
				break;

			driver = udev_device_get_driver(event->dev_parent);
			if (driver == NULL)
				break;
			l = util_strpcpy(&s, l, driver);
			dbg(event->udev, "substitute driver '%s'\n", driver);
			break;
		}
		case SUBST_MAJOR: {
			char num[UTIL_PATH_SIZE];

			sprintf(num, "%d", major(udev_device_get_devnum(dev)));
			l = util_strpcpy(&s, l, num);
			dbg(event->udev, "substitute major number '%s'\n", num);
			break;
		}
		case SUBST_MINOR: {
			char num[UTIL_PATH_SIZE];

			sprintf(num, "%d", minor(udev_device_get_devnum(dev)));
			l = util_strpcpy(&s, l, num);
			dbg(event->udev, "substitute minor number '%s'\n", num);
			break;
		}
		case SUBST_RESULT: {
			char *rest;
			int i;

			if (event->program_result == NULL)
				break;
			/* get part part of the result string */
			i = 0;
			if (attr != NULL)
				i = strtoul(attr, &rest, 10);
			if (i > 0) {
				char result[UTIL_PATH_SIZE];
				char tmp[UTIL_PATH_SIZE];
				char *cpos;

				dbg(event->udev, "request part #%d of result string\n", i);
				util_strscpy(result, sizeof(result), event->program_result);
				cpos = result;
				while (--i) {
					while (cpos[0] != '\0' && !isspace(cpos[0]))
						cpos++;
					while (isspace(cpos[0]))
						cpos++;
				}
				if (i > 0) {
					err(event->udev, "requested part of result string not found\n");
					break;
				}
				util_strscpy(tmp, sizeof(tmp), cpos);
				/* %{2+}c copies the whole string from the second part on */
				if (rest[0] != '+') {
					cpos = strchr(tmp, ' ');
					if (cpos)
						cpos[0] = '\0';
				}
				l = util_strpcpy(&s, l, tmp);
				dbg(event->udev, "substitute part of result string '%s'\n", tmp);
			} else {
				l = util_strpcpy(&s, l, event->program_result);
				dbg(event->udev, "substitute result string '%s'\n", event->program_result);
			}
			break;
		}
		case SUBST_ATTR: {
			const char *value = NULL;
			char vbuf[UTIL_NAME_SIZE];
			size_t len;
			int count;

			if (attr == NULL) {
				err(event->udev, "missing file parameter for attr\n");
				break;
			}

			/* try to read the value specified by "[dmi/id]product_name" */
			if (util_resolve_subsys_kernel(event->udev, attr, vbuf, sizeof(vbuf), 1) == 0)
				value = vbuf;

			/* try to read the attribute the device */
			if (value == NULL)
				value = udev_device_get_sysattr_value(event->dev, attr);

			/* try to read the attribute of the parent device, other matches have selected */
			if (value == NULL && event->dev_parent != NULL && event->dev_parent != event->dev)
				value = udev_device_get_sysattr_value(event->dev_parent, attr);

			if (value == NULL)
				break;

			/* strip trailing whitespace, and replace unwanted characters */
			if (value != vbuf)
				util_strscpy(vbuf, sizeof(vbuf), value);
			len = strlen(vbuf);
			while (len > 0 && isspace(vbuf[--len]))
				vbuf[len] = '\0';
			count = udev_util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
			if (count > 0)
				info(event->udev, "%i character(s) replaced\n" , count);
			l = util_strpcpy(&s, l, vbuf);
			dbg(event->udev, "substitute sysfs value '%s'\n", vbuf);
			break;
		}
		case SUBST_PARENT: {
			struct udev_device *dev_parent;
			const char *devnode;

			dev_parent = udev_device_get_parent(event->dev);
			if (dev_parent == NULL)
				break;
				devnode = udev_device_get_devnode(dev_parent);
			if (devnode != NULL) {
				size_t devlen = strlen(udev_get_dev_path(event->udev))+1;

				l = util_strpcpy(&s, l, &devnode[devlen]);
				dbg(event->udev, "found parent '%s', got node name '%s'\n",
				    udev_device_get_syspath(dev_parent), &devnode[devlen]);
			}
			break;
		}
		case SUBST_TEMP_NODE: {
			dev_t devnum;
			struct stat statbuf;
			char filename[UTIL_PATH_SIZE];
			const char *devtype;

			if (event->tmp_node != NULL) {
				l = util_strpcpy(&s, l, event->tmp_node);
				dbg(event->udev, "tempnode: return earlier created one\n");
				break;
			}
			devnum = udev_device_get_devnum(dev);
			if (major(devnum) == 0)
				break;
			/* lookup kernel provided node */
			if (udev_device_get_knodename(dev) != NULL) {
				util_strscpyl(filename, sizeof(filename),
					      udev_get_dev_path(event->udev), "/", udev_device_get_knodename(dev), NULL);
				if (stat(filename, &statbuf) == 0 && statbuf.st_rdev == devnum) {
					l = util_strpcpy(&s, l, filename);
					dbg(event->udev, "tempnode: return kernel node\n");
					break;
				}
			}
			/* lookup /dev/{char,block}/<maj>:<min> */
			if (strcmp(udev_device_get_subsystem(dev), "block") == 0)
				devtype = "block";
			else
				devtype = "char";
			snprintf(filename, sizeof(filename), "%s/%s/%u:%u",
				 udev_get_dev_path(event->udev), devtype,
				 major(udev_device_get_devnum(dev)),
				 minor(udev_device_get_devnum(dev)));
			if (stat(filename, &statbuf) == 0 && statbuf.st_rdev == devnum) {
				l = util_strpcpy(&s, l, filename);
				dbg(event->udev, "tempnode: return maj:min node\n");
				break;
			}
			/* create temporary node */
			dbg(event->udev, "tempnode: create temp node\n");
			asprintf(&event->tmp_node, "%s/.tmp-%s-%u:%u",
				 udev_get_dev_path(event->udev), devtype,
				 major(udev_device_get_devnum(dev)),
				 minor(udev_device_get_devnum(dev)));
			if (event->tmp_node == NULL)
				break;
			udev_node_mknod(dev, event->tmp_node, makedev(0, 0), 0600, 0, 0);
			l = util_strpcpy(&s, l, event->tmp_node);
			break;
		}
		case SUBST_NAME:
			if (event->name != NULL) {
				l = util_strpcpy(&s, l, event->name);
				dbg(event->udev, "substitute name '%s'\n", event->name);
			} else {
				l = util_strpcpy(&s, l, udev_device_get_sysname(dev));
				dbg(event->udev, "substitute sysname '%s'\n", udev_device_get_sysname(dev));
			}
			break;
		case SUBST_LINKS: {
			size_t devlen = strlen(udev_get_dev_path(event->udev))+1;
			struct udev_list_entry *list_entry;

			list_entry = udev_device_get_devlinks_list_entry(dev);
			if (list_entry == NULL)
				break;
			l = util_strpcpy(&s, l, &udev_list_entry_get_name(list_entry)[devlen]);
			udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry))
				l = util_strpcpyl(&s, l, " ", &udev_list_entry_get_name(list_entry)[devlen], NULL);
			break;
		}
		case SUBST_ROOT:
			l = util_strpcpy(&s, l, udev_get_dev_path(event->udev));
			dbg(event->udev, "substitute udev_root '%s'\n", udev_get_dev_path(event->udev));
			break;
		case SUBST_SYS:
			l = util_strpcpy(&s, l, udev_get_sys_path(event->udev));
			dbg(event->udev, "substitute sys_path '%s'\n", udev_get_sys_path(event->udev));
			break;
		case SUBST_ENV:
			if (attr == NULL) {
				dbg(event->udev, "missing attribute\n");
				break;
			} else {
				const char *value;

				value = udev_device_get_property_value(event->dev, attr);
				if (value == NULL)
					break;
				dbg(event->udev, "substitute env '%s=%s'\n", attr, value);
				l = util_strpcpy(&s, l, value);
				break;
			}
		default:
			err(event->udev, "unknown substitution type=%i\n", type);
			break;
		}
	}

out:
	s[0] = '\0';
	dbg(event->udev, "'%s' -> '%s' (%zu)\n", src, dest, l);
	return l;
}

static void rename_netif_kernel_log(struct ifreq ifr)
{
	int klog;
	FILE *f;

	klog = open("/dev/kmsg", O_WRONLY);
	if (klog < 0)
		return;

	f = fdopen(klog, "w");
	if (f == NULL) {
		close(klog);
		return;
	}

	fprintf(f, "<6>udev: renamed network interface %s to %s\n",
		ifr.ifr_name, ifr.ifr_newname);
	fclose(f);
}

static int rename_netif(struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	int sk;
	struct ifreq ifr;
	int err;

	info(event->udev, "changing net interface name from '%s' to '%s'\n",
	     udev_device_get_sysname(dev), event->name);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err(event->udev, "error opening socket: %m\n");
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	util_strscpy(ifr.ifr_name, IFNAMSIZ, udev_device_get_sysname(dev));
	util_strscpy(ifr.ifr_newname, IFNAMSIZ, event->name);
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err == 0)
		rename_netif_kernel_log(ifr);
	else {
		int loop;

		/* see if the destination interface name already exists */
		if (errno != EEXIST) {
			err(event->udev, "error changing netif name %s to %s: %m\n",
			    ifr.ifr_name, ifr.ifr_newname);
			goto exit;
		}

		/* free our own name, another process may wait for us */
		util_strscpy(ifr.ifr_newname, IFNAMSIZ, udev_device_get_sysname(dev));
		util_strscpy(ifr.ifr_newname, IFNAMSIZ, "_rename");
		err = ioctl(sk, SIOCSIFNAME, &ifr);
		if (err != 0) {
			err(event->udev, "error changing netif name %s to %s: %m\n",
			    ifr.ifr_name, ifr.ifr_newname);
			goto exit;
		}

		/* wait 90 seconds for our target to become available */
		util_strscpy(ifr.ifr_name, IFNAMSIZ, ifr.ifr_newname);
		util_strscpy(ifr.ifr_newname, IFNAMSIZ, event->name);
		loop = 90 * 20;
		while (loop--) {
			err = ioctl(sk, SIOCSIFNAME, &ifr);
			if (err == 0) {
				rename_netif_kernel_log(ifr);
				break;
			}

			if (errno != EEXIST) {
				err(event->udev, "error changing net interface name %s to %s: %m\n",
				    ifr.ifr_name, ifr.ifr_newname);
				break;
			}
			dbg(event->udev, "wait for netif '%s' to become free, loop=%i\n",
			    event->name, (90 * 20) - loop);
			usleep(1000 * 1000 / 20);
		}
	}
exit:
	close(sk);
	return err;
}

int udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules)
{
	struct udev_device *dev = event->dev;
	int err = 0;

	if (udev_device_get_devpath_old(dev) != NULL) {
		if (udev_device_rename_db(dev, udev_device_get_devpath(dev)) == 0)
			info(event->udev, "moved database from '%s' to '%s'\n",
			     udev_device_get_devpath_old(dev), udev_device_get_devpath(dev));
	}

	/* add device node */
	if (major(udev_device_get_devnum(dev)) != 0 &&
	    (strcmp(udev_device_get_action(dev), "add") == 0 || strcmp(udev_device_get_action(dev), "change") == 0)) {
		char filename[UTIL_PATH_SIZE];
		struct udev_device *dev_old;
		int delete_kdevnode = 0;

		dbg(event->udev, "device node add '%s'\n", udev_device_get_devpath(dev));

		/* read old database entry */
		dev_old = udev_device_new_from_syspath(event->udev, udev_device_get_syspath(dev));
		if (dev_old != NULL) {
			udev_device_read_db(dev_old);
			udev_device_set_info_loaded(dev_old);

			/* disable watch during event processing */
			udev_watch_end(event->udev, dev_old);
		}

		udev_rules_apply_to_event(rules, event);
		if (event->tmp_node != NULL) {
			dbg(event->udev, "cleanup temporary device node\n");
			util_unlink_secure(event->udev, event->tmp_node);
			free(event->tmp_node);
			event->tmp_node = NULL;
		}

		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			delete_kdevnode = 1;
			goto exit_add;
		}

		if (event->name != NULL && event->name[0] == '\0') {
			info(event->udev, "device node creation supressed\n");
			delete_kdevnode = 1;
			goto exit_add;
		}

		/* if rule given name disagrees with kernel node name, delete kernel node */
		if (event->name != NULL && udev_device_get_knodename(dev) != NULL) {
			if (strcmp(event->name, udev_device_get_knodename(dev)) != 0)
				delete_kdevnode = 1;
		}

		/* no rule, use kernel provided name */
		if (event->name == NULL) {
			if (udev_device_get_knodename(dev) != NULL) {
				event->name = strdup(udev_device_get_knodename(dev));
				info(event->udev, "no node name set, will use kernel supplied name '%s'\n", event->name);
			} else {
				event->name = strdup(udev_device_get_sysname(event->dev));
				info(event->udev, "no node name set, will use device name '%s'\n", event->name);
			}
		}

		/* something went wrong */
		if (event->name == NULL) {
			err(event->udev, "no node name for '%s'\n", udev_device_get_sysname(event->dev));
			goto exit_add;
		}

		/* set device node name */
		util_strscpyl(filename, sizeof(filename), udev_get_dev_path(event->udev), "/", event->name, NULL);
		udev_device_set_devnode(dev, filename);

		/* write current database entry */
		udev_device_update_db(dev);

		/* remove/update possible left-over symlinks from old database entry */
		if (dev_old != NULL)
			udev_node_update_old_links(dev, dev_old);

		/* create new node and symlinks */
		err = udev_node_add(dev, event->mode, event->uid, event->gid);
exit_add:
		if (delete_kdevnode && udev_device_get_knodename(dev) != NULL) {
			struct stat stats;

			util_strscpyl(filename, sizeof(filename),
				      udev_get_dev_path(event->udev), "/", udev_device_get_knodename(dev), NULL);
			if (stat(filename, &stats) == 0 && stats.st_rdev == udev_device_get_devnum(dev)) {
				unlink(filename);
				util_delete_path(event->udev, filename);
				info(event->udev, "removed kernel created node '%s'\n", filename);
			}
		}
		udev_device_unref(dev_old);
		goto exit;
	}

	/* add netif */
	if (strcmp(udev_device_get_subsystem(dev), "net") == 0 && strcmp(udev_device_get_action(dev), "add") == 0) {
		dbg(event->udev, "netif add '%s'\n", udev_device_get_devpath(dev));
		udev_device_delete_db(dev);

		udev_rules_apply_to_event(rules, event);
		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			goto exit;
		}
		if (event->name == NULL)
			goto exit;

		/* look if we want to change the name of the netif */
		if (strcmp(event->name, udev_device_get_sysname(dev)) != 0) {
			char syspath[UTIL_PATH_SIZE];
			char *pos;

			err = rename_netif(event);
			if (err != 0)
				goto exit;
			info(event->udev, "renamed netif to '%s'\n", event->name);

			/* remember old name */
			udev_device_add_property(dev, "INTERFACE_OLD", udev_device_get_sysname(dev));

			/* now change the devpath, because the kernel device name has changed */
			util_strscpy(syspath, sizeof(syspath), udev_device_get_syspath(dev));
			pos = strrchr(syspath, '/');
			if (pos != NULL) {
				pos++;
				util_strscpy(pos, sizeof(syspath) - (pos - syspath), event->name);
				udev_device_set_syspath(event->dev, syspath);
				udev_device_add_property(dev, "INTERFACE", udev_device_get_sysname(dev));
				info(event->udev, "changed devpath to '%s'\n", udev_device_get_devpath(dev));
			}
		}
		udev_device_update_db(dev);
		goto exit;
	}

	/* remove device node */
	if (major(udev_device_get_devnum(dev)) != 0 && strcmp(udev_device_get_action(dev), "remove") == 0) {
		/* import database entry and delete it */
		udev_device_read_db(dev);
		udev_device_set_info_loaded(dev);
		udev_device_delete_db(dev);

		/* remove watch */
		udev_watch_end(event->udev, dev);

		if (udev_device_get_devnode(dev) == NULL) {
			char devnode[UTIL_PATH_SIZE];

			info(event->udev, "'%s' not found in database, using kernel name '%s'\n",
			     udev_device_get_syspath(dev), udev_device_get_sysname(dev));
			util_strscpyl(devnode, sizeof(devnode),
				      udev_get_dev_path(event->udev), "/", udev_device_get_sysname(dev), NULL);
			udev_device_set_devnode(dev, devnode);
		}

		udev_rules_apply_to_event(rules, event);
		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			goto exit;
		}

		if (udev_device_get_ignore_remove(dev)) {
			info(event->udev, "ignore_remove for '%s'\n", udev_device_get_devnode(dev));
			goto exit;
		}

		err = udev_node_remove(dev);
		goto exit;
	}

	/* default devices */
	udev_rules_apply_to_event(rules, event);
	if (event->ignore_device)
		info(event->udev, "device event will be ignored\n");

	if (strcmp(udev_device_get_action(dev), "remove") != 0)
		udev_device_update_db(dev);
	else
		udev_device_delete_db(dev);
exit:
	return err;
}

int udev_event_execute_run(struct udev_event *event)
{
	struct udev_list_entry *list_entry;
	int err = 0;

	dbg(event->udev, "executing run list\n");
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&event->run_list)) {
		const char *cmd = udev_list_entry_get_name(list_entry);

		if (strncmp(cmd, "socket:", strlen("socket:")) == 0) {
			struct udev_monitor *monitor;

			monitor = udev_monitor_new_from_socket(event->udev, &cmd[strlen("socket:")]);
			if (monitor == NULL)
				continue;
			udev_monitor_send_device(monitor, NULL, event->dev);
			udev_monitor_unref(monitor);
		} else {
			char program[UTIL_PATH_SIZE];
			char **envp;

			udev_event_apply_format(event, cmd, program, sizeof(program));
			envp = udev_device_get_properties_envp(event->dev);
			if (util_run_program(event->udev, program, envp, NULL, 0, NULL) != 0) {
				if (udev_list_entry_get_flag(list_entry))
					err = -1;
			}
		}
	}
	return err;
}
