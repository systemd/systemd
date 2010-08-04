/*
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:
 */

#include <acl/libacl.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>
#include <glib.h>
#include <inttypes.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int debug;

enum{
	ACTION_NONE = 0,
	ACTION_REMOVE,
	ACTION_ADD,
	ACTION_CHANGE
};

static int set_facl(const char* filename, uid_t uid, int add)
{
	int get;
	acl_t acl;
	acl_entry_t entry = NULL;
	acl_entry_t e;
	acl_permset_t permset;
	int ret;

	/* don't touch ACLs for root */
	if (uid == 0)
		return 0;

	/* read current record */
	acl = acl_get_file(filename, ACL_TYPE_ACCESS);
	if (!acl)
		return -1;

	/* locate ACL_USER entry for uid */
	get = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
	while (get == 1) {
		acl_tag_t t;

		acl_get_tag_type(e, &t);
		if (t == ACL_USER) {
			uid_t *u;

			u = (uid_t*)acl_get_qualifier(e);
			if (u == NULL) {
				ret = -1;
				goto out;
			}
			if (*u == uid) {
				entry = e;
				acl_free(u);
				break;
			}
			acl_free(u);
		}

		get = acl_get_entry(acl, ACL_NEXT_ENTRY, &e);
	}

	/* remove ACL_USER entry for uid */
	if (!add) {
		if (entry == NULL) {
			ret = 0;
			goto out;
		}
		acl_delete_entry(acl, entry);
		goto update;
	}

	/* create ACL_USER entry for uid */
	if (entry == NULL) {
		ret = acl_create_entry(&acl, &entry);
		if (ret != 0)
			goto out;
		acl_set_tag_type(entry, ACL_USER);
		acl_set_qualifier(entry, &uid);
	}

	/* add permissions for uid */
	acl_get_permset(entry, &permset);
	acl_add_perm(permset, ACL_READ|ACL_WRITE);
update:
	/* update record */
	if (debug)
		printf("%c%u %s\n", add ? '+' : '-', uid, filename);
	acl_calc_mask(&acl);
	ret = acl_set_file(filename, ACL_TYPE_ACCESS, acl);
	if (ret != 0)
		goto out;
out:
	acl_free(acl);
	return ret;
}

/* check if a given uid is listed */
static int uid_in_list(GSList *list, uid_t uid)
{
	GSList *l;

	for (l = list; l != NULL; l = g_slist_next(l))
		if (uid == GPOINTER_TO_UINT(l->data))
			return 1;
	return 0;
}

/* return list of current uids of local active sessions */
static GSList *uids_with_local_active_session(const char *own_id)
{
	GSList *list = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();
	if (g_key_file_load_from_file(keyfile, "/var/run/ConsoleKit/database", 0, NULL)) {
		gchar **groups;

		groups = g_key_file_get_groups(keyfile, NULL);
		if (groups != NULL) {
			int i;

			for (i = 0; groups[i] != NULL; i++) {
				uid_t u;

				if (!g_str_has_prefix(groups[i], "Session "))
					continue;
				if (own_id != NULL &&g_str_has_suffix(groups[i], own_id))
					continue;
				if (!g_key_file_get_boolean(keyfile, groups[i], "is_local", NULL))
					continue;
				if (!g_key_file_get_boolean(keyfile, groups[i], "is_active", NULL))
					continue;
				u = g_key_file_get_integer(keyfile, groups[i], "uid", NULL);
				if (u > 0 && !uid_in_list(list, u))
					list = g_slist_prepend(list, GUINT_TO_POINTER(u));
			}
			g_strfreev(groups);
		}
	}
	g_key_file_free(keyfile);

	return list;
}

/* ConsoleKit calls us with special variables */
static int consolekit_called(const char *ck_action, uid_t *uid, uid_t *uid2, const char **remove_session_id, int *action)
{
	int a = ACTION_NONE;
	uid_t u = 0;
	uid_t u2 = 0;
	const char *s;
	const char *s2;
	const char *old_session = NULL;

	if (ck_action == NULL || strcmp(ck_action, "seat_active_session_changed") != 0)
		return -1;

	/* We can have one of: remove, add, change, no-change */
	s = getenv("CK_SEAT_OLD_SESSION_ID");
	s2 = getenv("CK_SEAT_SESSION_ID");
	if (s == NULL && s2 == NULL) {
		return -1;
	} else if (s2 == NULL) {
		a = ACTION_REMOVE;
	} else if (s == NULL) {
		a = ACTION_ADD;
	} else {
		a = ACTION_CHANGE;
	}

	switch (a) {
	case ACTION_ADD:
		s = getenv("CK_SEAT_SESSION_USER_UID");
		if (s == NULL)
			return -1;
		u = strtoul(s, NULL, 10);

		s = getenv("CK_SEAT_SESSION_IS_LOCAL");
		if (s == NULL)
			return -1;
		if (strcmp(s, "true") != 0)
			return 0;

		break;
	case ACTION_REMOVE:
		s = getenv("CK_SEAT_OLD_SESSION_USER_UID");
		if (s == NULL)
			return -1;
		u = strtoul(s, NULL, 10);

		s = getenv("CK_SEAT_OLD_SESSION_IS_LOCAL");
		if (s == NULL)
			return -1;
		if (strcmp(s, "true") != 0)
			return 0;

		old_session = getenv("CK_SEAT_OLD_SESSION_ID");
		if (old_session == NULL)
			return -1;

		break;
	case ACTION_CHANGE:
		s = getenv("CK_SEAT_OLD_SESSION_USER_UID");
		if (s == NULL)
			return -1;
		u = strtoul(s, NULL, 10);
		s = getenv("CK_SEAT_SESSION_USER_UID");
		if (s == NULL)
			return -1;
		u2 = strtoul(s, NULL, 10);

		s = getenv("CK_SEAT_OLD_SESSION_IS_LOCAL");
		s2 = getenv("CK_SEAT_SESSION_IS_LOCAL");
		if (s == NULL || s2 == NULL)
			return -1;
		/* don't process non-local session changes */
		if (strcmp(s, "true") != 0 && strcmp(s2, "true") != 0)
			return 0;

		if (strcmp(s, "true") == 0 && strcmp(s, "true") == 0) {
			/* process the change */
			if (u == u2) {
				/* special case: we noop if we are
				 * changing between local sessions for
				 * the same uid */
				a = ACTION_NONE;
			}
			old_session = getenv("CK_SEAT_OLD_SESSION_ID");
			if (old_session == NULL)
				return -1;
		} else if (strcmp(s, "true") == 0) {
			/* only process the removal */
			a = ACTION_REMOVE;
			old_session = getenv("CK_SEAT_OLD_SESSION_ID");
			if (old_session == NULL)
				return -1;
		} else if (strcmp(s2, "true") == 0) {
			/* only process the addition */
			a = ACTION_ADD;
			u = u2;
		}
		break;
	case ACTION_NONE:
		break;
	default:
		g_assert_not_reached();
		break;
	}

	*remove_session_id = old_session;
	*uid = u;
	*uid2 = u2;
	*action = a;
	return 0;
}

/* add or remove a ACL for a given uid from all matching devices */
static void apply_acl_to_devices(uid_t uid, int add)
{
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *list_entry;

	/* iterate over all devices tagged with ACL_SET */
	udev = udev_new();
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_tag(enumerate, "udev-acl");
	udev_enumerate_scan_devices(enumerate);
	udev_list_entry_foreach(list_entry, udev_enumerate_get_list_entry(enumerate)) {
		struct udev_device *device;
		const char *node;

		device = udev_device_new_from_syspath(udev_enumerate_get_udev(enumerate),
						      udev_list_entry_get_name(list_entry));
		if (device == NULL)
			continue;
		node = udev_device_get_devnode(device);
		if (node == NULL)
			continue;
		set_facl(node, uid, add);
		udev_device_unref(device);
	}
	udev_enumerate_unref(enumerate);
	udev_unref(udev);
}

static void
remove_uid (uid_t uid, const char *remove_session_id)
{
	/*
	 * Remove ACL for given uid from all matching devices
	 * when there is currently no local active session.
	 */
	GSList *list;

	list = uids_with_local_active_session(remove_session_id);
	if (!uid_in_list(list, uid))
		apply_acl_to_devices(uid, 0);
	g_slist_free(list);
}

int main (int argc, char* argv[])
{
	static const struct option options[] = {
		{ "action", required_argument, NULL, 'a' },
		{ "device", required_argument, NULL, 'D' },
		{ "user", required_argument, NULL, 'u' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int action = -1;
	const char *device = NULL;
	bool uid_given = false;
	uid_t uid = 0;
	uid_t uid2 = 0;
	const char* remove_session_id = NULL;
	int rc = 0;

	/* valgrind is more important to us than a slice allocator */
	g_slice_set_config (G_SLICE_CONFIG_ALWAYS_MALLOC, 1);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "+a:D:u:dh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'a':
			if (strcmp(optarg, "remove") == 0)
				action = ACTION_REMOVE;
			else
				action = ACTION_ADD;
			break;
		case 'D':
			device = optarg;
			break;
		case 'u':
			uid_given = true;
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			printf("Usage: udev-acl --action=ACTION [--device=DEVICEFILE] [--user=UID]\n\n");
		default:
			goto out;
		}
	}

	if (action < 0 && device == NULL && !uid_given)
		if (!consolekit_called(argv[optind], &uid, &uid2, &remove_session_id, &action))
			uid_given = true;

	if (action < 0) {
		fprintf(stderr, "missing action\n\n");
		rc = 2;
		goto out;
	}

	if (device != NULL && uid_given) {
		fprintf(stderr, "only one option, --device=DEVICEFILE or --user=UID expected\n\n");
		rc = 3;
		goto out;
	}

	if (uid_given) {
		switch (action) {
		case ACTION_ADD:
			/* Add ACL for given uid to all matching devices. */
			apply_acl_to_devices(uid, 1);
			break;
		case ACTION_REMOVE:
			remove_uid(uid, remove_session_id);
			break;
		case ACTION_CHANGE:
			remove_uid(uid, remove_session_id);
			apply_acl_to_devices(uid2, 1);
			break;
		case ACTION_NONE:
			goto out;
			break;
		default:
			g_assert_not_reached();
			break;
		}
	} else if (device != NULL) {
		/*
		 * Add ACLs for all current session uids to a given device.
		 *
		 * Or remove ACLs for uids which do not have any current local
		 * active session. Remove is not really interesting, because in
		 * most cases the device node is removed anyway.
		 */
		GSList *list;
		GSList *l;

		list = uids_with_local_active_session(NULL);
		for (l = list; l != NULL; l = g_slist_next(l)) {
			uid_t u;

			u = GPOINTER_TO_UINT(l->data);
			if (action == ACTION_ADD || !uid_in_list(list, u))
				set_facl(device, u, action == ACTION_ADD);
		}
		g_slist_free(list);
	} else {
		fprintf(stderr, "--device=DEVICEFILE or --user=UID expected\n\n");
		rc = 3;
	}
out:
	return rc;
}
