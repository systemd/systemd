/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef selinuxaccesshfoo
#define selinuxaccesshfoo

/***
  This file is part of systemd.

  Copyright 2012 Dan Walsh

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

void selinux_access_finish(void);
int selinux_manager_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, DBusError *error);
int selinux_unit_access_check(DBusConnection *connection, DBusMessage *message, Manager *m, const char *path, DBusError *error);
#endif
