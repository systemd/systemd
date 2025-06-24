/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression m;
@@
- sd_bus_send(NULL, m, NULL)
+ sd_bus_message_send(m)
