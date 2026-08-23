/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression p;
@@
- if (p) {
-         (void) sd_event_source_set_enabled(p, SD_EVENT_OFF);
-         p = sd_event_source_unref(p);
- }
+ p = sd_event_source_disable_unref(p);
@@
expression p;
@@
- if (p) {
-         sd_event_source_set_enabled(p, SD_EVENT_OFF);
-         sd_event_source_unref(p);
- }
+ sd_event_source_disable_unref(p);
@@
expression p;
@@
- if (p) {
-         (void) sd_event_source_set_enabled(p, SD_EVENT_OFF);
-         sd_event_source_unref(p);
- }
+ sd_event_source_disable_unref(p);
@@
expression p;
@@
- (void) sd_event_source_set_enabled(p, SD_EVENT_OFF);
- sd_event_source_unref(p);
+ sd_event_source_disable_unref(p);
@@
expression p;
@@
- sd_event_source_set_enabled(p, SD_EVENT_OFF);
- sd_event_source_unref(p);
+ sd_event_source_disable_unref(p);
