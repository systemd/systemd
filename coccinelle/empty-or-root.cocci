/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression s;
@@
- (isempty(s) || path_equal(s, "/"))
+ empty_or_root(s)
@@
expression s;
@@
- (!isempty(s) && !path_equal(s, "/"))
+ !empty_or_root(s)
