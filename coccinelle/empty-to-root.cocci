/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression s;
@@
- if (empty_or_root(s))
-         s = "/";
+ s = empty_to_root(s);
@@
expression s;
@@
- (empty_or_root(s) ? "/" : s)
+ empty_to_root(s)
@@
expression s;
@@
- (s ? s : "/")
+ empty_to_root(s)
