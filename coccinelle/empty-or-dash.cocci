/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression s;
@@
- (isempty(s) || streq(s, "-"))
+ empty_or_dash(s)
