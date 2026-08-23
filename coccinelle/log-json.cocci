/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression e, v, flags;
expression list args;
@@
- json_log(v, flags, 0, args);
- return -e;
+ return json_log(v, flags, SYNTHETIC_ERRNO(e), args);
