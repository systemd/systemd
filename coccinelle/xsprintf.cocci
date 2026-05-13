/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression e, fmt;
expression list vaargs;
@@
- snprintf(e, sizeof(e), fmt, vaargs);
+ xsprintf(e, fmt, vaargs);
