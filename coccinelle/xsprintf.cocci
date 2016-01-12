@@
expression e, fmt;
expression list vaargs;
@@
- snprintf(e, sizeof(e), fmt, vaargs);
+ xsprintf(e, fmt, vaargs);
