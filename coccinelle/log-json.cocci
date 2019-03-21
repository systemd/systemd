@@
expression e, v, flags;
expression list args;
@@
+ return
- json_log(v, flags, 0, args);
+ json_log(v, flags, SYNTHETIC_ERRNO(e), args);
- return -e;
