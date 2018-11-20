@@
expression e;
expression list args;
@@
- log_debug(args);
- return -e;
+ return log_debug_errno(SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression list args;
@@
- log_info(args);
- return -e;
+ return log_info_errno(SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression list args;
@@
- log_notice(args);
- return -e;
+ return log_notice_errno(SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression list args;
@@
- log_error(args);
- return -e;
+ return log_error_errno(SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression list args;
@@
- log_emergency(args);
- return -e;
+ return log_emergency_errno(SYNTHETIC_ERRNO(e), args);
