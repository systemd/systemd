@@
expression e;
expression list args;
@@
(
/* Ignore one specific case in src/shared/bootspec.c where we want to stick
 * with the log_debug() + return pattern */
log_debug("Found no default boot entry :(");
|
- log_debug(args);
- return -e;
+ return log_debug_errno(SYNTHETIC_ERRNO(e), args);
)
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
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
identifier ERRNO =~ "^E[A-Z]+$";
expression list args;
@@
- return log_LEVEL_errno(ERRNO, args);
+ return log_LEVEL_errno(SYNTHETIC_ERRNO(ERRNO), args);
