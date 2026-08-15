/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
(
/* Ignore specific cases in src/import/{export,import,pull}.c where we want to return positive value on success. */
log_info("Exiting.");
return -r;
|
- log_info(args);
- return -e;
+ return log_info_errno(SYNTHETIC_ERRNO(e), args);
)
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
- log_LEVEL_errno(ERRNO, args);
+ log_LEVEL_errno(SYNTHETIC_ERRNO(ERRNO), args);
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
identifier ERRNO =~ "^E[A-Z]+$";
expression u;
expression list args;
@@
- log_UNIT_LEVEL_errno(u, ERRNO, args);
+ log_UNIT_LEVEL_errno(u, SYNTHETIC_ERRNO(ERRNO), args);
@@
expression e;
expression u;
expression list args;
@@
- log_unit_debug(u, args);
- return -e;
+ return log_unit_debug_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_unit_info(u, args);
- return -e;
+ return log_unit_info_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_unit_notice(u, args);
- return -e;
+ return log_unit_notice_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_unit_error(u, args);
- return -e;
+ return log_unit_error_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_unit_emergency(u, args);
- return -e;
+ return log_unit_emergency_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_link_debug(u, args);
- return -e;
+ return log_link_debug_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_link_info(u, args);
- return -e;
+ return log_link_info_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_link_notice(u, args);
- return -e;
+ return log_link_notice_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_link_error(u, args);
- return -e;
+ return log_link_error_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_link_emergency(u, args);
- return -e;
+ return log_link_emergency_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_netdev_debug(u, args);
- return -e;
+ return log_netdev_debug_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_netdev_info(u, args);
- return -e;
+ return log_netdev_info_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_netdev_notice(u, args);
- return -e;
+ return log_netdev_notice_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_netdev_error(u, args);
- return -e;
+ return log_netdev_error_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_netdev_emergency(u, args);
- return -e;
+ return log_netdev_emergency_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_device_debug(u, args);
- return -e;
+ return log_device_debug_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_device_info(u, args);
- return -e;
+ return log_device_info_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_device_notice(u, args);
- return -e;
+ return log_device_notice_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_device_error(u, args);
- return -e;
+ return log_device_error_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_device_emergency(u, args);
- return -e;
+ return log_device_emergency_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_token_debug(u, args);
- return -e;
+ return log_token_debug_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_token_info(u, args);
- return -e;
+ return log_token_info_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_token_notice(u, args);
- return -e;
+ return log_token_notice_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_token_error(u, args);
- return -e;
+ return log_token_error_errno(u, SYNTHETIC_ERRNO(e), args);
@@
expression e;
expression u;
expression list args;
@@
- log_token_emergency(u, args);
- return -e;
+ return log_token_emergency_errno(u, SYNTHETIC_ERRNO(e), args);
