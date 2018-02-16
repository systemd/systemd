/***
  This semantic patch may cause more problems than it solves.
  It is strongly recommended that https://github.com/systemd/systemd/issues/4534
  and https://github.com/systemd/systemd/pull/8203 should be read first.
***/

virtual I_still_want_systemd_to_crash

@depends on I_still_want_systemd_to_crash@
expression e, fmt;
expression list vaargs;
@@
- snprintf(e, sizeof(e), fmt, vaargs);
+ xsprintf(e, fmt, vaargs);
