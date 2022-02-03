/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
@@
- r = -e;
+ r =
  log_LEVEL_errno(e, ...);
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
@@
+ r =
  log_LEVEL_errno(e, ...);
- r = -e;
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
@@
- r =
+ return
  log_LEVEL_errno(e, ...);
- return r;
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
@@
+ return
  log_LEVEL_errno(r, ...);
- return r;
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
expression e;
@@
+ return
  log_LEVEL_errno(e, ...);
- return -e;
@@
identifier log_LEVEL_errno =~ "^log_(debug|info|notice|warning|error|emergency)_errno$";
expression list args;
expression e;
local idexpression r;
@@
- log_LEVEL_errno(e, args);
- r = e;
+ r = log_LEVEL_errno(e, args);
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
expression u;
@@
- r = -e;
+ r =
  log_UNIT_LEVEL_errno(u, e, ...);
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
expression u;
@@
+ r =
  log_UNIT_LEVEL_errno(u, e, ...);
- r = -e;
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression e;
expression u;
@@
- r =
+ return
  log_UNIT_LEVEL_errno(u, e, ...);
- return r;
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
local idexpression r;
expression u;
@@
+ return
  log_UNIT_LEVEL_errno(u, r, ...);
- return r;
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
expression e;
expression u;
@@
+ return
  log_UNIT_LEVEL_errno(u, e, ...);
- return -e;
@@
identifier log_UNIT_LEVEL_errno =~ "^log_(unit|link|netdev|device|token)_(debug|info|notice|warning|error|emergency)_errno$";
expression list args;
expression e;
expression u;
local idexpression r;
@@
- log_UNIT_LEVEL_errno(u, e, args);
- r = e;
+ r = log_UNIT_LEVEL_errno(u, e, args);
