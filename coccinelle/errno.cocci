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
