@@
identifier r;
expression e;
@@
- r = -e;
- log_error_errno(e,
+ r = log_error_errno(e,
  ...);
@@
identifier r;
expression e;
@@
- log_error_errno(e,
+ r = log_error_errno(e,
  ...);
- r = -e;
@@
identifier r;
expression e;
@@
- r = log_error_errno(e,
+ return log_error_errno(e,
  ...);
- return r;
@@
identifier r;
expression e;
@@
- r = -e;
- log_warning_errno(e,
+ r = log_warning_errno(e,
  ...);
@@
identifier r;
expression e;
@@
- log_warning_errno(e,
+ r = log_warning_errno(e,
  ...);
- r = -e;
@@
identifier r;
expression e;
@@
- r = log_warning_errno(e,
+ return log_warning_errno(e,
  ...);
- return r;
