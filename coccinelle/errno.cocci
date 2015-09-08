@@
identifier r;
expression t, e;
@@
- r = -e;
- log_error_errno(e, t);
+ r = log_error_errno(e, t);
@@
identifier r;
expression t, e;
@@
- log_error_errno(e, t);
- r = -e;
+ r = log_error_errno(e, t);
@@
identifier r;
expression t, e;
@@
- r = log_error_errno(e, t);
- return r;
+ return log_error_errno(e, t);
@@
identifier r;
expression t, e;
@@
- r = -e;
- log_warning_errno(e, t);
+ r = log_warning_errno(e, t);
@@
identifier r;
expression t, e;
@@
- log_warning_errno(e, t);
- r = -e;
+ r = log_warning_errno(e, t);
@@
identifier r;
expression t, e;
@@
- r = log_warning_errno(e, t);
- return r;
+ return log_warning_errno(e, t);
