@@
expression s;
@@
- strv_length(s) == 0
+ strv_isempty(s)
@@
expression s;
@@
- strv_length(s) <= 0
+ strv_isempty(s)
@@
expression s;
@@
- strv_length(s) > 0
+ !strv_isempty(s)
@@
expression s;
@@
- strv_length(s) != 0
+ !strv_isempty(s)
@@
expression s;
@@
- strlen(s) == 0
+ isempty(s)
@@
expression s;
@@
- strlen(s) <= 0
+ isempty(s)
@@
expression s;
@@
- strlen(s) > 0
+ !isempty(s)
@@
expression s;
@@
- strlen(s) != 0
+ !isempty(s)
@@
expression s;
@@
- strlen_ptr(s) == 0
+ isempty(s)
@@
expression s;
@@
- strlen_ptr(s) <= 0
+ isempty(s)
@@
expression s;
@@
- strlen_ptr(s) > 0
+ !isempty(s)
@@
expression s;
@@
- strlen_ptr(s) != 0
+ !isempty(s)
