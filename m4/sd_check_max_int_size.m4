dnl Find what INT_MAX define to use for a type

#serial 1

ifdef([AC_TR_SH],[], [
define([AC_TR_SH],
       [patsubst(translit([[$1]], [*+], [pp]), [[^a-zA-Z0-9_]], [_])])
define([AC_TR_CPP],
       [patsubst(translit([[$1]],
                          [*abcdefghijklmnopqrstuvwxyz],
                          [PABCDEFGHIJKLMNOPQRSTUVWXYZ]),
                 [[^A-Z0-9_]], [_])])
])

AC_DEFUN([SD_CHECK_MAX_INT_SIZE],
        [AC_CHECK_SIZEOF([long],,)
         AC_CHECK_SIZEOF([long long],,)
         AC_CHECK_SIZEOF([$1],,[$2])
         AS_CASE([$ac_cv_sizeof_[]AC_TR_SH($1)],
                 [$ac_cv_sizeof_long], [sd_type_max=LONG_MAX],
                 [$ac_cv_sizeof_long_long], [sd_type_max=LONG_LONG_MAX],
                 [AC_MSG_ERROR([Don't know how to map $1 to an integer])])
         AC_DEFINE_UNQUOTED(AC_TR_CPP($1_MAX), [$sd_type_max],
                   [what int to use to maximize $1])
         AC_MSG_CHECKING([what int to to use to maximize $1])
         AC_MSG_RESULT([$sd_type_max])
])
