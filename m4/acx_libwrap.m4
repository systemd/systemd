AC_DEFUN([ACX_LIBWRAP], [
LIBWRAP_LIBS=
saved_LIBS="$LIBS"
LIBS="$LIBS -lwrap"
AC_MSG_CHECKING([for tcpwrap library and headers])
AC_LINK_IFELSE(
[AC_LANG_PROGRAM(
[#include <tcpd.h>
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;],
[struct request_info *req;
return hosts_access (req);])],
[AC_DEFINE(HAVE_LIBWRAP, [], [Have tcpwrap?])
LIBWRAP_LIBS="-lwrap"
AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)])
LIBS="$saved_LIBS"
])
