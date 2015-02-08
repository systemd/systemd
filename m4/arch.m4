
dnl SET_ARCH(ARCHNAME, PATTERN)
dnl
dnl Define ARCH_<archname> condition if the pattern match with the current
dnl architecture
dnl
AC_DEFUN([SET_ARCH], [
  cpu_$1=false
  case "$host" in
   $2) cpu_$1=true ;;
  esac
  AM_CONDITIONAL(AS_TR_CPP(ARCH_$1), [test "x$cpu_$1" = xtrue])
])
