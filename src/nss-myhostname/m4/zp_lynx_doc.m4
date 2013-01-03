dnl Macro for enabling LYNX-based documentation generation

AC_DEFUN([ZP_LYNX_DOC], [
  AC_ARG_ENABLE(lynx,
     AS_HELP_STRING([--disable-lynx],
        [Turn off lynx usage for documentation generation]),,
     [enable_lynx=yes])

  case "${enable_lynx}" in
    yes)
      AC_CHECK_PROG(have_lynx, lynx, yes, no)

      if test x$have_lynx = xno ; then
         AC_MSG_WARN([*** lynx not found, plain text README will not be built ***])
      fi
      ;;
    no)
      have_lynx=no ;;
    *)
      AC_MSG_ERROR(bad value ${enableval} for --disable-lynx) ;;
  esac

  AM_CONDITIONAL([USE_LYNX], [test "x$have_lynx" = xyes])
])
