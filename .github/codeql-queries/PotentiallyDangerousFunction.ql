/**
 * vi: sw=2 ts=2 et syntax=ql:
 *
 * Borrowed from
 * https://github.com/Semmle/ql/blob/master/cpp/ql/src/Security/CWE/CWE-676/PotentiallyDangerousFunction.ql
 *
 * @name Use of potentially dangerous function
 * @description Certain standard library functions are dangerous to call.
 * @id cpp/potentially-dangerous-function
 * @kind problem
 * @problem.severity error
 * @precision high
 * @tags reliability
 *       security
 */
import cpp

predicate potentiallyDangerousFunction(Function f, string message) {
  (
    f.getQualifiedName() = "fgets" and
    message = "Call to fgets() is potentially dangerous. Use read_line() instead."
  ) or (
    f.getQualifiedName() = "strtok" and
    message = "Call to strtok() is potentially dangerous. Use extract_first_word() instead."
  ) or (
    f.getQualifiedName() = "strsep" and
    message = "Call to strsep() is potentially dangerous. Use extract_first_word() instead."
  ) or (
    f.getQualifiedName() = "dup" and
    message = "Call to dup() is potentially dangerous. Use fcntl(fd, FD_DUPFD_CLOEXEC, 3) instead."
  ) or (
    f.getQualifiedName() = "htonl" and
    message = "Call to htonl() is confusing. Use htobe32() instead."
  ) or (
    f.getQualifiedName() = "htons" and
    message = "Call to htons() is confusing. Use htobe16() instead."
  ) or (
    f.getQualifiedName() = "ntohl" and
    message = "Call to ntohl() is confusing. Use be32toh() instead."
  ) or (
    f.getQualifiedName() = "ntohs" and
    message = "Call to ntohs() is confusing. Use be16toh() instead."
  ) or (
    f.getQualifiedName() = "strerror" and
    message = "Call to strerror() is not thread-safe. Use printf()'s %m format string or STRERROR() instead."
  ) or (
    f.getQualifiedName() = "accept" and
    message = "Call to accept() is not O_CLOEXEC-safe. Use accept4() instead."
  ) or (
    f.getQualifiedName() = "dirname" and
    message = "Call dirname() is icky. Use path_extract_directory() instead."
  )
}

from FunctionCall call, Function target, string message
where
  call.getTarget() = target and
  potentiallyDangerousFunction(target, message)
select call, message
