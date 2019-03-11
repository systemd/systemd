/**
 * @name Use of potentially dangerous function
 * @description Certain standard library functions are dangerous to call.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/potentially-dangerous-function
 * @tags reliability
 *       security
 *
 * Borrowed from
 * https://github.com/Semmle/ql/blob/master/cpp/ql/src/Security/CWE/CWE-676/PotentiallyDangerousFunction.ql
 */
import cpp

predicate potentiallyDangerousFunction(Function f, string message) {
  (
    f.getQualifiedName() = "fgets" and
    message = "Call to fgets is potentially dangerous. Use read_line() instead."
  ) or (
    f.getQualifiedName() = "strtok" and
    message = "Call to strtok is potentially dangerous. Use extract_first_word() instead."
  )
}

from FunctionCall call, Function target, string message
where
  call.getTarget() = target and
  potentiallyDangerousFunction(target, message)
select call, message
