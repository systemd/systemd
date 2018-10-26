/**
 * @name Use of fgets()
 * @description fgets() is dangerous to call. Use read_line() instead.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/fgets
 * @tags reliability
 *       security
 */
import cpp

predicate dangerousFunction(Function function) {
  exists (string name | name = function.getQualifiedName() |
    name = "fgets")
}

from FunctionCall call, Function target
where call.getTarget() = target
  and dangerousFunction(target)
select call, target.getQualifiedName() + " is potentially dangerous"
