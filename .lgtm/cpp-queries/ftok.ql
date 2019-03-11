/**
 * @name Use of ftok()
 * @description ftok() is unsafe to call. Use extract_first_word() instead.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/ftok
 * @tags reliability
 *       security
 */
import cpp

predicate dangerousFunction(Function function) {
  exists (string name | name = function.getQualifiedName() |
    name = "ftok")
}

from FunctionCall call, Function target
where call.getTarget() = target
  and dangerousFunction(target)
select call, target.getQualifiedName() + " is potentially dangerous"
