/**
 * vi: sw=2 ts=2 et syntax=ql:
 *
 * Based on cpp/uninitialized-local.
 *
 * @name Potentially uninitialized local variable using the cleanup attribute
 * @description Running the cleanup handler on a possibly uninitialized variable
 *              is generally a bad idea.
 * @id cpp/uninitialized-local-with-cleanup
 * @kind problem
 * @problem.severity error
 * @precision high
 * @tags security
 */

import cpp
import semmle.code.cpp.controlflow.StackVariableReachability

/**
 * Auxiliary predicate: Types that don't require initialization
 * before they are used, since they're stack-allocated.
 */
predicate allocatedType(Type t) {
  /* Arrays: "int foo[1]; foo[0] = 42;" is ok. */
  t instanceof ArrayType
  or
  /* Structs: "struct foo bar; bar.baz = 42" is ok. */
  t instanceof Class
  or
  /* Typedefs to other allocated types are fine. */
  allocatedType(t.(TypedefType).getUnderlyingType())
  or
  /* Type specifiers don't affect whether or not a type is allocated. */
  allocatedType(t.getUnspecifiedType())
}

/**
 * A declaration of a local variable using __attribute__((__cleanup__(x)))
 * that leaves the variable uninitialized.
 */
DeclStmt declWithNoInit(LocalVariable v) {
  result.getADeclaration() = v and
  not exists(v.getInitializer()) and
  /* The variable has __attribute__((__cleanup__(...))) set */
  v.getAnAttribute().hasName("cleanup") and
  /* The type of the variable is not stack-allocated. */
  exists(Type t | t = v.getType() | not allocatedType(t))
}

class UninitialisedLocalReachability extends StackVariableReachability {
  UninitialisedLocalReachability() { this = "UninitialisedLocal" }

  override predicate isSource(ControlFlowNode node, StackVariable v) { node = declWithNoInit(v) }

  /* Note: _don't_ use the `useOfVarActual()` predicate here (and a couple of lines
   * below), as it assumes that the callee always modifies the variable if
   * it's passed to the function.
   *
   * i.e.:
   * _cleanup_free char *x;
   * fun(&x);
   * puts(x);
   *
   * `useOfVarActual()` won't treat this an an uninitialized read even if the callee
   * doesn't modify the argument, however, `useOfVar()` will
   */
  override predicate isSink(ControlFlowNode node, StackVariable v) { useOfVar(v, node) }

  override predicate isBarrier(ControlFlowNode node, StackVariable v) {
    // only report the _first_ possibly uninitialized use
    useOfVar(v, node) or
    definitionBarrier(v, node)
  }
}

pragma[noinline]
predicate containsInlineAssembly(Function f) { exists(AsmStmt s | s.getEnclosingFunction() = f) }

/**
 * Auxiliary predicate: List common exceptions or false positives
 * for this check to exclude them.
 */
VariableAccess commonException() {
  // If the uninitialized use we've found is in a macro expansion, it's
  // typically something like va_start(), and we don't want to complain.
  result.getParent().isInMacroExpansion()
  or
  result.getParent() instanceof BuiltInOperation
  or
  // Finally, exclude functions that contain assembly blocks. It's
  // anyone's guess what happens in those.
  containsInlineAssembly(result.getEnclosingFunction())
}

from UninitialisedLocalReachability r, LocalVariable v, VariableAccess va
where
  r.reaches(_, v, va) and
  not va = commonException()
select va, "The variable $@ may not be initialized here, but has a cleanup handler.", v, v.getName()
