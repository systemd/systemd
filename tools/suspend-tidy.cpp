/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <algorithm>
#include <deque>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <clang-tidy/ClangTidyCheck.h>
#include <clang-tidy/ClangTidyModule.h>
#include <clang-tidy/utils/OptionsUtils.h>
#include <clang/AST/Attr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Analysis/AnalysisDeclContext.h>
#include <clang/Analysis/Analyses/ExprMutationAnalyzer.h>
#include <clang/Analysis/Analyses/LiveVariables.h>
#include <clang/Analysis/CFG.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/Builtins.h>
#include <clang/Lex/Lexer.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/Transformer/SourceCode.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Support/SaveAndRestore.h>

namespace systemd::suspend {

using namespace clang;

/* The values are ordered from the strongest to the weakest guarantee. A value can be stored in a slot
 * whose contract is the same or weaker. */
enum class Contract { Sync, MaySuspend, Unchecked };

static const char *contractName(Contract contract) {
        switch (contract) {
        case Contract::Sync:
                return "_sync_";
        case Contract::MaySuspend:
                return "_may_suspend_";
        case Contract::Unchecked:
                return "unchecked";
        }
        return "";
}

/* A missing contract describes a value that isn't a function pointer, such as a void pointer. Converting
 * such a value to a function pointer is a trusted boundary. */
static std::optional<Contract> join(std::optional<Contract> a, std::optional<Contract> b) {
        if (!a)
                return b;
        if (!b)
                return a;
        return std::max(*a, *b);
}

struct Annotations {
        /* Clang doesn't mark the attributes that a pragma adds, so SYNC_BEGIN adds a separate
         * "sd:sync_default" annotation. An explicit _may_suspend_ or _suspend_ overrides the default
         * instead of conflicting with it. */
        bool maySuspend = false, suspend = false, sync = false, syncDefault = false;
        bool scoped = false;

        void add(const Decl *decl) {
                for (const auto *attribute : decl->specific_attrs<AnnotateAttr>()) {
                        if (attribute->getAnnotation() == "sd:may_suspend")
                                maySuspend = true;
                        else if (attribute->getAnnotation() == "sd:suspend")
                                suspend = true;
                        else if (attribute->getAnnotation() == "sd:sync")
                                sync = true;
                        else if (attribute->getAnnotation() == "sd:sync_default")
                                syncDefault = true;
                        else if (attribute->getAnnotation() == "sd:scoped_callback")
                                scoped = true;
                }
        }

        void add(Contract contract) {
                maySuspend |= contract == Contract::MaySuspend;
                sync |= contract == Contract::Sync;
        }

        /* A _suspend_ function can suspend like a _may_suspend_ function. checkDeclarations() reports
         * conflicting declarations. The other checks use the weaker contract. */
        std::optional<Contract> contract() const {
                if (maySuspend || suspend)
                        return Contract::MaySuspend;
                if (sync || syncDefault)
                        return Contract::Sync;
                return {};
        }
};

static bool hasAnnotation(const Decl *decl, llvm::StringRef name) {
        for (const auto *attribute : decl->specific_attrs<AnnotateAttr>())
                if (attribute->getAnnotation() == name)
                        return true;
        return false;
}

static bool scopeAnnotation(const StmtExpr *statement, llvm::StringRef name) {
        if (!statement)
                return false;
        for (const auto *child : statement->getSubStmt()->body())
                if (const auto *declarations = dyn_cast<DeclStmt>(child))
                        for (const auto *decl : declarations->decls())
                                if (hasAnnotation(decl, name))
                                        return true;
        return false;
}

/* SD_AWAIT(call) expands to a comma expression whose left operand declares the marker. */
static const CallExpr *awaitedCall(const BinaryOperator *binary) {
        if (!binary->isCommaOp() || !scopeAnnotation(dyn_cast<StmtExpr>(binary->getLHS()->IgnoreParenCasts()), "sd:await"))
                return nullptr;
        return dyn_cast<CallExpr>(binary->getRHS()->IgnoreParenImpCasts());
}

static bool skipTranslationUnit(const SourceManager &sm, Preprocessor &preprocessor) {
        auto path = sm.getFileEntryRefForID(sm.getMainFileID())->getName();
        auto *boot = preprocessor.getMacroInfo(preprocessor.getIdentifierInfo("SD_BOOT"));
        return path.contains("/src/boot/") || path.ends_with(".bpf.c") ||
                (boot && boot->getNumTokens() == 1 && preprocessor.getSpelling(boot->getReplacementToken(0)) == "1");
}

/* Pointers and arrays of function pointers count as callback types too, because their elements are
 * callback slots. */
static bool isCallbackType(QualType type) {
        while (!type.isNull()) {
                type = type.getCanonicalType();
                if (type->isFunctionType())
                        return true;
                if (type->isPointerType())
                        type = type->getPointeeType();
                else if (const auto *array = type->getAsArrayTypeUnsafe())
                        type = array->getElementType();
                else
                        return false;
        }
        return false;
}

/* A Call is either a call in a function body or the cleanup of a local variable. */
struct Call {
        const CallExpr *expression = nullptr;
        const FunctionDecl *cleanup = nullptr;
        /* cleanupCallback is the callback that a generic cleanup function like array_cleanup() invokes. */
        const Expr *cleanupCallback = nullptr;
        SourceLocation location;
        bool awaited = false;
        bool blocking = false;
        /* The await marker comes from the body of another macro, like DEFINE_TRIVIAL_CLEANUP_FUNC(). */
        bool generic = false;
        /* The call goes through a scoped callback that the caller received as an argument. The checker
         * includes the contract of that callback at the calls of the caller instead. */
        bool forwarded = false;
        /* anchor is the statement whose position in the control flow graph is the position of the call:
         * the call expression, or the initializer of a variable with a cleanup. */
        const Stmt *anchor = nullptr;
        /* addMarker contains the fix-its that add a missing await marker. removeMarker contains the fix-its
         * that remove an unnecessary marker. The visitor leaves addMarker and removeMarker empty when the
         * call or the marker comes from a macro body, because an edit there changes every expansion. */
        std::vector<FixItHint> addMarker, removeMarker;
};

/* A Flow is a function pointer value that is stored in a slot with a declared contract. */
struct Flow {
        const Expr *value;
        Contract slot;
        std::string slotName;
        SourceLocation location;
};

class Analysis {
public:
        Analysis(clang::tidy::ClangTidyCheck &check, ASTContext &context)
                : check(check), context(context), sm(context.getSourceManager()), cfgs(context) {
                /* By default, the CFG leaves out most subexpressions. guarded() looks up each call among the
                 * elements of its block, so the CFG has to contain every statement. */
                cfgs.getCFGBuildOptions().setAllAlwaysAdd();
        }

        clang::tidy::ClangTidyCheck &check;
        ASTContext &context;
        SourceManager &sm;

        /* The calls of each function definition. A deque keeps the call lists in place while the visitor
         * appends new definitions. */
        std::deque<std::pair<const FunctionDecl *, std::vector<Call>>> bodies;
        std::vector<Flow> flows;
        std::vector<const FunctionDecl *> declarations;
        llvm::DenseMap<const FunctionDecl *, Contract> inferred;
        /* weakenedBy maps each inferred unchecked function to the first call that made it
         * unchecked. The inference made the callee of that call unchecked in an earlier step.
         * Following the calls in weakenedBy therefore never loops. */
        llvm::DenseMap<const FunctionDecl *, const Call *> weakenedBy;
        mutable llvm::DenseMap<const FunctionDecl *, std::unique_ptr<ExprMutationAnalyzer>> mutations;
        mutable llvm::DenseMap<const VarDecl *, bool> unmodified;
        mutable llvm::DenseMap<const RecordDecl *, bool> scopedRecords;
        /* suspendBy maps each function whose body requires a fiber to the first call that requires one.
         * The callee of that call required a fiber in an earlier step, like in weakenedBy. */
        llvm::DenseMap<const FunctionDecl *, const Call *> suspendBy;
        mutable AnalysisDeclContextManager cfgs;
        mutable llvm::DenseMap<const FunctionDecl *, std::unique_ptr<llvm::DenseSet<const Stmt *>>> guardedStatements;

        /* pkg-config adds the include directories of some libraries, like libmount and blkid, with -I
         * instead of -isystem. Clang doesn't consider their headers system headers. */
        bool isSystem(const Decl *decl) const {
                auto location = decl->getLocation();
                if (location.isInvalid() || sm.isInSystemHeader(location))
                        return true;
                return sm.getFilename(sm.getExpansionLoc(location)).starts_with("/usr/include/");
        }

        std::optional<Contract> annotatedContract(const FunctionDecl *function) const {
                Annotations annotations;
                for (const auto *redeclaration : function->redecls())
                        annotations.add(redeclaration);
                return annotations.contract();
        }

        /* PAM modules define functions that libpam declares, so a declaration in a system header alone
         * doesn't make a function native. */
        bool isNative(const FunctionDecl *function) const {
                if (function->getBuiltinID() != 0)
                        return true;
                if (!isSystem(function->getCanonicalDecl()))
                        return false;
                const auto *definition = function->getDefinition();
                return !definition || isSystem(definition);
        }

        /* Calls into system libraries and functions declared pure or const are trusted not to suspend.
         * Their bodies aren't checked. */
        std::optional<Contract> declaredContract(const FunctionDecl *function) const {
                if (auto contract = annotatedContract(function))
                        return contract;
                if (function->hasAttr<PureAttr>() || function->hasAttr<ConstAttr>() || isNative(function))
                        return Contract::Sync;
                return {};
        }

        Contract functionContract(const FunctionDecl *function) const {
                if (auto contract = declaredContract(function))
                        return *contract;
                auto found = inferred.find(function->getCanonicalDecl());
                return found != inferred.end() ? found->second : Contract::Unchecked;
        }

        /* The annotations of a type come from its typedefs and from the declarations that typeof() refers to. */
        void typeAnnotations(QualType type, Annotations &annotations) const {
                if (type.isNull())
                        return;
                const Type *t = type.getTypePtr();
                if (const auto *alias = dyn_cast<TypedefType>(t)) {
                        annotations.add(alias->getDecl());
                        typeAnnotations(alias->getDecl()->getUnderlyingType(), annotations);
                        return;
                }
                if (const auto *typeOf = dyn_cast<TypeOfExprType>(t)) {
                        const Expr *expression = typeOf->getUnderlyingExpr()->IgnoreParenImpCasts();
                        while (const auto *unary = dyn_cast<UnaryOperator>(expression)) {
                                if (unary->getOpcode() != UO_AddrOf && unary->getOpcode() != UO_Deref)
                                        break;
                                expression = unary->getSubExpr()->IgnoreParenImpCasts();
                        }
                        if (const auto *reference = dyn_cast<DeclRefExpr>(expression)) {
                                /* DLSYM_PROTOTYPE() declares a pointer with the type of the library function. */
                                if (const auto *function = dyn_cast<FunctionDecl>(reference->getDecl())) {
                                        if (auto contract = declaredContract(function))
                                                annotations.add(*contract);
                                } else
                                        annotations.add(reference->getDecl());
                        }
                }
                auto desugared = type->getLocallyUnqualifiedSingleStepDesugaredType();
                if (desugared.getTypePtr() != t)
                        typeAnnotations(desugared, annotations);
                else if (type->isPointerType())
                        typeAnnotations(type->getPointeeType(), annotations);
                else if (const auto *array = dyn_cast<ArrayType>(t))
                        typeAnnotations(array->getElementType(), annotations);
        }

        std::optional<Contract> typeContract(QualType type) const {
                Annotations annotations;
                typeAnnotations(type, annotations);
                return annotations.contract();
        }

        bool isScopedCallback(QualType type) const {
                if (!type->isFunctionPointerType())
                        return false;
                Annotations annotations;
                typeAnnotations(type, annotations);
                return annotations.scoped;
        }

        /* A table, like the dispatch table of sd_json_dispatch(), is an array of structures with a scoped
         * callback field. A parameter is a table when it is declared as an array. A pointer to a single
         * entry, like the entry that sd_json_dispatch() is processing, is not a table. */
        bool isScopedTable(QualType type) const {
                if (const auto *decayed = type->getAs<DecayedType>())
                        type = decayed->getOriginalType();
                if (!type->isArrayType())
                        return false;
                const auto *record = context.getBaseElementType(type)->getAsRecordDecl();
                if (!record || !record->getDefinition())
                        return false;
                record = record->getDefinition();
                auto [found, inserted] = scopedRecords.try_emplace(record, false);
                if (!inserted)
                        return found->second;
                bool result = llvm::any_of(record->fields(), [&](const FieldDecl *field) {
                        return isScopedCallback(field->getType());
                });
                scopedRecords[record] = result;
                return result;
        }

        /* A function that receives scoped callbacks can call them. The checker includes the contracts of the
         * callbacks at the calls of the function instead. */
        bool receivesScopedCallbacks(const FunctionDecl *function) const {
                if (function->isVariadic())
                        return true;
                return llvm::any_of(function->parameters(), [&](const ParmVarDecl *parameter) {
                        return isScopedCallback(parameter->getType()) || isScopedTable(parameter->getOriginalType()) ||
                                context.hasSameType(parameter->getOriginalType(), context.getBuiltinVaListType());
                });
        }

        struct ScopedCallbacks {
                std::vector<const Expr *> callbacks;
                /* unknown is the first table argument whose initializer isn't visible at the call. */
                const Expr *unknown = nullptr;
        };

        void scopedInitializer(const Expr *value, ScopedCallbacks &scoped) const {
                value = value->IgnoreParenImpCasts();
                if (const auto *literal = dyn_cast<CompoundLiteralExpr>(value))
                        value = literal->getInitializer()->IgnoreParenImpCasts();
                const auto *list = dyn_cast<InitListExpr>(value);
                if (!list)
                        return;
                if (list->isSyntacticForm() && list->getSemanticForm())
                        list = list->getSemanticForm();
                const auto *record = list->getType()->getAsRecordDecl();
                if (!record) {
                        for (const auto *element : list->inits())
                                scopedInitializer(element, scoped);
                        return;
                }
                unsigned i = 0;
                for (const auto *field : record->fields()) {
                        if (record->isUnion() && field != list->getInitializedFieldInUnion())
                                continue;
                        if (i >= list->getNumInits())
                                break;
                        const auto *initializer = list->getInit(i++);
                        if (isScopedCallback(field->getType()))
                                scoped.callbacks.push_back(initializer);
                        else
                                scopedInitializer(initializer, scoped);
                }
        }

        void scopedTable(const Expr *argument, ScopedCallbacks &scoped) const {
                if (argument->isNullPointerConstant(context, Expr::NPC_ValueDependentIsNotNull))
                        return;
                /* A pointer into a table, like table + 1 or &table[1], points at a subset of the entries of
                 * the table. The checker uses the callbacks of the whole table. */
                const Expr *value = argument;
                for (;;) {
                        value = value->IgnoreParenCasts();
                        if (const auto *unary = dyn_cast<UnaryOperator>(value); unary && unary->getOpcode() == UO_AddrOf)
                                value = unary->getSubExpr();
                        else if (const auto *subscript = dyn_cast<ArraySubscriptExpr>(value))
                                value = subscript->getBase();
                        else if (const auto *binary = dyn_cast<BinaryOperator>(value); binary && binary->isAdditiveOp())
                                value = binary->getLHS()->getType()->isPointerType() ? binary->getLHS() : binary->getRHS();
                        else
                                break;
                }
                if (const auto *reference = dyn_cast<DeclRefExpr>(value)) {
                        /* The checker includes the callbacks of a table parameter at the calls of the caller. */
                        if (isa<ParmVarDecl>(reference->getDecl()))
                                return;
                        if (const auto *variable = dyn_cast<VarDecl>(reference->getDecl()); variable && variable->getInit())
                                return scopedInitializer(variable->getInit(), scoped);
                } else if (isa<CompoundLiteralExpr>(value))
                        return scopedInitializer(value, scoped);
                if (!scoped.unknown)
                        scoped.unknown = argument;
        }

        ScopedCallbacks scopedCallbacks(const CallExpr *expression) const {
                ScopedCallbacks scoped;
                QualType callee = expression->getCallee()->getType();
                if (callee->isPointerType())
                        callee = callee->getPointeeType();
                const auto *prototype = callee->getAs<FunctionProtoType>();
                for (unsigned i = 0; i < expression->getNumArgs(); i++) {
                        const auto *argument = expression->getArg(i);
                        /* The conversion of a function name to a pointer drops the typedef of the parameter. */
                        QualType type = prototype && i < prototype->getNumParams() ? prototype->getParamType(i) : argument->getType();
                        if (isScopedCallback(type)) {
                                const auto *reference = dyn_cast<DeclRefExpr>(argument->IgnoreParenCasts());
                                if (!reference || !isa<ParmVarDecl>(reference->getDecl()))
                                        scoped.callbacks.push_back(argument);
                        } else if (isScopedTable(type))
                                scopedTable(argument, scoped);
                }
                return scoped;
        }

        Contract scopedContract(const ScopedCallbacks &scoped) const {
                Contract result = scoped.unknown ? Contract::Unchecked : Contract::Sync;
                for (const auto *callback : scoped.callbacks)
                        result = std::max(result, valueContract(callback).value_or(Contract::Unchecked));
                return result;
        }

        std::optional<Contract> declContract(const ValueDecl *decl) const {
                Annotations annotations;
                annotations.add(decl);
                if (const auto *variable = dyn_cast<VarDecl>(decl))
                        for (const auto *redeclaration : variable->redecls())
                                annotations.add(redeclaration);
                /* Parameter annotations are usually only spelled on the declaration in the header. */
                if (const auto *parameter = dyn_cast<ParmVarDecl>(decl))
                        if (const auto *function = dyn_cast<FunctionDecl>(parameter->getDeclContext()))
                                for (const auto *redeclaration : function->redecls())
                                        if (parameter->getFunctionScopeIndex() < redeclaration->getNumParams())
                                                annotations.add(redeclaration->getParamDecl(parameter->getFunctionScopeIndex()));
                typeAnnotations(decl->getType(), annotations);
                return annotations.contract();
        }

        std::optional<Contract> slotContract(const ValueDecl *decl) const {
                if (auto contract = declContract(decl))
                        return contract;
                if (isCallbackType(decl->getType()))
                        return Contract::Unchecked;
                return {};
        }

        std::optional<Contract> valueContract(const Expr *expression) const {
                expression = expression->IgnoreParens();
                if (isa<ImplicitValueInitExpr>(expression) ||
                    expression->isNullPointerConstant(context, Expr::NPC_ValueDependentIsNotNull))
                        return Contract::Sync;
                if (const auto *cast = dyn_cast<CastExpr>(expression)) {
                        /* A void pointer has no contract, also when it was cast from a function pointer. */
                        if (!isCallbackType(cast->getType()))
                                return {};
                        if (const auto *written = dyn_cast<ExplicitCastExpr>(cast))
                                if (auto contract = typeContract(written->getTypeAsWritten()))
                                        return contract;
                        return valueContract(cast->getSubExpr());
                }
                if (const auto *reference = dyn_cast<DeclRefExpr>(expression)) {
                        if (const auto *function = dyn_cast<FunctionDecl>(reference->getDecl()))
                                return functionContract(function);
                        if (const auto *variable = dyn_cast<VarDecl>(reference->getDecl()); variable && isUnmodified(variable))
                                return valueContract(variable->getInit());
                        return slotContract(reference->getDecl());
                }
                if (const auto *member = dyn_cast<MemberExpr>(expression))
                        return slotContract(member->getMemberDecl());
                if (const auto *subscript = dyn_cast<ArraySubscriptExpr>(expression))
                        return valueContract(subscript->getBase());
                if (const auto *unary = dyn_cast<UnaryOperator>(expression))
                        if (unary->getOpcode() == UO_AddrOf || unary->getOpcode() == UO_Deref)
                                return valueContract(unary->getSubExpr());
                if (const auto *conditional = dyn_cast<ConditionalOperator>(expression))
                        return join(valueContract(conditional->getTrueExpr()), valueContract(conditional->getFalseExpr()));
                if (const auto *conditional = dyn_cast<BinaryConditionalOperator>(expression))
                        return join(valueContract(conditional->getCommon()), valueContract(conditional->getFalseExpr()));
                if (const auto *binary = dyn_cast<BinaryOperator>(expression))
                        if (binary->isCommaOp() || binary->getOpcode() == BO_Assign)
                                return valueContract(binary->getRHS());
                if (const auto *statement = dyn_cast<StmtExpr>(expression))
                        if (const auto *last = dyn_cast_or_null<Expr>(statement->getSubStmt()->body_back()))
                                return valueContract(last);
                if (const auto *choose = dyn_cast<ChooseExpr>(expression))
                        return valueContract(choose->getChosenSubExpr());
                if (const auto *literal = dyn_cast<CompoundLiteralExpr>(expression))
                        if (const auto *list = dyn_cast<InitListExpr>(literal->getInitializer()); list && list->getNumInits() == 1)
                                return valueContract(list->getInit(0));
                if (const auto *generic = dyn_cast<GenericSelectionExpr>(expression))
                        return valueContract(generic->getResultExpr());
                if (auto contract = typeContract(expression->getType()))
                        return contract;
                if (isCallbackType(expression->getType()))
                        return Contract::Unchecked;
                return {};
        }

        /* A local function pointer without a contract that never changes after its initialization has
         * the contract of its initializer. */
        bool isUnmodified(const VarDecl *variable) const {
                if (!variable->hasLocalStorage() || isa<ParmVarDecl>(variable) || !variable->getInit() ||
                    !isCallbackType(variable->getType()) || declContract(variable))
                        return false;
                if (variable->getType().isConstQualified())
                        return true;
                const auto *function = dyn_cast<FunctionDecl>(variable->getDeclContext());
                if (!function || !function->getBody())
                        return false;
                auto [found, inserted] = unmodified.try_emplace(variable, false);
                if (!inserted)
                        return found->second;
                auto &analyzer = mutations[function];
                if (!analyzer)
                        analyzer = std::make_unique<ExprMutationAnalyzer>(*function->getBody(), context);
                bool result = !analyzer->isMutated(variable);
                unmodified[variable] = result;
                return result;
        }

        /* The local is often a temporary variable in a macro, like _func_ in typesafe_qsort(). Its name
         * doesn't tell the reader which function to annotate. Diagnostics name the function that the
         * local was initialized with instead. */
        const Expr *origin(const Expr *expression) const {
                for (;;) {
                        expression = expression->IgnoreParenCasts();
                        if (const auto *unary = dyn_cast<UnaryOperator>(expression))
                                expression = unary->getSubExpr()->IgnoreParenCasts();
                        const auto *reference = dyn_cast<DeclRefExpr>(expression);
                        const auto *variable = reference ? dyn_cast<VarDecl>(reference->getDecl()) : nullptr;
                        if (!variable || !isUnmodified(variable))
                                return expression;
                        expression = variable->getInit();
                }
        }

        std::string describe(const Expr *expression) const {
                expression = origin(expression);
                if (const auto *reference = dyn_cast<DeclRefExpr>(expression))
                        return "'" + reference->getDecl()->getNameAsString() + "'";
                if (const auto *member = dyn_cast<MemberExpr>(expression))
                        return "'" + member->getMemberDecl()->getNameAsString() + "'";
                return "callback";
        }

        std::string describe(const Call &call) const {
                if (call.cleanup)
                        return "'" + call.cleanup->getNameAsString() + "'";
                return describe(call.expression->getCallee());
        }

        /* A native function can invoke its callback arguments before it returns. */
        bool passesSuspendingCallback(const CallExpr *expression) const {
                for (const auto *argument : expression->arguments())
                        if (isCallbackType(argument->getType()))
                                if (auto contract = valueContract(argument); contract && *contract != Contract::Sync)
                                        return true;
                return false;
        }

        bool isNativeCall(const Call &call) const {
                if (!call.expression)
                        return false;
                const auto *function = call.expression->getDirectCallee();
                return function && !annotatedContract(function) && isNative(function);
        }

        bool declaredSuspend(const FunctionDecl *function) const {
                return llvm::any_of(function->redecls(), [](const FunctionDecl *redeclaration) {
                        return hasAnnotation(redeclaration, "sd:suspend");
                });
        }

        bool isSuspend(const FunctionDecl *function) const {
                return declaredSuspend(function) || suspendBy.contains(function->getCanonicalDecl());
        }

        bool valueSuspend(const Expr *value) const {
                value = origin(value);
                const ValueDecl *decl = nullptr;
                if (const auto *reference = dyn_cast<DeclRefExpr>(value))
                        decl = reference->getDecl();
                else if (const auto *member = dyn_cast<MemberExpr>(value))
                        decl = member->getMemberDecl();
                if (const auto *function = dyn_cast_or_null<FunctionDecl>(decl))
                        return isSuspend(function);
                Annotations annotations;
                if (decl)
                        annotations.add(decl);
                typeAnnotations(value->getType(), annotations);
                return annotations.suspend;
        }

        bool callSuspend(const Call &call) const {
                if (call.cleanupCallback)
                        return valueSuspend(call.cleanupCallback);
                if (call.cleanup)
                        return isSuspend(call.cleanup);
                if (call.forwarded)
                        return false;
                const auto *function = call.expression->getDirectCallee();
                if (function ? isSuspend(function) : valueSuspend(call.expression->getCallee()))
                        return true;
                return llvm::any_of(scopedCallbacks(call.expression).callbacks, [&](const Expr *callback) {
                        return valueSuspend(callback);
                });
        }

        /* A _suspend_guard_ function returns true on a fiber outside a blocking region. guardPolarity()
         * returns whether a condition is true when such a function returned true, or nothing when the
         * condition isn't a call to one. */
        std::optional<bool> guardPolarity(const Stmt *condition) const {
                bool positive = true;
                const auto *expression = dyn_cast_or_null<Expr>(condition);
                while (expression) {
                        expression = expression->IgnoreParenImpCasts();
                        if (const auto *unary = dyn_cast<UnaryOperator>(expression); unary && unary->getOpcode() == UO_LNot) {
                                positive = !positive;
                                expression = unary->getSubExpr();
                                continue;
                        }
                        const auto *call = dyn_cast<CallExpr>(expression);
                        if (!call)
                                return {};
                        /* assert() and _unlikely_() wrap their condition in __builtin_expect(). */
                        if (call->getBuiltinCallee() == Builtin::BI__builtin_expect && call->getNumArgs() > 0) {
                                expression = call->getArg(0);
                                continue;
                        }
                        const auto *function = call->getDirectCallee();
                        if (function && llvm::any_of(function->redecls(), [](const FunctionDecl *redeclaration) {
                                    return hasAnnotation(redeclaration, "sd:suspend_guard");
                            }))
                                return positive;
                        return {};
                }
                return {};
        }

        /* A statement is guarded when every path from the entry of the function to the statement goes
         * through a branch that a _suspend_guard_ function took because it returned true. The analysis
         * computes for each block whether it is only reachable that way. The CFG splits && and || into
         * separate branches, so each branch condition is at most a single guard call. */
        const llvm::DenseSet<const Stmt *> &guarded(const FunctionDecl *function) const {
                auto &result = guardedStatements[function];
                if (result)
                        return *result;
                result = std::make_unique<llvm::DenseSet<const Stmt *>>();

                const CFG *cfg = cfgs.getContext(function)->getCFG();
                if (!cfg)
                        return *result;

                auto edge = [&](const std::vector<bool> &in, const CFGBlock *from, const CFGBlock *to) {
                        auto polarity = guardPolarity(from->getTerminatorCondition());
                        if (!polarity || from->succ_size() != 2)
                                return bool(in[from->getBlockID()]);
                        bool taken = from->succ_begin()->getReachableBlock() == to;
                        return taken ? *polarity : !*polarity;
                };

                std::vector<bool> in(cfg->getNumBlockIDs(), true);
                in[cfg->getEntry().getBlockID()] = false;
                bool changed;
                do {
                        changed = false;
                        for (const CFGBlock *block : *cfg) {
                                if (block == &cfg->getEntry())
                                        continue;
                                bool value = true;
                                for (const auto &predecessor : block->preds())
                                        if (const CFGBlock *from = predecessor.getReachableBlock())
                                                value = value && edge(in, from, block);
                                if (value != in[block->getBlockID()]) {
                                        in[block->getBlockID()] = value;
                                        changed = true;
                                }
                        }
                } while (changed);

                for (const CFGBlock *block : *cfg)
                        if (in[block->getBlockID()])
                                for (const auto &element : *block)
                                        if (auto statement = element.getAs<CFGStmt>())
                                                result->insert(statement->getStmt());
                return *result;
        }

        bool isGuarded(const FunctionDecl *function, const Call &call) const {
                return call.anchor && guarded(function).contains(call.anchor);
        }

        /* A function requires a fiber when its body calls a function that requires one, outside a blocking
         * region and without a guard. Blocking regions don't count, because checkBody() reports calls in
         * them separately. */
        void inferSuspend() {
                bool changed;
                do {
                        changed = false;
                        for (const auto &[function, calls] : bodies) {
                                if (suspendBy.contains(function->getCanonicalDecl()))
                                        continue;
                                for (const auto &call : calls)
                                        if (!call.blocking && callSuspend(call) && !isGuarded(function, call)) {
                                                suspendBy[function->getCanonicalDecl()] = &call;
                                                changed = true;
                                                break;
                                        }
                        }
                } while (changed);
        }

        void explainSuspend(const FunctionDecl *function) const {
                if (declaredSuspend(function))
                        return;
                auto found = suspendBy.find(function->getCanonicalDecl());
                if (found == suspendBy.end())
                        return;
                check.diag(found->second->location, "%0 requires a fiber because of this call to %1", DiagnosticIDs::Note)
                        << ("'" + function->getNameAsString() + "'") << describe(*found->second);
                explainSuspend(*found->second);
        }

        void explainSuspend(const Call &call) const {
                if (call.cleanup)
                        explainSuspend(call.cleanup);
                else if (call.expression && call.expression->getDirectCallee())
                        explainSuspend(call.expression->getDirectCallee());
        }

        Contract effect(const Call &call) const {
                if (call.blocking)
                        return Contract::Sync;
                if (call.cleanupCallback)
                        return valueContract(call.cleanupCallback).value_or(Contract::Unchecked);
                if (call.cleanup)
                        return functionContract(call.cleanup);
                if (call.forwarded)
                        return Contract::Sync;
                if (isNativeCall(call) && passesSuspendingCallback(call.expression))
                        return Contract::Unchecked;
                Contract scoped = scopedContract(scopedCallbacks(call.expression));
                if (const auto *function = call.expression->getDirectCallee())
                        return std::max(functionContract(function), scoped);
                return std::max(valueContract(call.expression->getCallee()).value_or(Contract::Unchecked), scoped);
        }

        /* Unannotated functions with a body in this translation unit either never suspend or are
         * unchecked. The inference starts from the stronger guarantee, so that mutually recursive
         * helpers can keep it. It then weakens the guarantee of each function until nothing changes. */
        void infer() {
                for (const auto &[function, calls] : bodies)
                        if (!declaredContract(function))
                                inferred[function->getCanonicalDecl()] = Contract::Sync;

                bool changed;
                do {
                        changed = false;
                        for (const auto &[function, calls] : bodies) {
                                auto found = inferred.find(function->getCanonicalDecl());
                                if (found == inferred.end() || found->second != Contract::Sync)
                                        continue;
                                auto call = std::find_if(calls.begin(), calls.end(), [&](const Call &call) {
                                        return effect(call) != Contract::Sync;
                                });
                                if (call != calls.end()) {
                                        found->second = Contract::Unchecked;
                                        weakenedBy[function->getCanonicalDecl()] = &*call;
                                        changed = true;
                                }
                        }
                } while (changed);
        }

        void note(SourceLocation location, llvm::StringRef message, std::string name) const {
                check.diag(location, message, DiagnosticIDs::Note) << name;
        }

        void explain(const FunctionDecl *function) const {
                if (declaredContract(function))
                        return;
                auto name = "'" + function->getNameAsString() + "'";
                if (auto found = weakenedBy.find(function->getCanonicalDecl()); found != weakenedBy.end()) {
                        check.diag(found->second->location, "%0 is unchecked because of this call to %1", DiagnosticIDs::Note)
                                << name << describe(*found->second);
                        explain(*found->second);
                } else
                        note(function->getCanonicalDecl()->getLocation(), "%0 is declared here without _may_suspend_ or _sync_", name);
        }

        void explain(const Expr *value) const {
                value = origin(value);
                const ValueDecl *decl = nullptr;
                if (const auto *reference = dyn_cast<DeclRefExpr>(value))
                        decl = reference->getDecl();
                else if (const auto *member = dyn_cast<MemberExpr>(value))
                        decl = member->getMemberDecl();
                if (!decl)
                        return;
                if (const auto *function = dyn_cast<FunctionDecl>(decl))
                        explain(function);
                else if (!declContract(decl))
                        note(decl->getLocation(), "%0 is declared here without _may_suspend_ or _sync_",
                             "'" + decl->getNameAsString() + "'");
        }

        void explain(const Call &call) const {
                if (call.cleanupCallback)
                        explain(call.cleanupCallback);
                else if (call.cleanup)
                        explain(call.cleanup);
                else if (isNativeCall(call)) {
                        for (const auto *argument : call.expression->arguments())
                                if (isCallbackType(argument->getType()))
                                        if (auto contract = valueContract(argument); contract && *contract != Contract::Sync)
                                                explain(argument);
                } else {
                        auto scoped = scopedCallbacks(call.expression);
                        for (const auto *callback : scoped.callbacks) {
                                auto contract = valueContract(callback).value_or(Contract::Unchecked);
                                if (contract == Contract::Sync)
                                        continue;
                                check.diag(sm.getExpansionLoc(callback->getBeginLoc()), "%0 is %1 and runs during the call to %2",
                                           DiagnosticIDs::Note)
                                        << describe(callback) << contractName(contract) << describe(call);
                                if (contract == Contract::Unchecked)
                                        explain(callback);
                        }
                        if (scoped.unknown)
                                check.diag(sm.getExpansionLoc(scoped.unknown->getBeginLoc()), "the callbacks in %0 are unknown at the call to %1",
                                           DiagnosticIDs::Note)
                                        << describe(scoped.unknown) << describe(call);
                        if (const auto *function = call.expression->getDirectCallee()) {
                                if (functionContract(function) == Contract::Unchecked)
                                        explain(function);
                        } else if (valueContract(call.expression->getCallee()).value_or(Contract::Unchecked) == Contract::Unchecked)
                                explain(call.expression->getCallee());
                }
        }

        struct Varargs {
                unsigned first, stride;
        };

        /* parseVarargs() returns nothing for a malformed annotation. An annotation with a stride of 0, or
         * with a first argument that isn't variadic, is malformed. */
        std::optional<Varargs> parseVarargs(const FunctionDecl *function, const AnnotateAttr *attribute) const {
                if (attribute->args_size() != 2)
                        return {};
                auto first = (*attribute->args_begin())->getIntegerConstantExpr(context);
                auto stride = (*std::next(attribute->args_begin()))->getIntegerConstantExpr(context);
                if (!first || !stride || first->isNegative() || !stride->isStrictlyPositive() || !function->isVariadic() ||
                    first->getZExtValue() < function->getNumParams())
                        return {};
                return Varargs{unsigned(first->getZExtValue()), unsigned(stride->getZExtValue())};
        }

        std::vector<Varargs> varargs(const FunctionDecl *function) const {
                std::vector<Varargs> result;
                for (const auto *redeclaration : function->redecls())
                        for (const auto *attribute : redeclaration->specific_attrs<AnnotateAttr>())
                                if (attribute->getAnnotation() == "sd:varargs")
                                        if (auto parsed = parseVarargs(function, attribute))
                                                result.push_back(*parsed);
                return result;
        }

        void checkDeclarations() {
                /* The diagnostic points at the declaration that adds the conflicting contract. */
                llvm::DenseMap<const FunctionDecl *, Annotations> seen;
                for (const auto *function : declarations) {
                        auto &annotations = seen[function->getCanonicalDecl()];
                        bool conflicting = (annotations.maySuspend || annotations.suspend) && annotations.sync;
                        annotations.add(function);
                        if (!conflicting && (annotations.maySuspend || annotations.suspend) && annotations.sync)
                                check.diag(function->getLocation(), "%0 has conflicting suspension contracts") << function;
                        for (const auto *attribute : function->specific_attrs<AnnotateAttr>())
                                if (attribute->getAnnotation() == "sd:varargs" && !parseVarargs(function, attribute))
                                        check.diag(function->getLocation(), "%0 has an invalid variadic suspension contract") << function;
                }
        }

        void checkBody(const FunctionDecl *function, const std::vector<Call> &calls) {
                auto declared = annotatedContract(function);
                bool fiber = declared.has_value();

                for (const auto &call : calls) {
                        if (call.blocking) {
                                if (callSuspend(call) && !isGuarded(function, call)) {
                                        check.diag(call.location, "call to %0 in a blocking region, but %0 requires a fiber")
                                                << describe(call);
                                        explainSuspend(call);
                                }
                                continue;
                        }
                        auto contract = effect(call);

                        if (call.awaited && !call.generic && contract == Contract::Sync) {
                                if (call.cleanup)
                                        check.diag(call.location, "_cleanup_await_() on cleanup %0 that cannot suspend")
                                                << describe(call) << call.removeMarker;
                                else
                                        check.diag(call.location, "SD_AWAIT() on a call to %0 that cannot suspend")
                                                << describe(call) << call.removeMarker;
                                continue;
                        }

                        if (!fiber) {
                                if (callSuspend(call) && !isGuarded(function, call)) {
                                        check.diag(call.location, "call to %0 requires a fiber, but %1 is unchecked")
                                                << describe(call) << function;
                                        explainSuspend(call);
                                }
                                continue;
                        }

                        if (contract == Contract::Unchecked) {
                                if (isNativeCall(call))
                                        check.diag(call.location, "call to %0 passes a callback that can suspend; wrap it in SD_BLOCKING()")
                                                << describe(call);
                                else
                                        check.diag(call.location, "unchecked call to %0 requires a fiber-callable declaration")
                                                << describe(call);
                                explain(call);
                        } else if (contract == Contract::MaySuspend) {
                                if (*declared == Contract::Sync)
                                        check.diag(call.location, "call to %0 may suspend in _sync_ function %1")
                                                << describe(call) << function;
                                else if (!call.awaited && call.cleanup)
                                        check.diag(call.location, "cleanup %0 may suspend; declare it with _cleanup_await_()")
                                                << describe(call) << call.addMarker;
                                else if (!call.awaited)
                                        check.diag(call.location, "call to %0 may suspend; wrap it in SD_AWAIT()")
                                                << describe(call) << call.addMarker;
                        }
                }
        }

        void checkFlows() {
                for (const auto &flow : flows) {
                        auto value = valueContract(flow.value);
                        if (!value || *value <= flow.slot)
                                continue;
                        check.diag(flow.location, "%0 is %1, but %2 requires a %3 callback")
                                << describe(flow.value) << contractName(*value) << flow.slotName << contractName(flow.slot);
                        if (*value == Contract::Unchecked)
                                explain(flow.value);
                }
        }

        /* Other translation units can't see the body of an exported function, so its declaration has to
         * say that it requires a fiber. */
        void checkSuspendDeclarations() {
                for (const auto &[function, calls] : bodies) {
                        if (!function->isExternallyVisible() || declaredSuspend(function) ||
                            annotatedContract(function) != Contract::MaySuspend || !suspendBy.contains(function->getCanonicalDecl()))
                                continue;
                        check.diag(function->getLocation(), "%0 requires a fiber; declare it _suspend_") << function;
                        explainSuspend(function);
                }
        }

        void run() {
                infer();
                inferSuspend();
                checkDeclarations();
                checkSuspendDeclarations();
                for (const auto &[function, calls] : bodies)
                        checkBody(function, calls);
                checkFlows();
        }
};

class Visitor : public RecursiveASTVisitor<Visitor> {
        Analysis &a;
        ASTContext &context;
        SourceManager &sm;
        const FunctionDecl *current = nullptr;
        std::vector<Call> *calls = nullptr;
        bool blocking = false;
        struct Marker {
                bool generic = false;
                /* name and range describe the outermost marker macro and the file range of its expansion. */
                llvm::StringRef name;
                CharSourceRange range;
        };
        llvm::DenseMap<const CallExpr *, Marker> awaited;
        llvm::DenseSet<const InitListExpr *> initializers;

        SourceLocation location(SourceLocation location) const {
                return sm.getExpansionLoc(location);
        }

        /* Markers in the body of a reusable macro are exempt from the unnecessary-await check, while
         * markers passed as arguments of other macros are not. */
        bool spelledInMacro(SourceLocation location) const {
                while (location.isMacroID() && sm.isMacroArgExpansion(location))
                        location = sm.getImmediateSpellingLoc(location);
                return location.isMacroID();
        }

        /* getFileRangeForEdit() refuses ranges in macro bodies and in system headers. A fix-it there would
         * change every expansion of the macro or a file outside the project. */
        CharSourceRange fileRange(CharSourceRange range) const {
                return tooling::getFileRangeForEdit(range, context).value_or(CharSourceRange());
        }

        CharSourceRange fileRange(SourceRange range) const {
                return fileRange(CharSourceRange::getTokenRange(range));
        }

        /* _cleanup_await_() expands to _await_cleanup_, so findMarker() uses the outermost expansion of a
         * marker macro. */
        Marker findMarker(SourceLocation location, std::initializer_list<llvm::StringRef> names) const {
                Marker marker;
                while (location.isMacroID()) {
                        if (sm.isMacroArgExpansion(location)) {
                                location = sm.getImmediateSpellingLoc(location);
                                continue;
                        }
                        auto expansion = sm.getImmediateExpansionRange(location);
                        auto name = Lexer::getImmediateMacroName(location, sm, context.getLangOpts());
                        if (llvm::is_contained(names, name)) {
                                marker.generic = spelledInMacro(expansion.getBegin());
                                marker.name = name;
                                marker.range = fileRange(expansion);
                        }
                        location = expansion.getBegin();
                }
                return marker;
        }

        std::vector<FixItHint> removeAwait(const Marker &marker, const CallExpr *call) const {
                auto range = fileRange(call->getSourceRange());
                if (marker.generic || marker.range.isInvalid() || range.isInvalid())
                        return {};
                return {FixItHint::CreateReplacement(marker.range, Lexer::getSourceText(range, sm, context.getLangOpts()))};
        }

        std::vector<FixItHint> addAwait(const CallExpr *call) const {
                auto range = fileRange(call->getSourceRange());
                if (range.isInvalid())
                        return {};
                return {FixItHint::CreateInsertion(range.getBegin(), "SD_AWAIT("),
                        FixItHint::CreateInsertion(range.getEnd(), ")")};
        }

        std::vector<FixItHint> removeCleanupAwait(const Marker &marker) const {
                if (marker.generic || marker.range.isInvalid())
                        return {};
                auto name = CharSourceRange::getCharRange(marker.range.getBegin(), marker.range.getBegin().getLocWithOffset(marker.name.size()));
                if (marker.name == "_cleanup_await_")
                        return {FixItHint::CreateReplacement(name, "_cleanup_")};
                const char *after = sm.getCharacterData(name.getEnd());
                if (*after == ' ')
                        name.setEnd(name.getEnd().getLocWithOffset(1));
                return {FixItHint::CreateRemoval(name)};
        }

        /* When a macro like CLEANUP_ARRAY() declares the variable, the cleanup attribute is in the macro
         * body, so the fix-it inserts _await_cleanup_ in front of the macro. */
        std::vector<FixItHint> addCleanupAwait(const CleanupAttr *cleanup, const VarDecl *variable) const {
                auto location = cleanup->getLocation();
                if (location.isMacroID() && Lexer::getImmediateMacroName(location, sm, context.getLangOpts()) == "_cleanup_") {
                        auto name = sm.getImmediateExpansionRange(location).getBegin();
                        if (name.isFileID())
                                return {FixItHint::CreateReplacement(CharSourceRange::getTokenRange(name), "_cleanup_await_")};
                }
                if (variable->getBeginLoc().isMacroID() &&
                    sm.getExpansionLoc(variable->getBeginLoc()) == sm.getExpansionLoc(location))
                        return {FixItHint::CreateInsertion(sm.getExpansionLoc(variable->getBeginLoc()), "_await_cleanup_ ")};
                return {};
        }

        /* A cleanup function annotated with "sd:cleanup_callback:<field>" invokes the callback in that
         * field of its variable's initializer. */
        const Expr *cleanupCallback(const FunctionDecl *cleanup, const VarDecl *variable) const {
                for (const auto *attribute : cleanup->specific_attrs<AnnotateAttr>()) {
                        auto field = attribute->getAnnotation();
                        if (!field.consume_front("sd:cleanup_callback:"))
                                continue;
                        if (!variable->getType().isConstQualified())
                                return nullptr;
                        const auto *list = dyn_cast_or_null<InitListExpr>(variable->getInit());
                        if (!list)
                                return nullptr;
                        if (list->isSyntacticForm() && list->getSemanticForm())
                                list = list->getSemanticForm();
                        const auto *record = list->getType()->getAsRecordDecl();
                        if (!record)
                                return nullptr;
                        unsigned i = 0;
                        for (const auto *member : record->fields()) {
                                if (i >= list->getNumInits())
                                        break;
                                if (member->getName() == field)
                                        return list->getInit(i);
                                i++;
                        }
                        return nullptr;
                }
                return nullptr;
        }

        void flow(const Expr *value, std::optional<Contract> slot, std::string slotName, SourceLocation at) {
                if (!slot || *slot == Contract::Unchecked)
                        return;
                a.flows.push_back({value, *slot, std::move(slotName), location(at)});
        }

        void initializer(const Expr *value, std::optional<Contract> slot, const std::string &slotName) {
                const Expr *stripped = value->IgnoreParenImpCasts();
                if (const auto *literal = dyn_cast<CompoundLiteralExpr>(stripped))
                        stripped = literal->getInitializer()->IgnoreParenImpCasts();
                if (const auto *list = dyn_cast<InitListExpr>(stripped)) {
                        if (list->isSyntacticForm() && list->getSemanticForm())
                                list = list->getSemanticForm();
                        if (!initializers.insert(list).second)
                                return;
                        const auto *record = list->getType()->getAsRecordDecl();
                        if (record && record->getDefinition()) {
                                unsigned i = 0;
                                for (const auto *field : record->getDefinition()->fields()) {
                                        if (record->isUnion() && field != list->getInitializedFieldInUnion())
                                                continue;
                                        if (i >= list->getNumInits())
                                                break;
                                        initializer(list->getInit(i++), a.slotContract(field), "'" + field->getNameAsString() + "'");
                                }
                        } else
                                for (const auto *element : list->inits())
                                        initializer(element, slot, slotName);
                        return;
                }
                if (isCallbackType(value->getType()))
                        flow(value, slot, slotName, value->getBeginLoc());
        }

public:
        Visitor(Analysis &analysis, ASTContext &context) : a(analysis), context(context), sm(context.getSourceManager()) {}

        bool TraverseFunctionDecl(FunctionDecl *function) {
                if (a.isSystem(function))
                        return true;
                a.declarations.push_back(function);
                if (!function->doesThisDeclarationHaveABody())
                        return RecursiveASTVisitor::TraverseFunctionDecl(function);

                a.bodies.emplace_back(function, std::vector<Call>{});
                llvm::SaveAndRestore<const FunctionDecl *> savedFunction(current, function);
                llvm::SaveAndRestore savedCalls(calls, &a.bodies.back().second);
                llvm::SaveAndRestore savedBlocking(blocking, false);
                return RecursiveASTVisitor::TraverseFunctionDecl(function);
        }

        bool TraverseStmtExpr(StmtExpr *statement) {
                llvm::SaveAndRestore saved(blocking, blocking || scopeAnnotation(statement, "sd:blocking_scope"));
                return RecursiveASTVisitor::TraverseStmtExpr(statement);
        }

        bool TraverseBinaryOperator(BinaryOperator *binary) {
                auto *marker = binary->isCommaOp() ? dyn_cast<StmtExpr>(binary->getLHS()->IgnoreParenCasts()) : nullptr;
                if (!scopeAnnotation(marker, "sd:await"))
                        return RecursiveASTVisitor::TraverseBinaryOperator(binary);

                auto found = findMarker(marker->getBeginLoc(), {"SD_AWAIT"});
                if (const auto *call = dyn_cast<CallExpr>(binary->getRHS()->IgnoreParenImpCasts()))
                        awaited[call] = found;
                else if (!found.generic)
                        a.check.diag(location(binary->getBeginLoc()), "SD_AWAIT() must wrap a single call");
                return RecursiveASTVisitor::TraverseBinaryOperator(binary);
        }

        /* Calls in unevaluated operands never run. */
        bool TraverseUnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *expression) {
                if (expression->getKind() != UETT_SizeOf)
                        return true;
                QualType type = expression->isArgumentType() ? expression->getArgumentType() : expression->getArgumentExpr()->getType();
                if (!type->isVariablyModifiedType())
                        return true;
                return RecursiveASTVisitor::TraverseUnaryExprOrTypeTraitExpr(expression);
        }

        bool TraverseGenericSelectionExpr(GenericSelectionExpr *expression) {
                return TraverseStmt(expression->getResultExpr());
        }

        bool TraverseChooseExpr(ChooseExpr *expression) {
                return TraverseStmt(expression->getChosenSubExpr());
        }

        bool TraverseTypeOfExprTypeLoc(TypeOfExprTypeLoc type, bool = true) {
                if (!type.getUnderlyingExpr()->getType()->isVariablyModifiedType())
                        return true;
                return RecursiveASTVisitor::TraverseTypeOfExprTypeLoc(type, true);
        }

        bool TraverseCallExpr(CallExpr *call) {
                if (call->isUnevaluatedBuiltinCall(context))
                        return true;
                /* Clang's unevaluated-builtin predicate excludes assume even though its operand's side effects are discarded. */
                if (call->getBuiltinCallee() == Builtin::BI__builtin_assume || call->getBuiltinCallee() == Builtin::BI__assume)
                        return true;
                return RecursiveASTVisitor::TraverseCallExpr(call);
        }

        bool VisitCallExpr(CallExpr *expression) {
                if (calls) {
                        Call call;
                        call.expression = expression;
                        call.location = location(expression->getBeginLoc());
                        call.blocking = blocking;
                        call.anchor = expression;
                        call.forwarded = !expression->getDirectCallee() && a.isScopedCallback(expression->getCallee()->getType()) &&
                                a.receivesScopedCallbacks(current);
                        if (auto found = awaited.find(expression); found != awaited.end()) {
                                call.awaited = true;
                                call.generic = found->second.generic;
                                call.removeMarker = removeAwait(found->second, expression);
                        } else
                                call.addMarker = addAwait(expression);
                        calls->push_back(std::move(call));
                }

                const auto *function = expression->getDirectCallee();
                if (function && a.isNative(function) && !a.annotatedContract(function))
                        return true;
                QualType type = expression->getCallee()->getType();
                if (type->isPointerType())
                        type = type->getPointeeType();
                const auto *prototype = type->getAs<FunctionProtoType>();
                unsigned parameters = function ? function->getNumParams() : prototype ? prototype->getNumParams() : 0;
                for (unsigned i = 0; i < std::min(parameters, expression->getNumArgs()); i++) {
                        const auto *argument = expression->getArg(i);
                        if (function)
                                flow(argument, a.declContract(function->getParamDecl(i)),
                                     "parameter '" + function->getParamDecl(i)->getNameAsString() + "' of '" + function->getNameAsString() + "'",
                                     argument->getBeginLoc());
                        else
                                flow(argument, a.typeContract(prototype->getParamType(i)), "the callback parameter", argument->getBeginLoc());
                }
                if (function)
                        for (const auto &varargs : a.varargs(function))
                                for (unsigned i = varargs.first; i < expression->getNumArgs(); i += varargs.stride)
                                        flow(expression->getArg(i), Contract::MaySuspend,
                                             "argument " + std::to_string(i) + " of '" + function->getNameAsString() + "'",
                                             expression->getArg(i)->getBeginLoc());
                return true;
        }

        bool VisitVarDecl(VarDecl *variable) {
                if (isa<ParmVarDecl>(variable) || a.isSystem(variable))
                        return true;
                if (variable->hasInit())
                        initializer(variable->getInit(), a.slotContract(variable), "'" + variable->getNameAsString() + "'");
                if (const auto *cleanup = variable->getAttr<CleanupAttr>(); cleanup && calls) {
                        Call call;
                        call.cleanup = cleanup->getFunctionDecl();
                        call.anchor = variable->getInit();
                        call.cleanupCallback = cleanupCallback(call.cleanup, variable);
                        call.location = location(variable->getLocation());
                        call.blocking = blocking;
                        for (const auto *attribute : variable->specific_attrs<AnnotateAttr>())
                                if (attribute->getAnnotation() == "sd:await_cleanup") {
                                        auto marker = findMarker(attribute->getLocation(), {"_await_cleanup_", "_cleanup_await_"});
                                        call.awaited = true;
                                        call.generic = marker.generic;
                                        call.removeMarker = removeCleanupAwait(marker);
                                }
                        if (!call.awaited)
                                call.addMarker = addCleanupAwait(cleanup, variable);
                        calls->push_back(std::move(call));
                }
                return true;
        }

        bool VisitInitListExpr(InitListExpr *list) {
                initializer(list, a.typeContract(list->getType()), "the initializer");
                return true;
        }

        bool VisitBinaryOperator(BinaryOperator *binary) {
                if (binary->getOpcode() == BO_Assign && isCallbackType(binary->getLHS()->getType()))
                        flow(binary->getRHS(), a.valueContract(binary->getLHS()), a.describe(binary->getLHS()), binary->getBeginLoc());
                return true;
        }

        bool VisitReturnStmt(ReturnStmt *statement) {
                if (current && statement->getRetValue())
                        flow(statement->getRetValue(), a.typeContract(current->getReturnType()),
                             "the return value of '" + current->getNameAsString() + "'", statement->getBeginLoc());
                return true;
        }

        bool VisitExplicitCastExpr(ExplicitCastExpr *cast) {
                if (isCallbackType(cast->getSubExpr()->getType()))
                        flow(cast->getSubExpr(), a.typeContract(cast->getTypeAsWritten()), "the cast", cast->getBeginLoc());
                return true;
        }
};

class SuspendCheck : public clang::tidy::ClangTidyCheck {
        Preprocessor *preprocessor = nullptr;

public:
        using ClangTidyCheck::ClangTidyCheck;

        bool isLanguageVersionSupported(const LangOptions &options) const override {
                return !options.CPlusPlus && !options.ObjC;
        }

        void registerPPCallbacks(const SourceManager &, Preprocessor *pp, Preprocessor *) override {
                preprocessor = pp;
        }

        void registerMatchers(ast_matchers::MatchFinder *finder) override {
                finder->addMatcher(ast_matchers::translationUnitDecl(), this);
        }

        void check(const ast_matchers::MatchFinder::MatchResult &result) override {
                if (result.Context->getDiagnostics().hasErrorOccurred() ||
                    skipTranslationUnit(result.Context->getSourceManager(), *preprocessor))
                        return;

                Analysis analysis(*this, *result.Context);
                Visitor(analysis, *result.Context).TraverseDecl(result.Context->getTranslationUnitDecl());
                analysis.run();
        }
};

/* Another fiber can run while a fiber is suspended, and it can modify a hashmap that the suspended fiber
 * iterates. The iterator of the suspended fiber can then skip or repeat entries after the fiber resumes. */
class IteratorCheck : public clang::tidy::ClangTidyCheck {
        Preprocessor *preprocessor = nullptr;
        std::vector<llvm::StringRef> types;

        class Collector : public RecursiveASTVisitor<Collector> {
        public:
                const IteratorCheck &check;
                std::vector<const CallExpr *> suspensions;
                std::vector<const VarDecl *> variables;

                explicit Collector(const IteratorCheck &check) : check(check) {}

                bool VisitBinaryOperator(BinaryOperator *binary) {
                        if (const auto *call = awaitedCall(binary))
                                suspensions.push_back(call);
                        return true;
                }

                bool VisitVarDecl(VarDecl *variable) {
                        if (variable->hasLocalStorage() && check.matches(variable->getType()))
                                variables.push_back(variable);
                        return true;
                }
        };

        bool matches(QualType type) const {
                for (QualType t = type; !t.isNull();) {
                        if (const auto *alias = t->getAs<TypedefType>(); alias && llvm::is_contained(types, alias->getDecl()->getName()))
                                return true;
                        auto desugared = t->getLocallyUnqualifiedSingleStepDesugaredType();
                        if (desugared.getTypePtr() == t.getTypePtr())
                                break;
                        t = desugared;
                }
                const auto *record = type->getAsRecordDecl();
                return record && llvm::is_contained(types, record->getName());
        }

        /* FOREACH macros declare their iterator with a generated name, so the diagnostic names the macro
         * instead. */
        std::string describe(const VarDecl *variable, const SourceManager &sm, const LangOptions &options) const {
                auto location = variable->getLocation();
                llvm::StringRef macro;
                while (location.isMacroID()) {
                        if (sm.isMacroArgExpansion(location)) {
                                location = sm.getImmediateSpellingLoc(location);
                                continue;
                        }
                        macro = Lexer::getImmediateMacroName(location, sm, options);
                        location = sm.getImmediateExpansionRange(location).getBegin();
                }
                if (!macro.empty())
                        return "the iterator of " + macro.str() + "()";
                return "'" + variable->getNameAsString() + "'";
        }

public:
        IteratorCheck(llvm::StringRef name, clang::tidy::ClangTidyContext *context)
                : ClangTidyCheck(name, context), types(clang::tidy::utils::options::parseStringList(Options.get("Types", "Iterator"))) {}

        void storeOptions(clang::tidy::ClangTidyOptions::OptionMap &options) override {
                Options.store(options, "Types", clang::tidy::utils::options::serializeStringList(types));
        }

        bool isLanguageVersionSupported(const LangOptions &options) const override {
                return !options.CPlusPlus && !options.ObjC;
        }

        void registerPPCallbacks(const SourceManager &, Preprocessor *pp, Preprocessor *) override {
                preprocessor = pp;
        }

        void registerMatchers(ast_matchers::MatchFinder *finder) override {
                using namespace ast_matchers;
                finder->addMatcher(functionDecl(isDefinition()).bind("function"), this);
        }

        void check(const ast_matchers::MatchFinder::MatchResult &result) override {
                const auto *function = result.Nodes.getNodeAs<FunctionDecl>("function");
                auto &sm = *result.SourceManager;
                if (result.Context->getDiagnostics().hasErrorOccurred() || sm.isInSystemHeader(function->getLocation()) ||
                    skipTranslationUnit(sm, *preprocessor))
                        return;
                if (!llvm::any_of(function->redecls(), [](const FunctionDecl *redeclaration) {
                            return hasAnnotation(redeclaration, "sd:may_suspend") || hasAnnotation(redeclaration, "sd:suspend");
                    }))
                        return;

                Collector collector(*this);
                collector.TraverseStmt(function->getBody());
                if (collector.suspensions.empty() || collector.variables.empty())
                        return;

                /* LiveVariables only records liveness after statements that are CFG elements. isLive()
                 * returns false for any other statement, which would hide every report. setAllAlwaysAdd()
                 * makes each call a CFG element. */
                AnalysisDeclContextManager manager(*result.Context);
                manager.getCFGBuildOptions().setAllAlwaysAdd();
                auto *liveness = manager.getContext(function)->getAnalysis<LiveVariables>();
                if (!liveness)
                        return;

                for (const auto *suspension : collector.suspensions)
                        for (const auto *variable : collector.variables) {
                                if (!liveness->isLive(suspension, variable))
                                        continue;
                                auto name = describe(variable, sm, result.Context->getLangOpts());
                                diag(sm.getExpansionLoc(suspension->getBeginLoc()),
                                     "%0 is used after this suspension point, and another fiber can invalidate it while this fiber is suspended")
                                        << name;
                                diag(sm.getExpansionLoc(variable->getLocation()), "%0 is declared here", DiagnosticIDs::Note) << name;
                        }
        }
};

class SystemdModule : public clang::tidy::ClangTidyModule {
public:
        void addCheckFactories(clang::tidy::ClangTidyCheckFactories &checks) override {
                checks.registerCheck<SuspendCheck>("systemd-suspend");
                checks.registerCheck<IteratorCheck>("systemd-suspend-iterator");
        }
};

static clang::tidy::ClangTidyModuleRegistry::Add<SystemdModule> module("systemd", "Checks specific to systemd.");

}
