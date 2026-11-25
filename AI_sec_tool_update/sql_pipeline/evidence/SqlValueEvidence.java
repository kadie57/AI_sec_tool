import com.sun.source.tree.*;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreeScanner;
import java.util.*;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeKind;

/** A bounded, conservative interpreter for the argument of an already located JDBC call. */
class SqlValueEvidence {
    private static final int BUDGET = 500;
    private static final int MAX_HELPER_DEPTH = 4;
    private static final int MAX_REFERENCES = 32;
    private static final Set<Tree.Kind> WRITE_EXPRESSIONS = EnumSet.of(
        Tree.Kind.ASSIGNMENT, Tree.Kind.AND_ASSIGNMENT, Tree.Kind.OR_ASSIGNMENT, Tree.Kind.XOR_ASSIGNMENT,
        Tree.Kind.PLUS_ASSIGNMENT, Tree.Kind.MINUS_ASSIGNMENT, Tree.Kind.MULTIPLY_ASSIGNMENT,
        Tree.Kind.DIVIDE_ASSIGNMENT, Tree.Kind.REMAINDER_ASSIGNMENT, Tree.Kind.LEFT_SHIFT_ASSIGNMENT,
        Tree.Kind.RIGHT_SHIFT_ASSIGNMENT, Tree.Kind.UNSIGNED_RIGHT_SHIFT_ASSIGNMENT,
        Tree.Kind.PREFIX_INCREMENT, Tree.Kind.PREFIX_DECREMENT, Tree.Kind.POSTFIX_INCREMENT,
        Tree.Kind.POSTFIX_DECREMENT);

    private record Step(String file, long line, String role) {}
    private record Value(String status, Object literal, List<Step> steps) {
        boolean isConstant() { return status.equals("constant"); }
        boolean isUnknown() { return status.equals("unknown"); }
        Value with(List<Step> context) {
            var ordered = new LinkedHashSet<>(steps);
            ordered.addAll(context);
            return new Value(status, literal, ordered.stream().limit(MAX_REFERENCES).toList());
        }
    }
    private static final Value UNKNOWN = new Value("unknown", null, List.of());
    private enum Transfer { NEXT, RETURN, BREAK, TARGET, UNSUPPORTED }
    private record Outcome(Transfer transfer, Value value) {}
    private record ArgumentTarget(SqlEndpointProbe.Call call, int index, Set<Tree> ancestors) {}
    private static final Outcome NEXT = new Outcome(Transfer.NEXT, UNKNOWN);
    private static final Outcome BREAK = new Outcome(Transfer.BREAK, UNKNOWN);
    private static final Outcome UNSUPPORTED = new Outcome(Transfer.UNSUPPORTED, UNKNOWN);

    private final SqlEndpointProbe probe;
    private final Map<Tree, SqlEndpointProbe.Call> calls = new IdentityHashMap<>();
    private int remaining = BUDGET;

    private SqlValueEvidence(SqlEndpointProbe probe) {
        this.probe = probe;
        for (var call : probe.calls) calls.put(call.tree(), call);
    }

    public static void main(String[] args) throws Exception {
        SqlEndpointProbe.run(args, (probe, sink) -> new SqlValueEvidence(probe).report(sink));
    }

    private static TreePath child(TreePath parent, Tree tree) { return new TreePath(parent, tree); }

    private List<Step> step(TreePath path, String role) {
        var unit = path.getCompilationUnit();
        var file = probe.units.get(unit);
        long line = probe.line(unit, path.getLeaf());
        return file == null || line < 1 ? List.of() : List.of(new Step(file, line, role));
    }

    private Value unknownAt(TreePath path, String role) { return UNKNOWN.with(step(path, role)); }

    private static boolean hasWrites(Tree tree) {
        return Boolean.TRUE.equals(new TreeScanner<Boolean, Void>() {
            @Override public Boolean scan(Tree node, Void unused) {
                return node != null && (WRITE_EXPRESSIONS.contains(node.getKind()) || Boolean.TRUE.equals(super.scan(node, unused)));
            }
            @Override public Boolean reduce(Boolean a, Boolean b) {
                return Boolean.TRUE.equals(a) || Boolean.TRUE.equals(b);
            }
        }.scan(tree, null));
    }

    private static boolean supportedLiteral(Object value) {
        return value instanceof String || value instanceof Character || value instanceof Boolean || value instanceof Integer;
    }

    private Value literal(TreePath path, Object value) {
        return supportedLiteral(value) ? new Value("constant", value, step(path, "constant_expression")) : UNKNOWN;
    }

    private static int switchInt(Object value) {
        return value instanceof Character c ? c : (Integer) value;
    }

    private static boolean numeric(Object value) { return value instanceof Character || value instanceof Integer; }

    private static boolean switchValue(Object value) { return value instanceof String || numeric(value); }

    private static boolean sameSwitchValue(Object left, Object right) {
        return numeric(left) && numeric(right) ? switchInt(left) == switchInt(right) : Objects.equals(left, right);
    }

    private boolean intOperand(TreePath path, Value value) {
        var type = probe.trees.getTypeMirror(path);
        return value.isConstant() && numeric(value.literal()) && type != null
            && (type.getKind() == TypeKind.INT || type.getKind() == TypeKind.CHAR);
    }

    private static Object intOperation(Tree.Kind operator, TypeKind resultType, int left, int right) {
        if (resultType == TypeKind.INT) {
            // Use Java int operations to preserve its overflow and division semantics.
            return switch (operator) {
                case PLUS -> left + right;
                case MINUS -> left - right;
                case MULTIPLY -> left * right;
                case DIVIDE -> right == 0 ? null : left / right;
                case REMAINDER -> right == 0 ? null : left % right;
                default -> null;
            };
        }
        if (resultType == TypeKind.BOOLEAN) {
            return switch (operator) {
                case LESS_THAN -> left < right;
                case LESS_THAN_EQUAL -> left <= right;
                case GREATER_THAN -> left > right;
                case GREATER_THAN_EQUAL -> left >= right;
                default -> null;
            };
        }
        return null;
    }

    private static Value convert(Value value, String type) {
        if (value.isUnknown()) return value;
        if (type.equals("java.lang.String")) {
            return value.isConstant() && !(value.literal() instanceof String) ? UNKNOWN : value;
        }
        if (type.equals("boolean") && value.literal() instanceof Boolean) return value;
        if (!numeric(value.literal())) return UNKNOWN;
        int number = switchInt(value.literal());
        if (type.equals("int")) return new Value("constant", number, value.steps());
        if (type.equals("char") && number >= Character.MIN_VALUE && number <= Character.MAX_VALUE) {
            return new Value("constant", (char) number, value.steps());
        }
        return UNKNOWN;
    }

    private Value expression(TreePath path, Map<Element, Value> env, int depth) {
        if (--remaining < 0) return UNKNOWN;
        var tree = path.getLeaf();
        if (tree instanceof LiteralTree item) return literal(path, item.getValue());
        if (tree instanceof ParenthesizedTree paren) return expression(child(path, paren.getExpression()), env, depth);
        if (tree instanceof IdentifierTree || tree instanceof MemberSelectTree) {
            if (probe.trees.getElement(path) instanceof VariableElement variable) {
                var value = env.containsKey(variable) ? env.get(variable) : literal(path, variable.getConstantValue());
                return value.isUnknown() ? value.with(step(path, "value_at_reference_unresolved")) : value;
            }
            return UNKNOWN;
        }
        if (tree instanceof UnaryTree unary) {
            var operandPath = child(path, unary.getExpression());
            var operand = expression(operandPath, env, depth);
            if (unary.getKind() == Tree.Kind.LOGICAL_COMPLEMENT) {
                return operand.literal() instanceof Boolean value ? literal(path, !value).with(operand.steps()) : UNKNOWN;
            }
            if ((unary.getKind() == Tree.Kind.UNARY_PLUS || unary.getKind() == Tree.Kind.UNARY_MINUS)
                    && intOperand(operandPath, operand)) {
                int number = switchInt(operand.literal());
                int value = unary.getKind() == Tree.Kind.UNARY_MINUS ? -number : number;
                return new Value("constant", value, operand.steps()).with(step(path, "integer_arithmetic"));
            }
            return UNKNOWN;
        }
        if (tree instanceof BinaryTree binary) {
            var leftPath = child(path, binary.getLeftOperand());
            var left = expression(leftPath, env, depth);
            if (binary.getKind() == Tree.Kind.CONDITIONAL_AND || binary.getKind() == Tree.Kind.CONDITIONAL_OR) {
                if (!(left.literal() instanceof Boolean value)) return UNKNOWN;
                boolean and = binary.getKind() == Tree.Kind.CONDITIONAL_AND;
                if (and != value) return left;
                var right = expression(child(path, binary.getRightOperand()), env, depth);
                return right.literal() instanceof Boolean ? right.with(left.steps()) : UNKNOWN;
            }
            var rightPath = child(path, binary.getRightOperand());
            var right = expression(rightPath, env, depth);
            var type = probe.trees.getTypeMirror(path);
            if (binary.getKind() == Tree.Kind.PLUS && type != null && type.toString().equals("java.lang.String")) {
                if (left.isUnknown() || right.isUnknown()) {
                    var unresolved = UNKNOWN.with(left.isUnknown() ? left.steps() : List.of())
                        .with(right.isUnknown() ? right.steps() : List.of());
                    return unresolved.with(step(path, "string_concatenation_with_unresolved_operand"));
                }
                var value = left.isConstant() && right.isConstant()
                    ? new Value("constant", String.valueOf(left.literal()) + right.literal(), List.of())
                    : new Value("external_input_contributes", null, List.of());
                return value.with(left.steps()).with(right.steps()).with(step(path, "string_concatenation"));
            }
            if (left.isConstant() && right.isConstant()
                    && (binary.getKind() == Tree.Kind.EQUAL_TO || binary.getKind() == Tree.Kind.NOT_EQUAL_TO)
                    && ((numeric(left.literal()) && numeric(right.literal()))
                    || (left.literal() instanceof Boolean && right.literal() instanceof Boolean))) {
                boolean equal = sameSwitchValue(left.literal(), right.literal());
                return literal(path, (binary.getKind() == Tree.Kind.EQUAL_TO) == equal).with(left.steps()).with(right.steps());
            }
            if (type != null && intOperand(leftPath, left) && intOperand(rightPath, right)) {
                var value = intOperation(binary.getKind(), type.getKind(), switchInt(left.literal()), switchInt(right.literal()));
                if (value != null) {
                    var role = type.getKind() == TypeKind.INT ? "integer_arithmetic" : "integer_comparison";
                    return new Value("constant", value, left.steps()).with(right.steps()).with(step(path, role));
                }
            }
            return UNKNOWN;
        }
        if (tree instanceof ConditionalExpressionTree choice) {
            var condition = expression(child(path, choice.getCondition()), env, depth);
            if (!(condition.literal() instanceof Boolean value)) return UNKNOWN;
            var selected = child(path, value ? choice.getTrueExpression() : choice.getFalseExpression());
            return expression(selected, env, depth).with(condition.steps()).with(step(selected, "conditional_value_selected"));
        }
        if (tree instanceof MethodInvocationTree method) return invocation(path, method, env, depth);
        return unknownAt(path, "expression_not_modeled");
    }

    private Value invocation(TreePath path, MethodInvocationTree method, Map<Element, Value> env, int depth) {
        var call = calls.get(method);
        if (call == null) return unknownAt(path, "call_signature_unresolved");
        var definition = probe.trees.getPath(call.target());
        if (call.readsRequest() && definition == null
                && call.target().getReturnType().toString().equals("java.lang.String")) {
            return new Value("external_input_contributes", null, step(path, "servlet_request_read"));
        }
        if (call.owner().equals("java.lang.String") && call.name().equals("charAt")
                && method.getMethodSelect() instanceof MemberSelectTree member && method.getArguments().size() == 1) {
            var receiver = expression(child(child(path, member), member.getExpression()), env, depth);
            var index = expression(child(path, method.getArguments().get(0)), env, depth);
            if (receiver.literal() instanceof String string && index.literal() instanceof Integer i && i >= 0 && i < string.length()) {
                return new Value("constant", string.charAt(i), List.of()).with(receiver.steps()).with(index.steps())
                    .with(step(path, "constant_string_index"));
            }
        }
        if (call.owner().equals("java.lang.String") && call.name().equals("equals")
                && method.getMethodSelect() instanceof MemberSelectTree member && method.getArguments().size() == 1) {
            var receiver = expression(child(child(path, member), member.getExpression()), env, depth);
            var argument = expression(child(path, method.getArguments().get(0)), env, depth);
            if (receiver.literal() instanceof String string && argument.literal() instanceof String other) {
                return literal(path, string.equals(other)).with(receiver.steps()).with(argument.steps());
            }
        }
        if (depth >= MAX_HELPER_DEPTH || definition == null || !probe.units.containsKey(definition.getCompilationUnit())
                || !(definition.getLeaf() instanceof MethodTree helper) || helper.getBody() == null) {
            return unknownAt(path, "call_result_not_modeled");
        }
        if (!fixedDispatch(call)) return unknownAt(path, "helper_target_unresolved");
        var parameters = call.target().getParameters();
        if (parameters.size() != method.getArguments().size() || call.target().isVarArgs()) return UNKNOWN;
        var arguments = new HashMap<Element, Value>();
        for (int i = 0; i < parameters.size(); i++) {
            var parameter = parameters.get(i);
            arguments.put(parameter, convert(expression(child(path, method.getArguments().get(i)), env, depth), parameter.asType().toString()));
        }
        var result = execute(child(definition, helper.getBody()), arguments, List.of(), depth + 1);
        var value = result.transfer() == Transfer.RETURN ? convert(result.value(), call.target().getReturnType().toString())
            : UNKNOWN.with(result.value().steps());
        return value.with(step(path, "helper_call"));
    }

    private boolean fixedDispatch(SqlEndpointProbe.Call call) {
        if (!probe.dispatch(call).equals("declaration_only")) return true;
        if (!(call.tree().getMethodSelect() instanceof MemberSelectTree member)) return false;
        var receiver = child(child(call.path(), member), member.getExpression());
        while (receiver.getLeaf() instanceof ParenthesizedTree parenthesized) {
            receiver = child(receiver, parenthesized.getExpression());
        }
        if (!(receiver.getLeaf() instanceof NewClassTree created) || created.getClassBody() != null) return false;
        var type = probe.trees.getTypeMirror(receiver);
        return type != null && type.toString().equals(call.owner());
    }

    private Outcome block(TreePath path, List<? extends StatementTree> statements, Map<Element, Value> env,
                          List<Step> guards, int depth, ArgumentTarget target) {
        for (var statement : statements) {
            var result = visitStatement(child(path, statement), env, guards, depth, target);
            if (result.transfer() != Transfer.NEXT) return result;
        }
        return NEXT;
    }

    private Outcome visitStatement(TreePath path, Map<Element, Value> env, List<Step> guards,
                                   int depth, ArgumentTarget target) {
        if (target != null && target.ancestors().contains(path.getLeaf())) {
            return new Outcome(Transfer.TARGET, seek(path, target, env, guards));
        }
        return execute(path, env, guards, depth);
    }

    private Outcome execute(TreePath path, Map<Element, Value> env, List<Step> guards, int depth) {
        if (--remaining < 0) return UNSUPPORTED;
        var tree = path.getLeaf();
        if (tree instanceof BlockTree b) return block(path, b.getStatements(), env, guards, depth, null);
        if (tree instanceof EmptyStatementTree || tree instanceof ClassTree) return NEXT;
        if (tree instanceof VariableTree variable) {
            var rhs = variable.getInitializer();
            if (hasWrites(rhs)) return UNSUPPORTED;
            var symbol = probe.trees.getElement(path);
            if (symbol == null) return UNSUPPORTED;
            env.put(symbol, rhs == null ? UNKNOWN : convert(expression(child(path, rhs), env, depth), symbol.asType().toString())
                .with(guards).with(step(path, "local_definition")));
            return NEXT;
        }
        if (tree instanceof ExpressionStatementTree statement) {
            var expr = statement.getExpression();
            if (expr instanceof AssignmentTree assign) {
                var assignPath = child(path, assign);
                var symbol = probe.trees.getElement(child(assignPath, assign.getVariable()));
                if (!env.containsKey(symbol) || hasWrites(assign.getExpression())) return UNSUPPORTED;
                env.put(symbol, convert(expression(child(assignPath, assign.getExpression()), env, depth), symbol.asType().toString())
                    .with(guards).with(step(path, "local_assignment")));
                return NEXT;
            }
            return hasWrites(expr) ? UNSUPPORTED : NEXT;
        }
        if (tree instanceof ReturnTree ret) {
            var expr = ret.getExpression();
            return new Outcome(Transfer.RETURN, expr == null || hasWrites(expr) ? UNKNOWN
                : expression(child(path, expr), env, depth).with(guards).with(step(path, "helper_return")));
        }
        if (tree instanceof BreakTree br && br.getLabel() == null) return BREAK;
        if (tree instanceof IfTree branch) return when(path, branch, env, guards, depth);
        if (tree instanceof SwitchTree branch) return choose(path, branch, env, guards, depth, null);
        return new Outcome(Transfer.UNSUPPORTED, unknownAt(path, "statement_not_modeled"));
    }

    private static List<Step> context(List<Step> existing, List<Step> added, List<Step> decision) {
        var together = new ArrayList<>(existing);
        together.addAll(added);
        together.addAll(decision);
        return together;
    }

    private Outcome when(TreePath path, IfTree branch, Map<Element, Value> env, List<Step> guards, int depth) {
        if (hasWrites(branch.getCondition())) return UNSUPPORTED;
        var condition = expression(child(path, branch.getCondition()), env, depth);
        if (condition.literal() instanceof Boolean selected) {
            var body = selected ? branch.getThenStatement() : branch.getElseStatement();
            return body == null ? NEXT : execute(child(path, body), env,
                context(guards, condition.steps(), step(path, selected ? "if_true" : "if_false")), depth);
        }
        var left = new HashMap<>(env);
        var right = new HashMap<>(env);
        if (execute(child(path, branch.getThenStatement()), left, guards, depth).transfer() != Transfer.NEXT
                || (branch.getElseStatement() != null
                && execute(child(path, branch.getElseStatement()), right, guards, depth).transfer() != Transfer.NEXT)) {
            return new Outcome(Transfer.UNSUPPORTED, unknownAt(path, "runtime_if_changes_control_flow"));
        }
        env.replaceAll((key, value) -> Objects.equals(left.get(key), right.get(key)) ? left.get(key)
            : unknownAt(path, "runtime_if_merges_assignments"));
        return NEXT;
    }

    @SuppressWarnings("preview")
    private Outcome choose(TreePath path, SwitchTree branch, Map<Element, Value> env, List<Step> guards,
                           int depth, ArgumentTarget target) {
        if (hasWrites(branch.getExpression())) return UNSUPPORTED;
        var selector = expression(child(path, branch.getExpression()), env, depth);
        if (!switchValue(selector.literal())) return new Outcome(Transfer.UNSUPPORTED, unknownAt(path, "runtime_switch_selector"));
        int match = -1;
        int defaultCase = -1;
        var cases = branch.getCases();
        for (int i = 0; i < cases.size(); i++) {
            var entry = cases.get(i);
            var expressions = entry.getExpressions();
            if (entry.getLabels().size() == 1 && entry.getLabels().get(0).getKind().name().equals("DEFAULT_CASE_LABEL")) {
                defaultCase = i;
            } else if (expressions.isEmpty() || expressions.size() != entry.getLabels().size()) {
                return UNSUPPORTED;
            }
            for (var label : expressions) {
                var value = expression(child(child(path, entry), label), env, depth);
                if (!switchValue(value.literal())) return UNSUPPORTED;
                if (sameSwitchValue(selector.literal(), value.literal())) match = i;
            }
        }
        int selected = match < 0 ? defaultCase : match;
        if (selected < 0) return NEXT;
        var switchContext = context(guards, selector.steps(), step(path, "switch_selector"));
        for (int i = selected; i < cases.size(); i++) {
            var entry = cases.get(i);
            var entryPath = child(path, entry);
            switchContext = context(switchContext, step(entryPath, i == selected ? "switch_case_selected" : "switch_fallthrough"), List.of());
            if (entry.getCaseKind() == CaseTree.CaseKind.RULE) {
                var result = visitStatement(child(entryPath, entry.getBody()), env, switchContext, depth, target);
                return result.transfer() == Transfer.BREAK ? NEXT : result;
            }
            var result = block(entryPath, entry.getStatements(), env, switchContext, depth, target);
            if (result.transfer() == Transfer.BREAK) return NEXT;
            if (result.transfer() != Transfer.NEXT) return result;
        }
        return NEXT;
    }

    private Value seek(TreePath path, ArgumentTarget target, Map<Element, Value> env, List<Step> guards) {
        if (--remaining < 0) return UNKNOWN;
        var tree = path.getLeaf();
        var ancestors = target.ancestors();
        if (tree instanceof BlockTree block) {
            for (var statement : block.getStatements()) {
                var next = child(path, statement);
                if (ancestors.contains(statement)) return seek(next, target, env, guards);
                var outcome = execute(next, env, guards, 0);
                if (outcome.transfer() != Transfer.NEXT) {
                    return UNKNOWN.with(outcome.transfer() == Transfer.UNSUPPORTED ? outcome.value().steps() : List.of())
                        .with(step(next, "analysis_stopped_before_call"));
                }
            }
        }
        if (tree instanceof TryTree attempt && attempt.getResources().isEmpty() && ancestors.contains(attempt.getBlock())) {
            return seek(child(path, attempt.getBlock()), target, env, guards);
        }
        if (tree instanceof IfTree branch && !hasWrites(branch.getCondition())) {
            var condition = expression(child(path, branch.getCondition()), env, 0);
            if (condition.literal() instanceof Boolean selected) {
                var body = selected ? branch.getThenStatement() : branch.getElseStatement();
                if (body != null && ancestors.contains(body)) return seek(child(path, body), target, env,
                    context(guards, condition.steps(), step(path, selected ? "if_true" : "if_false")));
            }
        }
        if (tree instanceof SwitchTree branch) {
            var outcome = choose(path, branch, env, guards, 0, target);
            if (outcome.transfer() == Transfer.TARGET || outcome.transfer() == Transfer.UNSUPPORTED) return outcome.value();
            return unknownAt(path, "switch_target_not_reached");
        }
        var call = target.call();
        Tree rhs = tree instanceof ExpressionStatementTree statement ? statement.getExpression()
            : tree instanceof VariableTree local ? local.getInitializer() : tree instanceof ReturnTree ret ? ret.getExpression() : null;
        if (rhs instanceof AssignmentTree assignment && assignment.getVariable() instanceof IdentifierTree
                && assignment.getExpression() == call.tree()) {
            var assigned = probe.trees.getElement(child(child(path, assignment), assignment.getVariable()));
            if (assigned != null && assigned.getKind() == ElementKind.LOCAL_VARIABLE) {
                rhs = assignment.getExpression();
            }
        }
        if (rhs == call.tree() && !hasWrites(rhs)) {
            return expression(child(call.path(), call.tree().getArguments().get(target.index())), env, 0).with(guards);
        }
        return unknownAt(path, "scope_before_call_not_modeled");
    }

    private static TreePath enclosingMethod(SqlEndpointProbe.Call call) {
        if (call.enclosing() == null) return null;
        var method = call.path();
        while (method != null && method.getLeaf() != call.enclosing()) method = method.getParentPath();
        return method;
    }

    private Map<Element, Value> initialEnvironment(TreePath method) {
        var env = new HashMap<Element, Value>();
        for (var param : ((MethodTree) method.getLeaf()).getParameters()) {
            env.put(probe.trees.getElement(child(method, param)), UNKNOWN);
        }
        return env;
    }

    private Value evaluateArgument(SqlEndpointProbe.Call call, int argumentIndex, TreePath method, Map<Element, Value> env) {
        if (method == null || call.enclosing().getBody() == null) return UNKNOWN;
        var ancestors = Collections.newSetFromMap(new IdentityHashMap<Tree, Boolean>());
        for (var path = call.path(); path != method; path = path.getParentPath()) {
            ancestors.add(path.getLeaf());
        }
        return seek(child(method, call.enclosing().getBody()), new ArgumentTarget(call, argumentIndex, ancestors), env, List.of());
    }

    private SqlEndpointProbe.Call incomingCall(TreePath method) {
        var included = List.of(System.getProperty("sql.evidence.snapshotCallers", "").split(","));
        var target = probe.trees.getElement(method);
        if (!(target instanceof ExecutableElement executable)
                || executable.isVarArgs() || executable.getParameters().size() > 8) return null;
        var matches = probe.calls.stream().filter(call -> call.target().equals(target)).toList();
        if (matches.size() != 1) return null;
        var call = matches.get(0);
        return included.contains(call.file()) && call.enclosing() != null && fixedDispatch(call)
            && call.tree().getArguments().size() == executable.getParameters().size() ? call : null;
    }

    private Value fromCaller(SqlEndpointProbe.Call sink, TreePath method, SqlEndpointProbe.Call caller) {
        var callerMethod = enclosingMethod(caller);
        if (callerMethod == null) return UNKNOWN;
        var env = initialEnvironment(method);
        var params = sink.enclosing().getParameters();
        for (int i = 0; i < params.size(); i++) {
            var parameter = child(method, params.get(i));
            var argument = child(caller.path(), caller.tree().getArguments().get(i));
            var symbol = probe.trees.getElement(parameter);
            if (symbol == null) return UNKNOWN;
            SqlEndpointProbe.emit("A", sink.line(), sink.column(), caller.file(), caller.line(), caller.column(),
                caller.owner(), caller.signature(), i + 1, probe.line(argument.getCompilationUnit(), argument.getLeaf()),
                probe.line(parameter.getCompilationUnit(), parameter.getLeaf()));
            var value = convert(evaluateArgument(caller, i, callerMethod, initialEnvironment(callerMethod)),
                                symbol.asType().toString());
            env.put(symbol, value.with(step(argument, "caller_argument")).with(step(parameter, "callee_parameter")));
        }
        return evaluateArgument(sink, 0, method, env);
    }

    private void emitCallerSources(Value result) {
        if (!result.status().equals("external_input_contributes")) return;
        for (var fact : result.steps()) {
            if (fact.file().equals("F0") || !fact.role().equals("servlet_request_read")) continue;
            var reads = probe.calls.stream().filter(call -> call.file().equals(fact.file()) && call.line() == fact.line()
                && call.readsRequest() && probe.trees.getPath(call.target()) == null).toList();
            if (reads.size() == 1) {
                var read = reads.get(0);
                SqlEndpointProbe.emit("I", read.file(), read.line(), read.column(), read.owner(), read.signature());
            }
        }
    }

    private void sourceCandidates(SqlEndpointProbe.Call sink, SqlEndpointProbe.Call caller) {
        for (var call : probe.calls) {
            var inSink = call.file().equals(sink.file()) && call.enclosing() == sink.enclosing() && call.line() <= sink.line();
            var inCaller = caller != null && call.file().equals(caller.file())
                && call.enclosing() == caller.enclosing() && call.line() <= caller.line();
            var type = probe.trees.getTypeMirror(call.path());
            if ((!inSink && !inCaller) || !type.toString().equals("java.lang.String") || call.sqlArgument()) continue;
            var definition = probe.trees.getPath(call.target());
            if (definition != null && definition.getLeaf() instanceof MethodTree method
                    && method.getBody() != null && probe.units.containsKey(definition.getCompilationUnit())) {
                var unit = definition.getCompilationUnit();
                var end = probe.trees.getSourcePositions().getEndPosition(unit, method);
                if (end > 0) {
                    SqlEndpointProbe.emit("C", call.file(), call.line(), call.column(), call.owner(), call.signature(),
                        fixedDispatch(call),
                        probe.units.get(unit), probe.line(unit, method), unit.getLineMap().getLineNumber(end - 1));
                }
            } else if (definition == null) {
                SqlEndpointProbe.emit("C", call.file(), call.line(), call.column(), call.owner(), call.signature(), fixedDispatch(call));
            }
        }
    }

    private void report(SqlEndpointProbe.Call sink) {
        var method = enclosingMethod(sink);
        Value result = UNKNOWN;
        if (method != null && sink.enclosing().getBody() != null) {
            var caller = System.getProperty("sql.evidence.snapshotCallers") == null ? null : incomingCall(method);
            if (Boolean.getBoolean("sql.evidence.sourceCandidates")) sourceCandidates(sink, caller);
            result = evaluateArgument(sink, 0, method, initialEnvironment(method));
            if (result.isUnknown() && caller != null) {
                var contextual = fromCaller(sink, method, caller);
                if (!contextual.isUnknown()) {
                    result = contextual;
                    emitCallerSources(result);
                }
            }
        }
        SqlEndpointProbe.emit("V", sink.line(), sink.column(), result.isConstant() ? "constant_sql_text" : result.status(), remaining < 0 ? "budget_exhausted" :
            result.isUnknown() ? "unsupported_or_runtime_value" : "bounded_java_evaluation");
        var facts = result.steps();
        if (result.isUnknown()) {
            var argument = child(sink.path(), sink.tree().getArguments().get(0));
            if (probe.trees.getElement(argument) instanceof VariableElement variable) {
                var declared = probe.trees.getPath(variable);
                if (declared != null) facts = result.with(step(declared, "sql_argument_variable_declaration")).steps();
            }
            facts = facts.subList(Math.max(0, facts.size() - 10), facts.size());
        }
        for (var fact : facts) SqlEndpointProbe.emit("E", sink.line(), sink.column(), fact.file(), fact.line(), fact.role());
    }
}
