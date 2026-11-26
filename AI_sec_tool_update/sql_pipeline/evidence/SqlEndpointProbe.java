import com.sun.source.tree.*;
import com.sun.source.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.BiConsumer;
import javax.lang.model.element.*;
import javax.lang.model.type.TypeKind;
import javax.lang.model.util.Elements;
import javax.tools.*;

/** Attribute calls in a supplied Java snapshot without running or generating application code. */
class SqlEndpointProbe {
    private static final Set<String> REQUEST = Set.of(
        "javax.servlet.ServletRequest", "jakarta.servlet.ServletRequest",
        "javax.servlet.http.HttpServletRequest", "jakarta.servlet.http.HttpServletRequest");
    private static final Set<String> READS = Set.of(
        "getParameter", "getParameterValues", "getParameterMap", "getParameterNames",
        "getHeader", "getHeaders", "getCookies", "getQueryString", "getPathInfo",
        "getRequestURI", "getInputStream", "getReader");
    private static final Set<String> SQL_EXECUTIONS = Set.of(
        "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch");
    private static final Set<String> JDBC = Set.of(
        "java.sql.Connection", "java.sql.Statement", "java.sql.PreparedStatement", "java.sql.CallableStatement");
    private static final Set<String> SPRING_JDBC = Set.of(
        "org.springframework.jdbc.core.JdbcOperations", "org.springframework.jdbc.core.JdbcTemplate");
    private static final Set<String> SPRING_SQL_EXECUTIONS = Set.of(
        "execute", "update", "query", "queryForList", "queryForMap", "queryForObject", "queryForRowSet",
        "queryForStream", "batchUpdate");
    private static final Set<String> PARAMETER_BINDINGS = Set.of(
        "setString", "setNString", "setInt", "setLong", "setShort", "setByte", "setObject",
        "setNull", "setBoolean", "setDate", "setTime", "setTimestamp", "setBigDecimal",
        "setBytes", "setDouble", "setFloat", "setArray", "setBinaryStream", "setCharacterStream");

    final Trees trees;
    final Elements elements;
    final Map<CompilationUnitTree, String> units;
    final List<Call> calls = new ArrayList<>();
    private final Set<Element> reassigned = new HashSet<>();

    record Call(TreePath path, MethodInvocationTree tree, ExecutableElement target,
                        Element receiver, MethodTree enclosing, String file, long line, long column) {
        String owner() { return ((TypeElement) target.getEnclosingElement()).getQualifiedName().toString(); }
        String name() { return target.getSimpleName().toString(); }
        String signature() { return target.toString(); }
        boolean readsRequest() { return REQUEST.contains(owner()) && READS.contains(name()); }
        boolean springSql() { return SPRING_JDBC.contains(owner()) && SPRING_SQL_EXECUTIONS.contains(name()); }
        boolean sqlArgument() {
            if (tree.getArguments().isEmpty()) return false;
            // The evidence pipeline anchors a single SQL text argument per call.
            if (springSql() && target.isVarArgs() && firstParameter("java.lang.String[]")) {
                return tree.getArguments().size() == 1;
            }
            if (!firstParameter("java.lang.String")) return false;
            return springSql()
                || (owner().equals("java.sql.Connection") && Set.of("prepareStatement", "prepareCall").contains(name()))
                || (JDBC.contains(owner()) && SQL_EXECUTIONS.contains(name()));
        }
        boolean binding() {
            return (owner().equals("java.sql.PreparedStatement") || owner().equals("java.sql.CallableStatement"))
                && PARAMETER_BINDINGS.contains(name()) && firstParameter("int") && tree.getArguments().size() >= 2;
        }
        boolean firstParameter(String type) {
            var params = target.getParameters();
            return !params.isEmpty() && params.get(0).asType().toString().equals(type);
        }
    }

    private SqlEndpointProbe(Trees trees, Elements elements, Map<CompilationUnitTree, String> units) {
        this.trees = trees;
        this.elements = elements;
        this.units = units;
    }

    long line(CompilationUnitTree unit, Tree tree) {
        long start = trees.getSourcePositions().getStartPosition(unit, tree);
        return start < 0 ? -1 : unit.getLineMap().getLineNumber(start);
    }

    private final class Scan extends TreePathScanner<Void, Void> {
        @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
            var path = getCurrentPath();
            var type = trees.getTypeMirror(path);
            if (trees.getElement(path) instanceof ExecutableElement target
                    && type != null && type.getKind() != TypeKind.ERROR) {
                var select = tree.getMethodSelect();
                var unit = path.getCompilationUnit();
                long end = trees.getSourcePositions().getEndPosition(unit, select);
                if (end >= 0) {
                    long at = end - target.getSimpleName().length();
                    var enclosing = path.getParentPath();
                    while (enclosing != null && !(enclosing.getLeaf() instanceof MethodTree)) {
                        enclosing = enclosing.getParentPath();
                    }
                    Element receiver = null;
                    if (select instanceof MemberSelectTree member) {
                        receiver = trees.getElement(new TreePath(new TreePath(path, select), member.getExpression()));
                    }
                    calls.add(new Call(path, tree, target, receiver,
                        enclosing == null ? null : (MethodTree) enclosing.getLeaf(), units.get(unit),
                        unit.getLineMap().getLineNumber(at), unit.getLineMap().getColumnNumber(at)));
                }
            }
            return super.visitMethodInvocation(tree, unused);
        }

        @Override public Void visitAssignment(AssignmentTree node, Void unused) {
            var symbol = trees.getElement(new TreePath(getCurrentPath(), node.getVariable()));
            if (symbol != null) reassigned.add(symbol);
            return super.visitAssignment(node, unused);
        }
    }

    VariableTree stableLocal(Element symbol) {
        if (symbol == null || symbol.getKind() != ElementKind.LOCAL_VARIABLE || reassigned.contains(symbol)) return null;
        return trees.getTree(symbol) instanceof VariableTree variable ? variable : null;
    }

    String dispatch(Call call) {
        var target = call.target();
        var modifiers = target.getModifiers();
        if (modifiers.contains(Modifier.STATIC) || modifiers.contains(Modifier.PRIVATE)
                || modifiers.contains(Modifier.FINAL) || target.getEnclosingElement().getModifiers().contains(Modifier.FINAL)) {
            return "fixed_declaration";
        }
        var local = stableLocal(call.receiver());
        if (local != null && local.getInitializer() instanceof NewClassTree init && init.getClassBody() == null
                && target.getEnclosingElement().asType().toString().equals(call.receiver().asType().toString())) {
            var declaration = trees.getPath(call.receiver());
            var type = trees.getTypeMirror(new TreePath(declaration, init));
            if (type != null && type.toString().equals(call.owner())) return "exact_local_constructor";
        }
        return "declaration_only";
    }

    static void emit(Object... fields) {
        System.out.println(String.join("\t", Arrays.stream(fields).map(Object::toString).toList()));
    }

    private long argumentLine(Call call, int index) {
        return line(call.path().getCompilationUnit(), call.tree().getArguments().get(index));
    }

    private void reportSpringBindings(Call sink) {
        var parameters = sink.target().getParameters();
        if (parameters.size() < 2) return;
        int last = parameters.size() - 1;
        // Spring overloads accept either an explicit Object[] after SQL or trailing Object varargs.
        // Result types, callbacks and JDBC type arrays have different roles.
        if (sink.target().isVarArgs() && parameters.get(last).asType().toString().equals("java.lang.Object[]")) {
            for (int index = last; index < sink.tree().getArguments().size(); index++) {
                emit("T", sink.line(), sink.column(), index + 1, argumentLine(sink, index));
            }
        } else if (parameters.get(1).asType().toString().equals("java.lang.Object[]")) {
            emit("T", sink.line(), sink.column(), 2, argumentLine(sink, 1));
        }
    }

    private void report(long start, long end, BiConsumer<SqlEndpointProbe, Call> inspectValue) {
        var sinks = calls.stream().filter(c -> c.file().equals("F0") && c.line() >= start && c.line() <= end
            && c.sqlArgument() && trees.getPath(c.target()) == null).filter(c -> {
                var type = trees.getTypeMirror(new TreePath(c.path(), c.tree().getArguments().get(0)));
                return type != null && type.toString().equals("java.lang.String");
            }).toList();
        for (Call sink : sinks) {
            emit("Q", sink.file(), sink.line(), sink.column(), sink.owner(), sink.signature(), argumentLine(sink, 0));
            if (inspectValue != null) inspectValue.accept(this, sink);
            if (sink.springSql()) reportSpringBindings(sink);
            for (Call binding : calls) {
                if (binding.enclosing() != sink.enclosing() || !binding.binding() || binding.line() < sink.line()) continue;
                var variable = stableLocal(binding.receiver());
                if (variable != null && variable.getInitializer() == sink.tree()) {
                    emit("B", sink.line(), sink.column(), binding.line(), binding.owner(), binding.signature(), argumentLine(binding, 1));
                }
            }
        }
        for (Call call : calls) {
            if (!call.file().equals("F0") || call.line() > end) continue;
            boolean nearSink = call.enclosing() != null && sinks.stream().anyMatch(s -> s.enclosing() == call.enclosing());
            if (call.readsRequest() && trees.getPath(call.target()) == null) {
                emit("S", call.line(), call.column(), call.owner(), call.signature(), nearSink);
            }
            var definition = trees.getPath(call.target());
            if (definition == null || !units.containsKey(definition.getCompilationUnit())
                    || !(definition.getLeaf() instanceof MethodTree method) || method.getBody() == null) continue;
            var statements = method.getBody().getStatements();
            if (statements.size() != 1 || !(statements.get(0) instanceof ReturnTree result)) continue;
            for (Call read : calls) {
                if (read.tree() == result.getExpression() && read.readsRequest() && trees.getPath(read.target()) == null) {
                    emit("H", call.line(), call.column(), call.owner(), call.signature(), nearSink, read.file(),
                        read.line(), read.owner(), read.signature(), dispatch(call));
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        run(args, null);
    }

    static void run(String[] args, BiConsumer<SqlEndpointProbe, Call> inspectValue) throws Exception {
        var compiler = ToolProvider.getSystemJavaCompiler();
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var files = new LinkedHashMap<Path, String>();
        boolean projectSources = Boolean.getBoolean("sql.evidence.projectServletSources");
        if (projectSources) {
            for (String line : Files.readAllLines(Path.of(args[4]))) {
                var entry = line.split("\t", 2);
                files.put(Path.of(entry[1]), entry[0]);
            }
        } else {
            for (int i = 4; i < args.length; i += 2) files.put(Path.of(args[i + 1]), args[i]);
        }
        try (var manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, java.nio.charset.StandardCharsets.UTF_8)) {
            var task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                List.of("-proc:none", "-classpath", args[2], "-sourcepath", args[3], "-implicit:none"),
                null, manager.getJavaFileObjectsFromPaths(files.keySet()));
            var units = new LinkedHashMap<CompilationUnitTree, String>();
            for (var unit : task.parse()) units.put(unit, files.get(Path.of(unit.getSourceFile().toUri())));
            task.analyze();
            var probe = new SqlEndpointProbe(Trees.instance(task), task.getElements(), units);
            var scanner = probe.new Scan();
            for (var unit : units.keySet()) scanner.scan(unit, null);
            long errors = diagnostics.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count();
            emit("STATUS", errors);
            if (projectSources) {
                for (var call : probe.calls) {
                    if (call.readsRequest() && probe.trees.getPath(call.target()) == null) {
                        emit("P", call.file(), call.line(), call.column(), call.owner(), call.signature());
                    }
                }
            } else {
                probe.report(Long.parseLong(args[0]), Long.parseLong(args[1]), inspectValue);
            }
        }
    }
}
