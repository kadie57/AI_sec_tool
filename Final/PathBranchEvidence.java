/* Bounded local-int branch audit. Parses input with javac; NEVER executes it.
 * Requires JDK 17+. Only straight-line local int/boolean values are evaluated.
 * Unsupported control flow invalidates written locals and is not explored.
 * Output is supplementary expression evidence, never a vulnerability verdict.
 */
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class PathBranchEvidence {
    static final String VERSION = "java-local-branch-evidence-v1";
    static final Object UNKNOWN = new Object();
    record Binding(String type, Object value, List<Long> evidence) {}
    static class Audit {
        CompilationUnitTree unit;
        SourcePositions positions;
        String source;
        Deque<Map<String, Binding>> scopes = new ArrayDeque<>();
        List<Map<String, Object>> facts = new ArrayList<>();
        int skipped = 0;
        Audit(CompilationUnitTree u, SourcePositions p, String s) {
            unit=u; positions=p; source=s;
        }
        long line(Tree t) { return unit.getLineMap().getLineNumber(positions.getStartPosition(unit,t)); }
        String code(Tree t) {
            long a=positions.getStartPosition(unit,t), b=positions.getEndPosition(unit,t);
            return a>=0 && b>=a && b<=source.length() ? source.substring((int)a,(int)b) : t.toString();
        }
        Binding binding(String name) {
            for (var scope:scopes) if(scope.containsKey(name)) return scope.get(name);
            return null; // Fields, getters and other-file definitions stay unknown.
        }
        void assign(String name, Object value, List<Long> lines) {
            for(var scope:scopes) if(scope.containsKey(name)) {
                Binding old=scope.get(name);
                boolean compatible=(old.type().equals("int") && value instanceof Integer)
                    || (old.type().equals("boolean") && value instanceof Boolean);
                scope.put(name,new Binding(old.type(),compatible?value:UNKNOWN,lines)); return;
            }
        }
        String localName(ExpressionTree tree) {
            while(tree instanceof ParenthesizedTree p) tree=p.getExpression();
            return tree instanceof IdentifierTree id ? id.getName().toString() : null;
        }
        void invalidate(Tree tree) {
            new TreeScanner<Void,Void>() {
                void kill(ExpressionTree t) {
                    String name=localName(t);
                    if(name!=null) assign(name,UNKNOWN,List.of());
                }
                @Override public Void visitAssignment(AssignmentTree t,Void p) {
                    kill(t.getVariable()); return super.visitAssignment(t,p);
                }
                @Override public Void visitCompoundAssignment(CompoundAssignmentTree t,Void p) {
                    kill(t.getVariable()); return super.visitCompoundAssignment(t,p);
                }
                @Override public Void visitUnary(UnaryTree t,Void p) {
                    switch(t.getKind()) {
                        case PREFIX_INCREMENT, PREFIX_DECREMENT, POSTFIX_INCREMENT, POSTFIX_DECREMENT -> kill(t.getExpression());
                        default -> {}
                    }
                    return super.visitUnary(t,p);
                }
            }.scan(tree,null);
        }
        List<Long> dependencies(Tree tree) {
            TreeSet<Long> lines=new TreeSet<>();
            new TreeScanner<Void,Void>() {
                @Override public Void visitIdentifier(IdentifierTree t,Void p) {
                    Binding b=binding(t.getName().toString());
                    if(b!=null && b.value()!=UNKNOWN) lines.addAll(b.evidence());
                    return null;
                }
            }.scan(tree,null);
            return new ArrayList<>(lines);
        }
        Object evaluate(ExpressionTree tree) {
            if(tree==null) return UNKNOWN;
            if(tree instanceof ParenthesizedTree p) return evaluate(p.getExpression());
            if(tree instanceof LiteralTree l) {
                Object v=l.getValue();
                return v instanceof Integer || v instanceof Boolean ? v : UNKNOWN;
            }
            if(tree instanceof IdentifierTree id) {
                Binding b=binding(id.getName().toString()); return b==null?UNKNOWN:b.value();
            }
            if(tree instanceof UnaryTree u) {
                Object v=evaluate(u.getExpression());
                if(v instanceof Integer n) return switch(u.getKind()) {
                    case UNARY_PLUS -> n; case UNARY_MINUS -> -n; case BITWISE_COMPLEMENT -> ~n;
                    default -> UNKNOWN;
                };
                if(v instanceof Boolean b && u.getKind()==Tree.Kind.LOGICAL_COMPLEMENT) return !b;
                return UNKNOWN;
            }
            if(tree instanceof BinaryTree b) {
                Object l=evaluate(b.getLeftOperand()), r=evaluate(b.getRightOperand());
                if(l instanceof Integer x && r instanceof Integer y) {
                    // Java performs these operations in int, including wraparound.
                    return switch(b.getKind()) {
                        case PLUS -> x+y; case MINUS -> x-y; case MULTIPLY -> x*y;
                        case DIVIDE -> y==0?UNKNOWN:x/y; case REMAINDER -> y==0?UNKNOWN:x%y;
                        case LESS_THAN -> x<y; case LESS_THAN_EQUAL -> x<=y;
                        case GREATER_THAN -> x>y; case GREATER_THAN_EQUAL -> x>=y;
                        case EQUAL_TO -> x.intValue()==y.intValue(); case NOT_EQUAL_TO -> x.intValue()!=y.intValue();
                        default -> UNKNOWN;
                    };
                }
                if(l instanceof Boolean x && r instanceof Boolean y) return switch(b.getKind()) {
                    case EQUAL_TO -> x.equals(y); case NOT_EQUAL_TO -> !x.equals(y);
                    case CONDITIONAL_AND -> x && y; case CONDITIONAL_OR -> x || y;
                    default -> UNKNOWN;
                };
            }
            // No calls, fields, casts, long/float promotion, or numeric ?: typing.
            return UNKNOWN;
        }
        void inspect(ExpressionTree expression) {
            // Do not scan arbitrary children: nested lambdas/classes have other scopes.
            if(expression instanceof ParenthesizedTree p) { inspect(p.getExpression()); return; }
            if(!(expression instanceof ConditionalExpressionTree c)) return;
            Object condition=evaluate(c.getCondition());
            if(!(condition instanceof Boolean chosen)) { skipped++; return; }
            ExpressionTree selected=chosen?c.getTrueExpression():c.getFalseExpression();
            Map<String,Object> f=new LinkedHashMap<>();
            f.put("line",line(c)); f.put("condition",code(c.getCondition()));
            f.put("condition_value",chosen); f.put("selected_arm",chosen?"true":"false");
            f.put("selected_expression",code(selected));
            // Literal information only; not proof of this value reaching a sink.
            if(selected instanceof LiteralTree l && l.getValue() instanceof String)
                f.put("selected_string_literal",l.getValue());
            f.put("dependency_lines",dependencies(c.getCondition()));
            if(c.getCondition() instanceof BinaryTree b) {
                Object l=evaluate(b.getLeftOperand()),r=evaluate(b.getRightOperand());
                if(l!=UNKNOWN && r!=UNKNOWN) { f.put("left_value",l); f.put("right_value",r); }
            }
            facts.add(f);
        }
        void statement(StatementTree statement) {
            if(statement==null) return;
            if(statement instanceof BlockTree b) {
                scopes.push(new HashMap<>());
                for(var s:b.getStatements()) statement(s);
                scopes.pop(); return;
            }
            if(statement instanceof VariableTree v) {
                String name=v.getName().toString(), type=v.getType().toString();
                scopes.peek().put(name,new Binding(type,UNKNOWN,List.of()));
                invalidate(v.getInitializer()); inspect(v.getInitializer());
                var deps=dependencies(v.getInitializer()); deps.add(line(v));
                assign(name,evaluate(v.getInitializer()),deps); return;
            }
            if(statement instanceof ExpressionStatementTree e) {
                ExpressionTree expression=e.getExpression();
                if(expression instanceof AssignmentTree a && localName(a.getVariable())!=null) {
                    invalidate(a.getExpression()); inspect(a.getExpression());
                    var deps=dependencies(a.getExpression()); deps.add(line(a));
                    assign(localName(a.getVariable()),evaluate(a.getExpression()),deps);
                } else invalidate(expression);
                return;
            }
            if(statement instanceof ReturnTree r) {
                invalidate(r.getExpression()); inspect(r.getExpression()); return;
            }
            // Unknown if/loop/try/switch, catch/finally, or other statements:
            // invalidate *all* local names assigned inside, never pick a branch.
            // Over-invalidation under name shadowing is deliberate and conservative.
            invalidate(statement); skipped++;
        }
        void method(MethodTree method) {
            scopes.clear(); scopes.push(new HashMap<>());
            for(var p:method.getParameters()) scopes.peek().put(p.getName().toString(),
                new Binding(p.getType().toString(),UNKNOWN,List.of()));
            if(method.getBody()!=null) statement(method.getBody());
            scopes.clear();
        }
    }
    static String json(Object v) {
        if(v==null) return "null";
        if(v instanceof String s) {
            StringBuilder out=new StringBuilder("\"");
            for(char c:s.toCharArray()) {
                if(c=='"' || c=='\\') out.append('\\').append(c);
                else if(c<32) out.append(String.format("\\u%04x",(int)c));
                else out.append(c);
            }
            return out.append('"').toString();
        }
        if(v instanceof Map<?,?> m) {
            List<String> items=new ArrayList<>();
            m.forEach((k,x)->items.add(json(k.toString())+":"+json(x)));
            return "{"+String.join(",",items)+"}";
        }
        if(v instanceof Collection<?> c) return "["+String.join(",",c.stream().map(PathBranchEvidence::json).toList())+"]";
        return v.toString();
    }
    public static void main(String[] args) throws Exception {
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        if(compiler==null) throw new IllegalStateException("JDK compiler module is required");
        if(args.length!=1) throw new IllegalArgumentException("Expected one Java source file");
        String source=Files.readString(Path.of(args[0]),StandardCharsets.UTF_8);
        DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
        JavaFileObject input=new SimpleJavaFileObject(URI.create("string:///Input.java"),JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignore) { return source; }
        };
        try(var manager=compiler.getStandardFileManager(diagnostics,null,StandardCharsets.UTF_8)) {
            JavacTask task=(JavacTask)compiler.getTask(null,manager,diagnostics,List.of("-proc:none"),null,List.of(input));
            var units=task.parse(); // No analyze(), generate(), annotation processors or execution.
            List<Map<String,Object>> facts=new ArrayList<>(); int skipped=0;
            for(var unit:units) {
                Audit audit=new Audit(unit,Trees.instance(task).getSourcePositions(),source);
                // Only top-level class methods; no inherited/captured scope assumptions.
                for(var decl:unit.getTypeDecls()) if(decl instanceof ClassTree c)
                    for(var member:c.getMembers()) if(member instanceof MethodTree m) audit.method(m);
                facts.addAll(audit.facts); skipped+=audit.skipped;
            }
            if(diagnostics.getDiagnostics().stream().anyMatch(d->d.getKind()==Diagnostic.Kind.ERROR))
                throw new IllegalArgumentException("Java parse error; no evidence accepted");
            System.out.println(json(Map.of("version",VERSION,"status","PARSED_PARTIAL",
                "facts",facts,"unsupported_constructs",skipped,
                "scope","straight-line local int/boolean expressions; no sink reachability proof")));
        }
    }
}
