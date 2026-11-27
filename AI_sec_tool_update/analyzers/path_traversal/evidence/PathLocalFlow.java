import com.sun.source.tree.*;
import com.sun.source.util.*;
import java.util.*;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;
import javax.lang.model.element.*;
import javax.lang.model.type.TypeKind;

/** Tracks values reaching a typed filesystem operation, with optional bounded project evidence. */
final class PathLocalFlow {
    private static final Set<String> OPERATIONS = Set.of("file_read", "file_write", "file_io", "file_metadata");
    private static final Set<String> PATH_VALUES = Set.of("java.io.File", "java.nio.file.Path", "java.lang.String");
    private static final Set<String> DERIVATIONS = Set.of(
        "path_construction", "lexical_normalization", "canonicalization", "basename_extraction");
    private static final int MAX_EVIDENCE_LINES = 24;

    private static final int MAX_HELPER_DEPTH = 3;
    private static final int MAX_COLLECTION_ENTRIES = 16;
    private static final String STRING = "java.lang.String";
    private static final String HASH_MAP = "java.util.HashMap";
    private static final String ARRAY_LIST = "java.util.ArrayList";
    private static final Set<String> API_FLOW_FACTS = Set.of(
        "http_header_enumeration", "header_availability_guard_true", "header_element_from_receiver",
        "url_decode_from_argument_1");
    private static final Set<String> HELPER_DECISION_FACTS = Set.of(
        "if_true", "if_false", "conditional_true", "conditional_false", "switch_case_selected");
    private static final String FIXED_ALTERNATIVE = "fixed_alternative_";
    private static final Set<String> LIST_ALTERNATIVE_FACTS = Set.of(
        "list_append", "list_remove_index", "list_get_by_index", "local_definition", "local_assignment");

    private enum Origin {
        FIXED_VALUE, CONFIGURATION_VALUE, EXTERNAL_INPUT_IN_EXPRESSION, POSSIBLE_EXTERNAL_INPUT_IN_EXPRESSION,
        HTTP_HEADER_ENUMERATION, LOCAL_COLLECTION, UNKNOWN
    }
    private enum CollectionOperation {
        MAP_GET, MAP_PUT, LIST_GET, LIST_APPEND, LIST_REMOVE_INDEX;

        boolean reads() { return this == MAP_GET || this == LIST_GET; }
    }
    private record LocalMap(Map<String, Value> entries) {}
    private record LocalList(List<Value> entries) {}
    private record ApiSignature(String owner, String name, List<String> parameters) {}
    private enum Propagation { HEADER_ELEMENT_FROM_RECEIVER, URL_DECODE_FROM_ARGUMENT_1, STRING_REPLACE_CHARS }
    private static final Map<ApiSignature, Propagation> API_SUMMARIES = Map.of(
        new ApiSignature("java.util.Enumeration", "nextElement", List.of()), Propagation.HEADER_ELEMENT_FROM_RECEIVER,
        new ApiSignature("java.net.URLDecoder", "decode", List.of(STRING, STRING)), Propagation.URL_DECODE_FROM_ARGUMENT_1,
        new ApiSignature("java.net.URLDecoder", "decode", List.of(STRING, "java.nio.charset.Charset")),
            Propagation.URL_DECODE_FROM_ARGUMENT_1,
        new ApiSignature(STRING, "replace", List.of("char", "char")), Propagation.STRING_REPLACE_CHARS);
    private record Fact(String file, long first, long last, String role, boolean inHelper) {}
    private record HeaderGuard(Element receiver, Value binding, Fact check) {}
    private record Controls(Set<Long> lines, Set<Fact> facts, Set<HeaderGuard> headerGuards) {}
    private static final Controls ENTRY = new Controls(Set.of(), Set.of(), Set.of());

    private record Value(Origin origin, Object literal, Set<Integer> sites, Set<Long> lines,
                         Set<Long> fixedDefinitions, Set<Fact> facts) {
        Value(Origin origin, Object literal, Set<Integer> sites, Set<Long> lines, Set<Long> fixedDefinitions) {
            this(origin, literal, sites, lines, fixedDefinitions, Set.of());
        }

        Value withFacts(Collection<Fact> extra) {
            return new Value(origin, literal, sites, lines, fixedDefinitions, union(facts, extra));
        }

        Value under(Controls controls) {
            return withLines(controls.lines()).withFacts(controls.facts());
        }

        Value withLines(Collection<Long> extra) {
            return new Value(origin, literal, sites, union(lines, extra), fixedDefinitions, facts);
        }

        Value definedAt(long line) {
            return new Value(origin, literal, sites, union(lines, Set.of(line)),
                origin == Origin.FIXED_VALUE ? union(fixedDefinitions, Set.of(line)) : fixedDefinitions, facts);
        }

        Value derivedAt(int site, long line) {
            return new Value(origin, null, union(sites, Set.of(site)), union(lines, Set.of(line)), fixedDefinitions, facts);
        }
    }

    private static final Value UNKNOWN = new Value(Origin.UNKNOWN, null, Set.of(), Set.of(), Set.of());
    private final Trees trees;
    private final Map<Tree, PathEvidenceProbe.Site> sites;
    private final ToLongFunction<Tree> line;
    private final CompilationUnitTree unit;
    private final Map<CompilationUnitTree, String> files;
    private final int depth;
    private final List<Value> returns;
    private boolean unsupported;
    private int budget = 1500;

    PathLocalFlow(Trees trees, Map<Tree, PathEvidenceProbe.Site> sites, ToLongFunction<Tree> line,
                  CompilationUnitTree unit, Map<CompilationUnitTree, String> files) {
        this(trees, sites, line, unit, files, 0, null);
    }

    private PathLocalFlow(Trees trees, Map<Tree, PathEvidenceProbe.Site> sites, ToLongFunction<Tree> line,
                          CompilationUnitTree unit, Map<CompilationUnitTree, String> files,
                          int depth, List<Value> returns) {
        this.trees = trees;
        this.sites = sites;
        this.line = line;
        this.unit = unit;
        this.files = files;
        this.depth = depth;
        this.returns = returns;
    }

    private PathLocalFlow nested(TreePath path, List<Value> returned) {
        var childUnit = path.getCompilationUnit();
        return new PathLocalFlow(trees, Map.of(),
            tree -> lineAt(childUnit, trees.getSourcePositions().getStartPosition(childUnit, tree)),
            childUnit, files, depth + 1, returned);
    }

    private static long lineAt(CompilationUnitTree unit, long position) {
        return position < 0 ? -1 : unit.getLineMap().getLineNumber(position);
    }

    private Fact fact(Tree tree, String role) {
        return new Fact(files.get(unit), line.applyAsLong(tree), line.applyAsLong(tree), role, returns != null);
    }

    private Controls selected(Controls controls, Value condition, Tree decision, String role, Tree skipped) {
        var lines = union(controls.lines(), condition.lines);
        if (files == null) return new Controls(lines, controls.facts(), controls.headerGuards());
        var facts = union(controls.facts(), condition.facts);
        facts.add(fact(decision, role));
        if (skipped != null) exclude(facts, skipped, line.applyAsLong(skipped) + 1, Long.MAX_VALUE);
        return new Controls(lines, facts, controls.headerGuards());
    }

    private void exclude(Set<Fact> facts, Tree tree, long first, long before) {
        long end = trees.getSourcePositions().getEndPosition(unit, tree);
        long last = Math.min(lineAt(unit, end - 1) - 1, before - 1);
        // Exclude shared boundary lines where Joern may also locate a reachable sibling.
        if (first <= last) facts.add(new Fact(files.get(unit), first, last,
            depth == 0 ? "excluded_branch" : "excluded_helper_branch", returns != null));
    }

    private Value explained(Value value, Tree tree, String role) {
        return files == null ? value : value.withFacts(Set.of(fact(tree, role)));
    }

    void analyze(TreePath path) {
        var method = (MethodTree) path.getLeaf();
        statement(child(path, method.getBody()), new HashMap<>(), ENTRY);
    }

    private static TreePath child(TreePath path, Tree tree) { return new TreePath(path, tree); }

    private static <T> Set<T> union(Set<T> first, Collection<T> second) {
        var result = new LinkedHashSet<>(first);
        result.addAll(second);
        return result;
    }

    private static <T> Set<T> intersection(Set<T> first, Set<T> second) {
        var result = new LinkedHashSet<>(first);
        result.retainAll(second);
        return result;
    }

    private static boolean local(Element element) {
        return element != null && switch (element.getKind()) {
            case LOCAL_VARIABLE, RESOURCE_VARIABLE, PARAMETER, EXCEPTION_PARAMETER -> true;
            default -> false;
        };
    }

    private Value literal(Tree tree, Object value) {
        return value instanceof String || value instanceof Integer || value instanceof Boolean || (files != null && value instanceof Character)
            ? new Value(Origin.FIXED_VALUE, value, Set.of(), Set.of(line.applyAsLong(tree)), Set.of()) : UNKNOWN;
    }

    private static Value combine(Value left, Value right) {
        Origin origin = Origin.UNKNOWN;
        if (left.origin == Origin.EXTERNAL_INPUT_IN_EXPRESSION || right.origin == Origin.EXTERNAL_INPUT_IN_EXPRESSION) {
            origin = Origin.EXTERNAL_INPUT_IN_EXPRESSION;
        } else if (externalScalar(left.origin) || externalScalar(right.origin)) {
            origin = Origin.POSSIBLE_EXTERNAL_INPUT_IN_EXPRESSION;
        } else if (modeledScalar(left.origin) && modeledScalar(right.origin)) {
            origin = left.origin == Origin.CONFIGURATION_VALUE || right.origin == Origin.CONFIGURATION_VALUE
                ? Origin.CONFIGURATION_VALUE : Origin.FIXED_VALUE;
        }
        return new Value(origin, null, union(left.sites, right.sites), union(left.lines, right.lines),
            union(left.fixedDefinitions, right.fixedDefinitions), union(left.facts, right.facts));
    }

    private static boolean externalScalar(Origin origin) {
        return origin == Origin.EXTERNAL_INPUT_IN_EXPRESSION || origin == Origin.POSSIBLE_EXTERNAL_INPUT_IN_EXPRESSION;
    }

    private static boolean modeledScalar(Origin origin) {
        return externalScalar(origin) || origin == Origin.FIXED_VALUE || origin == Origin.CONFIGURATION_VALUE;
    }

    private static Value join(Value first, Value second) {
        var origin = first.origin == second.origin ? first.origin : Origin.UNKNOWN;
        var commonValue = Objects.equals(first.literal, second.literal) ? first.literal : null;
        var sharedFacts = intersection(first.facts, second.facts);
        if (origin == Origin.FIXED_VALUE) {
            var branchFacts = union(first.facts, second.facts);
            if (branchFacts.stream().anyMatch(fact -> fact.role().equals("list_get_by_index")
                    || fact.role().equals(FIXED_ALTERNATIVE + "list_get_by_index"))) {
                // Both branches yield fixed values. Keep branch-only witnesses without making them unconditional.
                branchFacts.removeAll(sharedFacts);
                for (var fact : branchFacts) {
                    if (LIST_ALTERNATIVE_FACTS.contains(fact.role())) {
                        sharedFacts.add(new Fact(fact.file(), fact.first(), fact.last(),
                            FIXED_ALTERNATIVE + fact.role(), fact.inHelper()));
                    } else if (fact.role().startsWith(FIXED_ALTERNATIVE)) {
                        sharedFacts.add(fact);
                    }
                }
            }
        } else if (modeledScalar(first.origin) && modeledScalar(second.origin)
                && (externalScalar(first.origin) || externalScalar(second.origin))) {
            var apiFacts = union(first.facts, second.facts).stream()
                .filter(fact -> API_FLOW_FACTS.contains(fact.role())).toList();
            if (!apiFacts.isEmpty()) {
                // Only propagate the API evidence across alternatives. Branch exclusions still require agreement.
                if (first.origin != second.origin) origin = Origin.POSSIBLE_EXTERNAL_INPUT_IN_EXPRESSION;
                sharedFacts.addAll(apiFacts);
            }
        }
        return new Value(origin, commonValue, intersection(first.sites, second.sites), union(first.lines, second.lines),
            intersection(first.fixedDefinitions, second.fixedDefinitions), sharedFacts);
    }

    private static void merge(Map<Element, Value> env, Map<Element, Value> left, Map<Element, Value> right) {
        env.clear();
        for (var symbol : union(left.keySet(), right.keySet())) {
            env.put(symbol, join(left.getOrDefault(symbol, UNKNOWN), right.getOrDefault(symbol, UNKNOWN)));
        }
    }

    private static String csv(Collection<? extends Number> values) {
        return values.stream().map(Number::longValue).filter(value -> value > 0).distinct().sorted()
            .limit(MAX_EVIDENCE_LINES).map(String::valueOf).collect(Collectors.joining(","));
    }

    private void use(PathEvidenceProbe.Site operation, int argument, Value value, Controls controls) {
        var producers = union(value.sites, Set.of(operation.id()));
        var references = union(value.lines, controls.lines());
        references.add(operation.line());
        System.out.printf("USE\t%d\t%d\t%s\t%s\t%s\t%s%n", operation.id(), argument,
            value.origin.name().toLowerCase(Locale.ROOT), csv(producers), csv(references), csv(value.fixedDefinitions));
        if (files != null) {
            var facts = union(value.facts, controls.facts());
            boolean headerRoute = externalScalar(value.origin)
                && facts.stream().anyMatch(item -> item.role().equals("header_availability_guard_true"));
            for (var item : facts.stream().limit(MAX_EVIDENCE_LINES).toList()) {
                if (item.file() != null && item.first() > 0 && item.last() >= item.first()) {
                    String role = headerRoute && item.inHelper() && HELPER_DECISION_FACTS.contains(item.role())
                        ? "helper_" + item.role() : item.role();
                    System.out.printf("FACT\t%d\t%d\t%s\t%d\t%d\t%s%n", operation.id(), argument,
                        item.file(), item.first(), item.last(), role);
                }
            }
        }
    }

    private void recordOperation(PathEvidenceProbe.Site site, Value receiver, List<Value> args, Controls controls) {
        if (site.owner().equals("java.io.File") && !site.method().equals("<init>")) {
            use(site, 0, receiver, controls);
            return;
        }
        for (int index = 0; index < Math.min(args.size(), site.parameters().size()); index++) {
            var parameter = site.parameters().get(index);
            if (site.owner().equals("java.nio.file.Files") ? parameter.equals("java.nio.file.Path") : PATH_VALUES.contains(parameter)) {
                use(site, index + 1, args.get(index), controls);
            }
        }
    }

    private Value call(TreePath path, TreePath receiver, List<? extends ExpressionTree> arguments,
                       Map<Element, Value> env, Controls controls) {
        var receiverValue = receiver == null ? UNKNOWN : expression(receiver, env, controls);
        var args = arguments.stream().map(arg -> expression(child(path, arg), env, controls)).toList();
        var site = sites.get(path.getLeaf());
        if (site == null) return files == null ? UNKNOWN : projectCall(path, receiver, receiverValue, args, controls);
        if (OPERATIONS.contains(site.role())) {
            recordOperation(site, receiverValue, args, controls);
        } else if (site.role().equals("external_input_api")) {
            return httpRead(path, site.method());
        } else if (DERIVATIONS.contains(site.role())) {
            var value = path.getLeaf() instanceof NewClassTree || site.owner().equals("java.nio.file.Paths")
                || (site.owner().equals("java.nio.file.Path") && site.method().equals("of"))
                ? new Value(Origin.FIXED_VALUE, null, Set.of(), Set.of(), Set.of()) : receiverValue;
            for (var argument : args) value = combine(value, argument);
            return value.derivedAt(site.id(), site.line());
        }
        return UNKNOWN;
    }

    private Value httpRead(TreePath path, String method) {
        var type = trees.getTypeMirror(path);
        var tree = path.getLeaf();
        if (type != null && type.toString().equals(STRING)) {
            return explained(new Value(Origin.EXTERNAL_INPUT_IN_EXPRESSION, null, Set.of(),
                Set.of(line.applyAsLong(tree)), Set.of()), tree, "verified_http_read");
        }
        if (files != null && method.equals("getHeaders") && type != null
                && type.toString().equals("java.util.Enumeration<java.lang.String>")
                && trees.getElement(path) instanceof ExecutableElement target
                && target.getParameters().size() == 1 && target.getParameters().get(0).asType().toString().equals(STRING)) {
            return explained(new Value(Origin.HTTP_HEADER_ENUMERATION, null, Set.of(),
                Set.of(line.applyAsLong(tree)), Set.of()), tree, "http_header_enumeration");
        }
        return UNKNOWN;
    }

    private Value propagated(Tree tree, Value input, Origin origin, String role) {
        return explained(new Value(origin, null, input.sites, union(input.lines, Set.of(line.applyAsLong(tree))),
            input.fixedDefinitions, input.facts), tree, role);
    }

    private Value headerElement(TreePath call, TreePath receiverPath, Value receiver, Controls controls) {
        if (receiver.origin != Origin.HTTP_HEADER_ENUMERATION) return UNKNOWN;
        var receiverSymbol = receiverPath == null ? null : trees.getElement(receiverPath);
        var guards = controls.headerGuards().stream()
            .filter(guard -> guard.receiver().equals(receiverSymbol) && guard.binding() == receiver)
            .map(HeaderGuard::check).toList();
        return propagated(call.getLeaf(), receiver, Origin.EXTERNAL_INPUT_IN_EXPRESSION, "header_element_from_receiver")
            .withFacts(guards);
    }

    private Value applySummary(TreePath path, Propagation summary, TreePath receiverPath, Value receiver,
                               List<Value> args, Controls controls) {
        var type = trees.getTypeMirror(path);
        if (type == null || !type.toString().equals(STRING)) return UNKNOWN;
        var call = path.getLeaf();
        return switch (summary) {
            case HEADER_ELEMENT_FROM_RECEIVER -> headerElement(path, receiverPath, receiver, controls);
            case URL_DECODE_FROM_ARGUMENT_1 -> args.size() == 2 && externalScalar(args.get(0).origin)
                ? propagated(call, args.get(0), args.get(0).origin, "url_decode_from_argument_1") : UNKNOWN;
            case STRING_REPLACE_CHARS -> replaceChars(call, receiver, args);
        };
    }

    private Value replaceChars(Tree call, Value receiver, List<Value> args) {
        if ((receiver.origin != Origin.FIXED_VALUE && receiver.origin != Origin.CONFIGURATION_VALUE)
                || !(args.get(0).literal instanceof Character from) || !(args.get(1).literal instanceof Character to)) {
            return UNKNOWN;
        }
        Object literal = receiver.literal instanceof String text ? text.replace(from, to) : null;
        var value = new Value(receiver.origin, literal, receiver.sites, receiver.lines, receiver.fixedDefinitions,
            receiver.facts).withLines(union(args.get(0).lines, args.get(1).lines))
            .withFacts(union(args.get(0).facts, args.get(1).facts));
        return explained(value.withLines(Set.of(line.applyAsLong(call))), call, "string_constant_char_replacement");
    }

    private Value atCall(Value value, Tree call, String role) {
        return explained(new Value(value.origin, value.literal, Set.of(), Set.of(line.applyAsLong(call)),
            Set.of(), value.facts), call, role);
    }

    private boolean inSnapshot(TreePath definition) {
        return definition != null && files.containsKey(definition.getCompilationUnit());
    }

    private Value configuration(VariableElement variable, Tree reference) {
        if (!variable.getModifiers().containsAll(Set.of(Modifier.STATIC, Modifier.FINAL))
                || !variable.asType().toString().equals("java.lang.String")) return UNKNOWN;
        if (variable.getEnclosingElement() instanceof TypeElement owner
                && owner.getQualifiedName().contentEquals("java.io.File")
                && Set.of("separator", "pathSeparator").contains(variable.getSimpleName().toString())) {
            return explained(new Value(Origin.CONFIGURATION_VALUE, null, Set.of(), Set.of(), Set.of()),
                reference, "platform_path_separator");
        }
        var definition = trees.getPath(variable);
        if (depth >= MAX_HELPER_DEPTH || !inSnapshot(definition) || !(definition.getLeaf() instanceof VariableTree declaration)
                || declaration.getInitializer() == null) return UNKNOWN;
        var frame = nested(definition, null);
        var value = frame.read(child(definition, declaration.getInitializer()), new HashMap<>(), ENTRY);
        if (value.origin != Origin.FIXED_VALUE && value.origin != Origin.CONFIGURATION_VALUE) return UNKNOWN;
        return atCall(frame.explained(value, declaration, "static_final_initializer"), reference, "static_final_read");
    }

    private boolean exactReceiver(TreePath receiver, TypeElement owner) {
        if (receiver == null || !(receiver.getLeaf() instanceof NewClassTree created)
                || created.getClassBody() != null) return false;
        var type = trees.getTypeMirror(receiver);
        return type != null && type.toString().equals(owner.getQualifiedName().toString());
    }

    private CollectionOperation collectionOperation(TreePath path) {
        if (!(path.getLeaf() instanceof MethodInvocationTree call)
                || !(trees.getElement(path) instanceof ExecutableElement target)
                || !(target.getEnclosingElement() instanceof TypeElement owner)) return null;
        String kind = owner.getQualifiedName().toString();
        String name = target.getSimpleName().toString();
        int arity = call.getArguments().size();
        if (target.getParameters().size() != arity) return null;
        if (kind.equals(HASH_MAP) || kind.equals("java.util.Map")) {
            if (name.equals("get") && arity == 1) return CollectionOperation.MAP_GET;
            if (name.equals("put") && arity == 2) return CollectionOperation.MAP_PUT;
        }
        if ((kind.equals(ARRAY_LIST) || kind.equals("java.util.List")) && arity == 1) {
            if (name.equals("add")) return CollectionOperation.LIST_APPEND;
            if (target.getParameters().get(0).asType().getKind() == TypeKind.INT) {
                if (name.equals("get")) return CollectionOperation.LIST_GET;
                if (name.equals("remove")) return CollectionOperation.LIST_REMOVE_INDEX;
            }
        }
        return null;
    }

    private boolean supportedCollectionReference(TreePath reference, TreePath method) {
        var select = reference.getParentPath();
        if (!(select.getLeaf() instanceof MemberSelectTree member) || member.getExpression() != reference.getLeaf()) {
            return false;
        }
        var call = select.getParentPath();
        if (!(call.getLeaf() instanceof MethodInvocationTree invocation) || invocation.getMethodSelect() != member) {
            return false;
        }
        for (var ancestor = call.getParentPath(); ancestor != method; ancestor = ancestor.getParentPath()) {
            if (ancestor.getLeaf() instanceof LambdaExpressionTree || ancestor.getLeaf() instanceof ClassTree
                    || ancestor.getLeaf() instanceof MethodTree) return false;
        }
        var operation = collectionOperation(call);
        return operation != null && (operation.reads()
            || (call.getParentPath().getLeaf() instanceof ExpressionStatementTree statement
                && statement.getExpression() == invocation));
    }

    private boolean onlyLocalCollectionUses(TreePath declaration, Element symbol) {
        var method = declaration;
        while (method != null && !(method.getLeaf() instanceof MethodTree)) method = method.getParentPath();
        if (method == null) return false;
        var enclosing = method;
        // Admit exact receiver uses only. An alias, escape or unsupported mutator invalidates the model.
        var escapes = new TreePathScanner<Boolean, Void>() {
            @Override public Boolean visitIdentifier(IdentifierTree node, Void unused) {
                var reference = getCurrentPath();
                return symbol.equals(trees.getElement(reference)) && !supportedCollectionReference(reference, enclosing);
            }
            @Override public Boolean reduce(Boolean first, Boolean second) {
                return Boolean.TRUE.equals(first) || Boolean.TRUE.equals(second);
            }
        }.scan(enclosing, null);
        return !Boolean.TRUE.equals(escapes);
    }

    private Value newLocalCollection(TreePath declaration, Element symbol, ExpressionTree initializer) {
        if (files == null || symbol == null || symbol.getKind() != ElementKind.LOCAL_VARIABLE
                || !(initializer instanceof NewClassTree created) || created.getClassBody() != null
                || !created.getArguments().isEmpty()
                || !(trees.getElement(child(declaration, created)) instanceof ExecutableElement constructor)
                || !(constructor.getEnclosingElement() instanceof TypeElement owner)) {
            return UNKNOWN;
        }
        String kind = owner.getQualifiedName().toString();
        Object contents = switch (kind) {
            case HASH_MAP -> new LocalMap(Map.of());
            case ARRAY_LIST -> new LocalList(List.of());
            default -> null;
        };
        if (contents == null || !onlyLocalCollectionUses(declaration, symbol)) return UNKNOWN;
        var value = new Value(Origin.LOCAL_COLLECTION, contents, Set.of(), Set.of(), Set.of());
        return explained(value, initializer, kind.equals(HASH_MAP) ? "local_map_created" : "local_list_created");
    }

    private boolean updateCollection(TreePath path, Map<Element, Value> env, Controls controls) {
        if (files == null) return false;
        var operation = collectionOperation(path);
        if (operation == null || operation.reads()) return false;
        var call = (MethodInvocationTree) path.getLeaf();
        if (!(call.getMethodSelect() instanceof MemberSelectTree member)) return false;
        var receiver = trees.getElement(child(child(path, member), member.getExpression()));
        var tracked = env.getOrDefault(receiver, UNKNOWN);
        if (tracked.origin != Origin.LOCAL_COLLECTION || tracked.literal == null) return false;
        var firstPath = child(path, call.getArguments().get(0));
        var first = read(firstPath, env, controls);
        Value updated = UNKNOWN;
        if (operation == CollectionOperation.MAP_PUT && tracked.literal instanceof LocalMap map) {
            var valuePath = child(path, call.getArguments().get(1));
            var value = read(valuePath, env, controls);
            if (first.literal instanceof String key
                    && (map.entries().size() < MAX_COLLECTION_ENTRIES || map.entries().containsKey(key))) {
                var entries = new HashMap<>(map.entries());
                var stored = stringValue(valuePath, value).withLines(first.lines).withFacts(first.facts).under(controls);
                entries.put(key, explained(stored, call, "map_put_for_key"));
                updated = collectionWith(tracked, new LocalMap(Map.copyOf(entries)));
            }
        } else if (tracked.literal instanceof LocalList list) {
            var entries = new ArrayList<>(list.entries());
            if (operation == CollectionOperation.LIST_APPEND && entries.size() < MAX_COLLECTION_ENTRIES) {
                entries.add(explained(stringValue(firstPath, first).under(controls), call, "list_append"));
                updated = collectionWith(tracked, new LocalList(List.copyOf(entries)));
            } else if (operation == CollectionOperation.LIST_REMOVE_INDEX
                    && first.literal instanceof Integer index && index >= 0 && index < entries.size()) {
                entries.remove(index.intValue());
                updated = explained(collectionWith(tracked, new LocalList(List.copyOf(entries)))
                    .withLines(first.lines).withFacts(first.facts).under(controls), call, "list_remove_index");
            }
        }
        env.put(receiver, env.get(receiver) == tracked ? updated : UNKNOWN);
        return true;
    }

    private Value stringValue(TreePath path, Value value) {
        var type = trees.getTypeMirror(path);
        return type != null && type.toString().equals(STRING) ? value : UNKNOWN;
    }

    private static Value collectionWith(Value collection, Object contents) {
        return new Value(Origin.LOCAL_COLLECTION, contents, collection.sites, collection.lines,
            collection.fixedDefinitions, collection.facts);
    }

    private Value readCollection(Tree call, CollectionOperation operation, Value collection, Value key) {
        Value value;
        String role;
        if (operation == CollectionOperation.MAP_GET && collection.literal instanceof LocalMap map
                && key.literal instanceof String text && map.entries().containsKey(text)) {
            value = map.entries().get(text);
            role = "map_get_by_key";
        } else if (operation == CollectionOperation.LIST_GET && collection.literal instanceof LocalList list
                && key.literal instanceof Integer index && index >= 0 && index < list.entries().size()) {
            value = list.entries().get(index);
            role = "list_get_by_index";
        } else {
            return UNKNOWN;
        }
        return explained(value.withLines(union(collection.lines, key.lines))
            .withFacts(union(collection.facts, key.facts)), call, role);
    }

    private Value projectCall(TreePath path, TreePath receiver, Value base, List<Value> args, Controls controls) {
        if (!(trees.getElement(path) instanceof ExecutableElement target)
                || !(target.getEnclosingElement() instanceof TypeElement owner)) return UNKNOWN;
        var tree = path.getLeaf();
        String className = owner.getQualifiedName().toString();
        String name = target.getSimpleName().toString();
        var signature = new ApiSignature(className, name,
            target.getParameters().stream().map(parameter -> parameter.asType().toString()).toList());
        var summary = API_SUMMARIES.get(signature);
        if (summary != null) return applySummary(path, summary, receiver, base, args, controls);
        if (base.origin == Origin.LOCAL_COLLECTION) {
            var operation = collectionOperation(path);
            if (operation != null && operation.reads()) return readCollection(tree, operation, base, args.get(0));
        }
        if ("external_input_api".equals(PathEvidenceProbe.role(className, name))) return httpRead(path, name);
        if (className.equals("java.lang.String") && name.equals("charAt") && base.literal instanceof String text
                && args.size() == 1 && args.get(0).literal instanceof Integer index && index >= 0 && index < text.length()) {
            return explained(literal(tree, text.charAt(index)).withLines(union(base.lines, args.get(0).lines))
                .withFacts(union(base.facts, args.get(0).facts)), tree, "constant_string_index");
        }
        if (className.equals("java.lang.System") && name.equals("getProperty") && args.size() == 1
                && args.get(0).literal instanceof String key && key.equals("user.dir")) {
            return explained(new Value(Origin.CONFIGURATION_VALUE, null, Set.of(), Set.of(), Set.of()),
                tree, "jvm_working_directory");
        }
        if (!(tree instanceof MethodInvocationTree invocation) || !target.getReturnType().toString().equals(STRING)) {
            return UNKNOWN;
        }
        boolean fixedTarget = target.getModifiers().stream().anyMatch(
            modifier -> modifier == Modifier.STATIC || modifier == Modifier.PRIVATE || modifier == Modifier.FINAL)
            || owner.getModifiers().contains(Modifier.FINAL) || exactReceiver(receiver, owner);
        var definition = trees.getPath(target);
        if (!fixedTarget || depth >= MAX_HELPER_DEPTH || !inSnapshot(definition)
                || !(definition.getLeaf() instanceof MethodTree method) || method.getBody() == null
                || target.isVarArgs() || args.size() != target.getParameters().size()) {
            var result = UNKNOWN;
            if (owner.getKind().isInterface()) {
                for (int i = 0; i < args.size(); i++) {
                    if (args.get(i).origin == Origin.FIXED_VALUE) {
                        result = explained(result.withFacts(args.get(i).facts), invocation.getArguments().get(i),
                            "fixed_argument_" + (i + 1) + "_at_unresolved_call");
                    }
                }
                if (!result.facts.isEmpty()) result = explained(result, tree, "helper_return_unresolved");
            }
            return result;
        }

        var returned = new ArrayList<Value>();
        var frame = nested(definition, returned);
        var env = new HashMap<Element, Value>();
        for (int i = 0; i < args.size(); i++) {
            var arg = args.get(i);
            var bound = new Value(arg.origin, arg.literal, Set.of(), Set.of(), Set.of(), arg.facts);
            env.put(target.getParameters().get(i),
                explained(bound, invocation.getArguments().get(i), "actual_argument_" + (i + 1)));
        }
        boolean fallsThrough = frame.statement(child(definition, method.getBody()), env, ENTRY);
        if (fallsThrough || frame.unsupported || returned.isEmpty()) return UNKNOWN;
        return atCall(returned.stream().reduce(PathLocalFlow::join).orElseThrow(), tree, "verified_helper_call");
    }

    private Value binary(TreePath path, BinaryTree tree, Map<Element, Value> env, Controls controls) {
        var leftPath = child(path, tree.getLeftOperand());
        var rightPath = child(path, tree.getRightOperand());
        var left = expression(leftPath, env, controls);
        if (left.literal instanceof Boolean truth
                && (tree.getKind() == Tree.Kind.CONDITIONAL_AND || tree.getKind() == Tree.Kind.CONDITIONAL_OR)) {
            boolean skipsRight = tree.getKind() == Tree.Kind.CONDITIONAL_AND ? !truth : truth;
            return skipsRight ? left : expression(rightPath, env, controls).withLines(left.lines);
        }
        var right = expression(rightPath, env, controls);
        var combined = combine(left, right);
        var resultType = trees.getTypeMirror(path);
        if (tree.getKind() == Tree.Kind.PLUS && resultType != null && resultType.toString().equals("java.lang.String")) {
            return combined.withLines(Set.of(line.applyAsLong(tree)));
        }
        var leftType = trees.getTypeMirror(leftPath);
        var rightType = trees.getTypeMirror(rightPath);
        if (!(left.literal instanceof Integer a) || !(right.literal instanceof Integer b)
                || leftType == null || rightType == null || leftType.getKind() != TypeKind.INT
                || rightType.getKind() != TypeKind.INT) return UNKNOWN;
        Object value = switch (tree.getKind()) {
            case PLUS -> a + b;
            case MINUS -> a - b;
            case MULTIPLY -> a * b;
            case DIVIDE -> b == 0 ? null : a / b;
            case REMAINDER -> b == 0 ? null : a % b;
            case LESS_THAN -> a < b;
            case LESS_THAN_EQUAL -> a <= b;
            case GREATER_THAN -> a > b;
            case GREATER_THAN_EQUAL -> a >= b;
            case EQUAL_TO -> a.equals(b);
            case NOT_EQUAL_TO -> !a.equals(b);
            default -> null;
        };
        return value == null ? UNKNOWN : literal(tree, value).withLines(combined.lines).withFacts(combined.facts);
    }

    private Value expression(TreePath path, Map<Element, Value> env, Controls controls) {
        if (--budget < 0) return UNKNOWN;
        var tree = path.getLeaf();
        if (tree instanceof LiteralTree value) return literal(tree, value.getValue());
        if (tree instanceof ParenthesizedTree p) return expression(child(path, p.getExpression()), env, controls);
        if (files != null && tree instanceof TypeCastTree cast) {
            var type = trees.getTypeMirror(path);
            var input = child(path, cast.getExpression());
            while (input.getLeaf() instanceof ParenthesizedTree p) input = child(input, p.getExpression());
            var operation = collectionOperation(input);
            if (type != null && type.toString().equals(STRING) && operation != null && operation.reads()) {
                return expression(input, env, controls);
            }
        }
        if (tree instanceof IdentifierTree || tree instanceof MemberSelectTree) {
            var symbol = trees.getElement(path);
            if (local(symbol)) return env.getOrDefault(symbol, UNKNOWN);
            if (symbol instanceof VariableElement variable) {
                var value = literal(tree, variable.getConstantValue());
                return files != null && value.origin == Origin.UNKNOWN ? configuration(variable, tree) : value;
            }
        }
        if (tree instanceof BinaryTree binary) return binary(path, binary, env, controls);
        if (tree instanceof ConditionalExpressionTree select) {
            var condition = expression(child(path, select.getCondition()), env, controls);
            if (condition.literal instanceof Boolean truth) {
                var selected = truth ? select.getTrueExpression() : select.getFalseExpression();
                var context = selected(controls, condition, select, truth ? "conditional_true" : "conditional_false", null);
                return expression(child(path, selected), env, context).withLines(condition.lines).withFacts(context.facts());
            }
            return join(expression(child(path, select.getTrueExpression()), env, controls),
                expression(child(path, select.getFalseExpression()), env, controls));
        }
        if (tree instanceof NewClassTree created && created.getClassBody() == null) {
            return call(path, null, created.getArguments(), env, controls);
        }
        if (tree instanceof MethodInvocationTree invoked) {
            var receiver = invoked.getMethodSelect() instanceof MemberSelectTree member
                ? child(child(path, member), member.getExpression()) : null;
            return call(path, receiver, invoked.getArguments(), env, controls);
        }
        return UNKNOWN;
    }

    /** Nested writes are outside the modeled expression set. Forget bindings before proceeding. */
    private Value read(TreePath path, Map<Element, Value> env, Controls controls) {
        var writes = new TreeScanner<Boolean, Void>() {
            @Override public Boolean visitAssignment(AssignmentTree node, Void unused) { return true; }
            @Override public Boolean visitCompoundAssignment(CompoundAssignmentTree node, Void unused) { return true; }
            @Override public Boolean visitUnary(UnaryTree node, Void unused) {
                return switch (node.getKind()) {
                    case PREFIX_INCREMENT, PREFIX_DECREMENT, POSTFIX_INCREMENT, POSTFIX_DECREMENT -> true;
                    default -> super.visitUnary(node, unused);
                };
            }
            @Override public Boolean reduce(Boolean first, Boolean second) {
                return Boolean.TRUE.equals(first) || Boolean.TRUE.equals(second);
            }
        }.scan(path.getLeaf(), null);
        if (!Boolean.TRUE.equals(writes)) return expression(path, env, controls);
        if (returns != null) unsupported = true;
        env.clear();
        return UNKNOWN;
    }

    private boolean branch(TreePath path, IfTree branch, Map<Element, Value> env, Controls controls) {
        var predicate = child(path, branch.getCondition());
        var condition = read(predicate, env, controls);
        if (condition.literal instanceof Boolean truth) {
            var body = truth ? branch.getThenStatement() : branch.getElseStatement();
            var skipped = truth ? branch.getElseStatement() : branch.getThenStatement();
            var context = selected(controls, condition, branch, truth ? "if_true" : "if_false", skipped);
            return body == null || statement(child(path, body), env, context);
        }
        var left = new HashMap<>(env);
        var right = new HashMap<>(env);
        var trueControls = controls;
        if (files != null) {
            var guards = new LinkedHashSet<>(controls.headerGuards());
            collectPositiveHeaderGuards(predicate, env, guards);
            trueControls = new Controls(controls.lines(), controls.facts(), guards);
        }
        boolean continuesLeft = statement(child(path, branch.getThenStatement()), left, trueControls);
        boolean continuesRight = branch.getElseStatement() == null
            || statement(child(path, branch.getElseStatement()), right, controls);
        if (continuesLeft && continuesRight) {
            merge(env, left, right);
        } else {
            env.clear();
            if (continuesLeft) env.putAll(left);
            if (continuesRight) env.putAll(right);
        }
        return continuesLeft || continuesRight;
    }

    private void collectPositiveHeaderGuards(TreePath predicate, Map<Element, Value> env, Set<HeaderGuard> guards) {
        var tree = predicate.getLeaf();
        if (tree instanceof ParenthesizedTree parentheses) {
            collectPositiveHeaderGuards(child(predicate, parentheses.getExpression()), env, guards);
        } else if (tree instanceof BinaryTree binary && binary.getKind() == Tree.Kind.CONDITIONAL_AND) {
            collectPositiveHeaderGuards(child(predicate, binary.getLeftOperand()), env, guards);
            collectPositiveHeaderGuards(child(predicate, binary.getRightOperand()), env, guards);
        } else if (tree instanceof MethodInvocationTree call && call.getArguments().isEmpty()
                && call.getMethodSelect() instanceof MemberSelectTree member
                && trees.getElement(predicate) instanceof ExecutableElement method
                && method.getSimpleName().contentEquals("hasMoreElements")
                && method.getEnclosingElement() instanceof TypeElement owner
                && owner.getQualifiedName().contentEquals("java.util.Enumeration")) {
            var receiver = trees.getElement(child(child(predicate, member), member.getExpression()));
            var binding = env.getOrDefault(receiver, UNKNOWN);
            if (binding.origin == Origin.HTTP_HEADER_ENUMERATION) {
                guards.add(new HeaderGuard(receiver, binding, fact(tree, "header_availability_guard_true")));
            }
        }
    }

    private static Object switchKey(Object value) {
        return value instanceof Character character ? (int) character : value;
    }

    private static boolean containsJump(Tree action) {
        return Boolean.TRUE.equals(new TreeScanner<Boolean, Void>() {
            @Override public Boolean visitBreak(BreakTree node, Void unused) { return true; }
            @Override public Boolean visitContinue(ContinueTree node, Void unused) { return true; }
            @Override public Boolean reduce(Boolean a, Boolean b) {
                return Boolean.TRUE.equals(a) || Boolean.TRUE.equals(b);
            }
        }.scan(action, null));
    }

    private boolean unresolvedSwitch(Map<Element, Value> env) {
        env.clear();
        if (returns != null) unsupported = true;
        return true;
    }

    private boolean constantSwitch(TreePath path, SwitchTree branch, Map<Element, Value> env, Controls controls) {
        var selector = read(child(path, branch.getExpression()), env, controls);
        if (!(selector.literal instanceof Character || selector.literal instanceof Integer || selector.literal instanceof String)) {
            return unresolvedSwitch(env);
        }
        int match = -1;
        int fallback = -1;
        var cases = branch.getCases();
        for (int i = 0; i < cases.size(); i++) {
            var entry = cases.get(i);
            if (entry.getExpressions().isEmpty()) fallback = i;
            for (var label : entry.getExpressions()) {
                var labelPath = child(child(path, entry), label);
                var symbol = trees.getElement(labelPath);
                var value = symbol instanceof VariableElement variable && variable.getConstantValue() != null
                    ? variable.getConstantValue() : expression(labelPath, env, ENTRY).literal;
                if (value == null) return unresolvedSwitch(env);
                if (Objects.equals(switchKey(selector.literal), switchKey(value))) match = i;
            }
        }
        int start = match >= 0 ? match : fallback;
        if (start < 0) return true;
        for (var entry : cases.subList(start, cases.size())) {
            var actions = entry.getStatements();
            boolean unsupportedJump = actions == null ? containsJump(entry.getBody()) : actions.stream().anyMatch(action ->
                action instanceof BreakTree jump ? jump.getLabel() != null : containsJump(action));
            if (unsupportedJump) return unresolvedSwitch(env);
        }
        var context = selected(controls, selector, branch, "constant_switch_selector", null);
        var facts = union(context.facts(), Set.of(fact(cases.get(start), "switch_case_selected")));
        boolean fallThrough = false;
        for (int i = 0; i < cases.size(); i++) {
            var entry = cases.get(i);
            if (i == start || fallThrough) {
                fallThrough = entry.getCaseKind() == CaseTree.CaseKind.STATEMENT
                    && entry.getStatements().stream().noneMatch(action -> action instanceof BreakTree);
                continue;
            }
            long next = i + 1 < cases.size() ? line.applyAsLong(cases.get(i + 1)) : Long.MAX_VALUE;
            exclude(facts, entry, line.applyAsLong(entry) + 1, next);
        }
        context = new Controls(context.lines(), facts, context.headerGuards());
        for (var entry : cases.subList(start, cases.size())) {
            var entryPath = child(path, entry);
            if (entry.getCaseKind() == CaseTree.CaseKind.RULE) {
                var body = entry.getBody();
                if (body instanceof ExpressionTree) {
                    if (returns != null) unsupported = true;
                    else read(child(entryPath, body), env, context);
                    return true;
                }
                return statement(child(entryPath, body), env, context);
            }
            for (var action : entry.getStatements()) {
                if (action instanceof BreakTree) return true;
                if (!statement(child(entryPath, action), env, context)) return false;
            }
        }
        return true;
    }

    private boolean statement(TreePath path, Map<Element, Value> env, Controls controls) {
        if (--budget < 0) {
            if (returns != null) unsupported = true;
            return false;
        }
        var tree = path.getLeaf();
        if (tree instanceof BlockTree block) {
            for (var inner : block.getStatements()) if (!statement(child(path, inner), env, controls)) return false;
        } else if (tree instanceof VariableTree local) {
            var symbol = trees.getElement(path);
            var initializer = local.getInitializer();
            var value = newLocalCollection(path, symbol, initializer);
            if (value == UNKNOWN && initializer != null) value = read(child(path, initializer), env, controls);
            if (local(symbol)) env.put(symbol, explained(value.under(controls).definedAt(line.applyAsLong(tree)),
                tree, "local_definition"));
        } else if (tree instanceof ExpressionStatementTree expression) {
            var expressionPath = child(path, expression.getExpression());
            if (expression.getExpression() instanceof AssignmentTree assign) {
                var target = trees.getElement(child(expressionPath, assign.getVariable()));
                var value = read(child(expressionPath, assign.getExpression()), env, controls);
                if (local(target)) env.put(target, explained(value.under(controls).definedAt(line.applyAsLong(tree)),
                    tree, "local_assignment"));
                else if (returns != null) unsupported = true;
            } else if (updateCollection(expressionPath, env, controls)) {
                return true;
            } else if (returns != null) {
                unsupported = true;
            } else {
                read(expressionPath, env, controls);
            }
        } else if (tree instanceof IfTree branch) {
            return branch(path, branch, env, controls);
        } else if (tree instanceof SwitchTree branch && files != null) {
            return constantSwitch(path, branch, env, controls);
        } else if (tree instanceof TryTree attempt && returns == null) {
            var inside = new HashMap<>(env);
            for (var resource : attempt.getResources()) {
                if (resource instanceof VariableTree) statement(child(path, resource), inside, controls);
            }
            boolean normalExit = statement(child(path, attempt.getBlock()), inside, controls);
            // Catch/finally may enter at unknown points; do not carry aliases through the try.
            env.clear();
            return normalExit || !attempt.getCatches().isEmpty() || attempt.getFinallyBlock() != null;
        } else if (tree instanceof ReturnTree returned) {
            if (returned.getExpression() != null) {
                var value = read(child(path, returned.getExpression()), env, controls).under(controls);
                if (returns != null) returns.add(explained(value, tree, "helper_return"));
            }
            return false;
        } else if (tree instanceof ThrowTree || tree instanceof BreakTree || tree instanceof ContinueTree) {
            if (returns != null) unsupported = true;
            return false;
        } else {
            if (returns != null) unsupported = true;
            env.clear();
        }
        return true;
    }
}
