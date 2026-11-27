import com.sun.source.tree.*;
import com.sun.source.util.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.lang.model.element.*;
import javax.lang.model.util.Types;
import javax.tools.*;

/** Reports typed API locations and bounded local path use. Never runs the input. */
public class PathEvidenceProbe {
    private static final Set<String> REQUEST_TYPES = Set.of(
        "javax.servlet.ServletRequest", "javax.servlet.http.HttpServletRequest",
        "jakarta.servlet.ServletRequest", "jakarta.servlet.http.HttpServletRequest",
        "javax.servlet.http.Cookie", "jakarta.servlet.http.Cookie");
    private static final Set<String> REQUEST_READS = Set.of(
        "getParameter", "getParameterValues", "getParameterNames", "getParameterMap",
        "getHeader", "getHeaders", "getHeaderNames", "getQueryString", "getRequestURI",
        "getPathInfo", "getCookies", "getValue", "getReader", "getInputStream");
    private static final Set<String> FILE_READS = Set.of(
        "newInputStream", "newBufferedReader", "readAllBytes", "readAllLines", "readString",
        "lines", "list", "walk", "readAttributes");
    private static final Set<String> FILE_WRITES = Set.of(
        "newOutputStream", "newBufferedWriter", "write", "writeString", "createFile",
        "createDirectory", "createDirectories", "delete", "deleteIfExists");
    private static final Set<String> PATH_BUILD = Set.of("of", "resolve", "resolveSibling", "toAbsolutePath");
    private static final Set<String> FILE_METADATA = Set.of(
        "exists", "notExists", "isFile", "isDirectory", "isRegularFile", "isSymbolicLink", "size", "length");

    static String role(String owner, String name) {
        if (REQUEST_TYPES.contains(owner) && REQUEST_READS.contains(name)) return "external_input_api";
        if (name.equals("<init>")) {
            return switch (owner) {
                case "java.io.File", "java.net.URI" -> "path_construction";
                case "java.io.FileInputStream", "java.io.FileReader" -> "file_read";
                case "java.io.FileOutputStream", "java.io.FileWriter" -> "file_write";
                case "java.io.RandomAccessFile" -> "file_io";
                default -> null;
            };
        }
        if (owner.equals("java.nio.file.Files")) {
            if (FILE_READS.contains(name)) return "file_read";
            if (FILE_WRITES.contains(name)) return "file_write";
            if (Set.of("copy", "move", "newByteChannel").contains(name)) return "file_io";
            if (FILE_METADATA.contains(name)) return "file_metadata";
        }
        if (owner.equals("java.io.File")) {
            if (FILE_METADATA.contains(name)) return "file_metadata";
            return switch (name) {
                case "getCanonicalFile", "getCanonicalPath" -> "canonicalization";
                case "toPath", "toURI", "getAbsolutePath", "getAbsoluteFile" -> "path_construction";
                default -> null;
            };
        }
        if (owner.equals("java.nio.file.Path")) {
            if (PATH_BUILD.contains(name)) return "path_construction";
            return switch (name) {
                case "normalize" -> "lexical_normalization";
                case "toRealPath" -> "canonicalization";
                case "startsWith" -> "path_prefix_check";
                case "getFileName" -> "basename_extraction";
                default -> null;
            };
        }
        if (owner.equals("java.nio.file.Paths") && name.equals("get")) return "path_construction";
        if (owner.equals("java.lang.String") && name.equals("startsWith")) return "string_prefix_check";
        return null;
    }

    record Site(int id, String role, String owner, String method, List<String> parameters, long line) {}

    private static class Sites extends TreePathScanner<Void, Void> {
        private final CompilationUnitTree unit;
        private final Trees trees;
        private final Types types;
        private final SourcePositions positions;
        private final Map<CompilationUnitTree, String> projectFiles;
        private final CharSequence source;
        private final Map<Tree, Site> calls = new IdentityHashMap<>();
        private final List<TreePath> methods = new ArrayList<>();

        Sites(CompilationUnitTree unit, Trees trees, Types types, Map<CompilationUnitTree, String> projectFiles)
                throws java.io.IOException {
            this.unit = unit;
            this.trees = trees;
            this.types = types;
            this.positions = trees.getSourcePositions();
            this.projectFiles = projectFiles;
            this.source = projectFiles == null ? "" : unit.getSourceFile().getCharContent(true);
        }

        private long line(long position) {
            return position < 0 ? -1 : unit.getLineMap().getLineNumber(position);
        }

        private long firstLine(Tree tree) { return line(positions.getStartPosition(unit, tree)); }
        private long lastLine(Tree tree) {
            long end = positions.getEndPosition(unit, tree);
            return line(end - 1);
        }

        private void record(Tree call, List<? extends ExpressionTree> arguments) {
            var path = getCurrentPath();
            if (!(trees.getElement(path) instanceof ExecutableElement target)
                    || !(target.getEnclosingElement() instanceof TypeElement type)) return;
            String owner = type.getQualifiedName().toString();
            String name = target.getSimpleName().toString();
            String role = role(owner, name);
            if (role == null) return;
            Tree statement = call;
            Tree method = null;
            for (var parent = path.getParentPath(); parent != null; parent = parent.getParentPath()) {
                var tree = parent.getLeaf();
                if (statement == call && tree instanceof StatementTree) statement = tree;
                if (tree instanceof MethodTree) {
                    method = tree;
                    break;
                }
                if (tree instanceof ClassTree) break;
            }
            if (method == null || firstLine(call) < 1 || lastLine(statement) < 1) return;
            List<String> parameters = target.getParameters().stream().map(parameter -> types.erasure(parameter.asType()).toString())
                .toList();
            String argumentLines = arguments.stream().map(arg -> Long.toString(firstLine(arg)))
                .collect(Collectors.joining(","));
            int id = calls.size() + 1;
            calls.put(call, new Site(id, role, owner, name, parameters, firstLine(call)));
            System.out.printf("SITE\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s%n",
                id, role, owner, name, String.join(",", parameters), firstLine(call), lastLine(call),
                firstLine(statement), lastLine(statement), firstLine(method), lastLine(method), argumentLines);
            if (projectFiles != null && call instanceof NewClassTree) {
                long start = positions.getStartPosition(unit, call), end = positions.getEndPosition(unit, call);
                if (start >= 0 && end > start && end <= source.length()) {
                    String code = source.subSequence((int) start, (int) end).toString();
                    System.out.printf("CTOR\t%d\t%s%n", id,
                        Base64.getEncoder().encodeToString(code.getBytes(StandardCharsets.UTF_8)));
                }
            }
        }

        @Override public Void visitMethod(MethodTree method, Void unused) {
            if (method.getBody() != null) methods.add(getCurrentPath());
            return super.visitMethod(method, unused);
        }

        @Override public Void visitNewClass(NewClassTree call, Void unused) {
            record(call, call.getArguments());
            return super.visitNewClass(call, unused);
        }

        @Override public Void visitMethodInvocation(MethodInvocationTree call, Void unused) {
            record(call, call.getArguments());
            return super.visitMethodInvocation(call, unused);
        }

        void reportPathUses() {
            for (var method : methods) new PathLocalFlow(trees, calls, this::firstLine, unit, projectFiles).analyze(method);
        }
    }

    public static void main(String[] args) throws Exception {
        var compiler = ToolProvider.getSystemJavaCompiler();
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        boolean projectSites = Boolean.getBoolean("path.evidence.projectSites");
        boolean valueFacts = projectSites && Boolean.getBoolean("path.evidence.valueFacts");
        var inputs = new LinkedHashMap<Path, String>();
        if (projectSites) {
            for (String row : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
                String[] fields = row.split("\t", 2);
                inputs.put(Path.of(fields[1]), fields[0]);
            }
        } else {
            inputs.put(Path.of(args[0]), args[0]);
        }
        try (var files = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            var units = files.getJavaFileObjectsFromPaths(inputs.keySet());
            var task = (JavacTask) compiler.getTask(null, files, diagnostics,
                List.of("-proc:none", "-classpath", args[1], "-sourcepath", args[2]), null, units);
            var parsed = task.parse();
            if (diagnostics.getDiagnostics().stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR)) {
                throw new IllegalArgumentException("Java syntax error in the verified source snapshot.");
            }
            task.analyze();
            long errors = diagnostics.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count();
            System.out.printf("STATUS\t%d%n", errors);
            Map<CompilationUnitTree, String> projectFiles = valueFacts ? new IdentityHashMap<>() : null;
            if (valueFacts) {
                for (var unit : parsed) projectFiles.put(unit, inputs.get(Path.of(unit.getSourceFile().toUri())));
            }
            for (var unit : parsed) {
                if (projectSites) {
                    System.out.printf("FILE\t%s%n", inputs.get(Path.of(unit.getSourceFile().toUri())));
                }
                var sites = new Sites(unit, Trees.instance(task), task.getTypes(), projectFiles);
                sites.scan(unit, null);
                if (!projectSites || valueFacts) sites.reportPathUses();
            }
        }
    }
}
