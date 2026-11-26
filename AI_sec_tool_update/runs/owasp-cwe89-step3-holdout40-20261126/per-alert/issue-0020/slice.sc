import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode}

@main def exec() = {
  importCode("/project")
  def emit(fields: Any*): Unit = println(("SQL_PATH" +: fields).mkString("\t"))
  def fileName(n: AstNode): String =
    n.file.name.headOption.getOrElse("").stripPrefix("/project/")
  def matching(ref: (String, Int, String)) = {
    val (file, line, name) = ref
    cpg.call.filter(c => c.name == name && c.lineNumber.contains(line) && fileName(c) == file).l
  }

  def trace(origins: List[(String, Int, String)], target: (String, Int, String)): Unit = {
  val sinkCalls = matching(target)
  val sinkArgs = sinkCalls.iterator.argument(1).l
  emit("SINK", sinkCalls.size, sinkArgs.size)
  origins.zipWithIndex.foreach { (ref, i) =>
    val reads = matching(ref)
    emit("SOURCE", i, reads.size)
    if (reads.size == 1 && sinkCalls.size == 1 && sinkArgs.size == 1) {
      val paths = sinkArgs.iterator.reachableByFlows(reads.iterator).take(13).l
      emit("COUNT", i, paths.size)
      paths.take(12).zipWithIndex.foreach { (path, p) =>
        path.elements.foreach { n =>
          val (method, start, end) = n match {
            case cfg: CfgNode =>
              val m = cfg.method
              (m.name, m.lineNumber.getOrElse(0), m.lineNumberEnd.getOrElse(0))
            case _ => ("", 0, 0)
          }
          emit("NODE", i, p, n.getClass.getSimpleName, fileName(n), n.lineNumber.getOrElse(0), method, start, end)
          n match {
            case c: Call if c.dispatchType == "DYNAMIC_DISPATCH" =>
              val targets = c.start.callee.filter(m => !m.isExternal && m.lineNumber.isDefined).l
                .map(m => (fileName(m), m.lineNumber.get, m.fullName)).distinct.sortBy(identity)
              if (targets.size > 1) targets.foreach { (file, line, name) =>
                emit("TARGET", i, p, fileName(c), c.lineNumber.getOrElse(0), c.name, file, line, name)
              }
            case _ =>
          }
        }
      }
    }
  }
  }
  trace(List(("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01474.java", 45, "getParameterNames"), ("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01474.java", 48, "getParameterValues"), ("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01474.java", 47, "nextElement")), ("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01474.java", 67, "executeUpdate"))
}
