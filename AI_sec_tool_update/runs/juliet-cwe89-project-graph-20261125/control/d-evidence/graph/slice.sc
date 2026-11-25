import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode}

@main def exec() = {
  val build = scala.sys.process.Process(Seq("joern-parse", "/project", "--language", "JAVASRC", "-o", "/work/snapshot.bin", "--frontend-args", "--delombok-mode", "no-delombok", "--inference-jar-paths", "/work/type-jars/0001.jar")).!
  require(build == 0, "Java snapshot parse failed")
  importCpg("/work/snapshot.bin", "snapshot")
  def emit(fields: Any*): Unit = println(("SQL_PATH" +: fields).mkString("\t"))
  def fileName(n: AstNode): String =
    n.file.name.headOption.getOrElse("").stripPrefix("/project/")
  val callsByLocation = cpg.call.l.groupBy(c => (fileName(c), c.lineNumber.getOrElse(0), c.name))
  def matching(ref: (String, Int, String)) = callsByLocation.getOrElse(ref, List.empty)

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
  val input = scala.io.Source.fromFile("/work/queries.tsv", "UTF-8")
  val entries = try input.getLines().map(_.split("\t", -1)).toList finally input.close()
  val byCase = entries.groupBy(_(1).toInt)
  def ref(row: Array[String]): (String, Int, String) = (row(2), row(3).toInt, row(4))
  byCase.toList.sortBy(_._1).foreach { case (id, entries) =>
    val sink = entries.find(_(0) == "sink").get
    println(s"SQL_CASE\t$id")
    trace(entries.filter(_(0) == "source").map(ref), ref(sink))
  }
}
