import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, CfgNode}

@main def exec() = {
  {SNAPSHOT_IMPORT}
  val limit = {PATH_LIMIT}
  def emit(fields: Any*): Unit = println(("PATH_FLOW" +: fields).mkString("\t"))
  def fileName(node: AstNode): String = node.file.name.headOption.getOrElse("").stripPrefix("/project/")
  val endpoints = scala.util.Using.resource(scala.io.Source.fromFile("/work/endpoints.tsv", "UTF-8")) { file =>
    file.getLines().map(_.split("\t", -1)).toList
  }
  val calls = cpg.call.l.groupBy(call => (fileName(call), call.lineNumber.getOrElse(0), call.name))
  def matching(row: Array[String]) = calls.getOrElse((row(2), row(3).toInt, row(4)), List.empty)
  val reads = endpoints.filter(_(0) == "source").flatMap { row =>
    val matches = matching(row)
    emit("SOURCE", row(1), matches.size)
    if (matches.size == 1) Some(matches.head -> row(1).toInt) else None
  }
  val sourceIds = reads.map((call, i) => call.id -> i).toMap
  endpoints.filter(_(0) == "sink").foreach { row =>
    val matches = if (row.length == 7) {
      // The Java probe verifies the signature. Match the exact expression when the CPG omits constructor types.
      val code = new String(java.util.Base64.getDecoder.decode(row(6)), java.nio.charset.StandardCharsets.UTF_8)
      matching(row).filter(_.code.trim == code.trim)
    } else matching(row)
    val args = matches.iterator.argument(row(5).toInt).l
    emit("SINK", row(1), matches.size, args.size)
    if (reads.nonEmpty && matches.size == 1 && args.size == 1) {
      val paths = args.iterator.reachableByFlows(reads.iterator.map(_._1)).take(limit + 1).l
      emit("COUNT", row(1), paths.size)
      paths.take(limit).zipWithIndex.foreach { (path, index) =>
        val first = path.elements.head
        require(path.elements.last.id == args.head.id, "Flow ended at an unverified file operand")
        val origin = sourceIds(first.id)
        path.elements.foreach { node =>
          val method = node match {
            case cfg: CfgNode => cfg.method.name
            case _ => ""
          }
          emit("NODE", row(1), index, origin, fileName(node), node.lineNumber.getOrElse(0),
               method, node.getClass.getSimpleName)
        }
      }
    }
  }
}
