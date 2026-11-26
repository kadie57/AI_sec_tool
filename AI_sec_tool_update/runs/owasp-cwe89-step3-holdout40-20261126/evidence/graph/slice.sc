import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode}

@main def exec() = {
  val build = scala.sys.process.Process(Seq("joern-parse", "/project", "--language", "JAVASRC", "-o", "/work/snapshot.bin", "--frontend-args", "--delombok-mode", "no-delombok", "--inference-jar-paths", "/work/type-jars/0001.jar,/work/type-jars/0002.jar,/work/type-jars/0003.jar,/work/type-jars/0004.jar,/work/type-jars/0005.jar,/work/type-jars/0006.jar,/work/type-jars/0007.jar,/work/type-jars/0008.jar,/work/type-jars/0009.jar,/work/type-jars/0010.jar,/work/type-jars/0011.jar,/work/type-jars/0012.jar,/work/type-jars/0013.jar,/work/type-jars/0014.jar,/work/type-jars/0015.jar,/work/type-jars/0016.jar,/work/type-jars/0017.jar,/work/type-jars/0018.jar,/work/type-jars/0019.jar,/work/type-jars/0020.jar,/work/type-jars/0021.jar,/work/type-jars/0022.jar,/work/type-jars/0023.jar,/work/type-jars/0024.jar,/work/type-jars/0025.jar,/work/type-jars/0026.jar,/work/type-jars/0027.jar,/work/type-jars/0028.jar,/work/type-jars/0029.jar,/work/type-jars/0030.jar,/work/type-jars/0031.jar,/work/type-jars/0032.jar,/work/type-jars/0033.jar,/work/type-jars/0034.jar,/work/type-jars/0035.jar,/work/type-jars/0036.jar,/work/type-jars/0037.jar,/work/type-jars/0038.jar,/work/type-jars/0039.jar,/work/type-jars/0040.jar,/work/type-jars/0041.jar,/work/type-jars/0042.jar,/work/type-jars/0043.jar,/work/type-jars/0044.jar,/work/type-jars/0045.jar,/work/type-jars/0046.jar,/work/type-jars/0047.jar,/work/type-jars/0048.jar,/work/type-jars/0049.jar,/work/type-jars/0050.jar,/work/type-jars/0051.jar,/work/type-jars/0052.jar,/work/type-jars/0053.jar,/work/type-jars/0054.jar,/work/type-jars/0055.jar,/work/type-jars/0056.jar,/work/type-jars/0057.jar,/work/type-jars/0058.jar,/work/type-jars/0059.jar,/work/type-jars/0060.jar,/work/type-jars/0061.jar,/work/type-jars/0062.jar,/work/type-jars/0063.jar,/work/type-jars/0064.jar,/work/type-jars/0065.jar,/work/type-jars/0066.jar,/work/type-jars/0067.jar,/work/type-jars/0068.jar,/work/type-jars/0069.jar,/work/type-jars/0070.jar,/work/type-jars/0071.jar,/work/type-jars/0072.jar,/work/type-jars/0073.jar,/work/type-jars/0074.jar,/work/type-jars/0075.jar,/work/type-jars/0076.jar,/work/type-jars/0077.jar,/work/type-jars/0078.jar,/work/type-jars/0079.jar,/work/type-jars/0080.jar,/work/type-jars/0081.jar,/work/type-jars/0082.jar,/work/type-jars/0083.jar,/work/type-jars/0084.jar,/work/type-jars/0085.jar,/work/type-jars/0086.jar,/work/type-jars/0087.jar,/work/type-jars/0088.jar,/work/type-jars/0089.jar,/work/type-jars/0090.jar,/work/type-jars/0091.jar,/work/type-jars/0092.jar,/work/type-jars/0093.jar,/work/type-jars/0094.jar,/work/type-jars/0095.jar,/work/type-jars/0096.jar,/work/type-jars/0097.jar,/work/type-jars/0098.jar,/work/type-jars/0099.jar,/work/type-jars/0100.jar,/work/type-jars/0101.jar,/work/type-jars/0102.jar,/work/type-jars/0103.jar,/work/type-jars/0104.jar,/work/type-jars/0105.jar,/work/type-jars/0106.jar,/work/type-jars/0107.jar,/work/type-jars/0108.jar,/work/type-jars/0109.jar,/work/type-jars/0110.jar,/work/type-jars/0111.jar,/work/type-jars/0112.jar,/work/type-jars/0113.jar,/work/type-jars/0114.jar,/work/type-jars/0115.jar,/work/type-jars/0116.jar,/work/type-jars/0117.jar,/work/type-jars/0118.jar,/work/type-jars/0119.jar,/work/type-jars/0120.jar,/work/type-jars/0121.jar,/work/type-jars/0122.jar,/work/type-jars/0123.jar,/work/type-jars/0124.jar,/work/type-jars/0125.jar,/work/type-jars/0126.jar,/work/type-jars/0127.jar,/work/type-jars/0128.jar,/work/type-jars/0129.jar,/work/type-jars/0130.jar,/work/type-jars/0131.jar,/work/type-jars/0132.jar,/work/type-jars/0133.jar")).!
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
