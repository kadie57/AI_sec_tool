@main def exec() = {
  importCode("/project")
  val mainFile = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02088.java"
  def isMain(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean =
    c.start.method.filename.l.exists(f => f == mainFile || f.endsWith("/" + mainFile))
  def sinkCalls = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => isMain(c) && c.lineNumber.exists(n => n >= 61 && n <= 61))
  def sources = cpg.method.parameter.filter(_.index > 0)
  val paths = sinkCalls.argument(1).reachableByFlows(sources).l
  println("PROBE_SINK_COUNT=" + sinkCalls.size)
  println("PROBE_FLOW_COUNT=" + paths.size)
  cpg.method.isExternal(false).filename.dedup.l.sorted.foreach(file => println("PROBE_FILE=" + file))
  cpg.call.name("getTheParameter|createThing|doSomething").filter(isMain).l.foreach(c => {
    val targets = c.start.callee.l.map(m => m.fullName + "|" + m.filename + "|" + m.isExternal).mkString(";")
    println("PROBE_CALL=" + c.lineNumber.getOrElse(-1) + "|" + c.methodFullName + "|" + targets)
  })
  println("PROBE_PATHS_BEGIN")
  println(paths.iterator.p.mkString("\n"))
  println("PROBE_PATHS_END")
}
