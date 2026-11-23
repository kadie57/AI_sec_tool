@main def exec() = {
  importCode("/project/Clean_Code/VulnerablePath.java")

  def source = cpg.method.nameExact("getFileContent")
    .parameter.nameExact("fileName")

  def sink = cpg.call.nameExact("<init>")
    .filter(c => c.methodFullName.startsWith("java.io.File.<init>:"))
    .filter(c => c.lineNumber.contains(16))
    .argument(1)

  println("=== PATH_FLOW_BEGIN ===")
  println("SOURCE=" + source.code.l.mkString(" | "))
  println("SINK_ARGUMENT=" + sink.code.l.mkString(" | "))

  val paths = sink.reachableByFlows(source).l
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("=== PATH_FLOW_END ===")
}
