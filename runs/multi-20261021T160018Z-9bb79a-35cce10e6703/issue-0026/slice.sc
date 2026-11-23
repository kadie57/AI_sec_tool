@main def exec() = {
  importCode("/work/input")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sink = cpg.call.nameExact("<init>")
    .filter(c => c.methodFullName.startsWith("java.io.File.<init>:") ||
      (c.methodFullName.startsWith("ANY.<init>:<unresolvedSignature>") &&
       c.code.startsWith("new java.io.File(")))
    .filter(c => c.lineNumber.exists(n => n >= 7 && n <= 7))
    .filter(c => c.argument.filter(_.argumentIndex > 0).size == 1).argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
