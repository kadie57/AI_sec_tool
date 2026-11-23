@main def exec() = {
  importCode("/project/Clean_Code/lab/Case03.java")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sink = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => c.lineNumber.exists(n => n >= 14 && n <= 14)).argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
