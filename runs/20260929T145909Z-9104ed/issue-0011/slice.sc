@main def exec() = {
  importCode("/project/Clean_Code/pilot_sql89/Trial04.java")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sink = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => c.lineNumber.exists(n => n >= 20 && n <= 20)).argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
