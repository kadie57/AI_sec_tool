@main def exec() = {
  importCode("/project/experiments/owasp_holdout_v1/inputs/a452b3aafd232245d0753e54eb243d6651f8ef96/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01311.java")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sinkCalls = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => c.lineNumber.exists(n => n >= 53 && n <= 53))
  def sink = sinkCalls.argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_GATE_BEGIN")
  println("SINK_CALL_COUNT=" + sinkCalls.size)
  println("SINK_ARGUMENT_COUNT=" + sink.size)
  println("CPG_GATE_END")
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
